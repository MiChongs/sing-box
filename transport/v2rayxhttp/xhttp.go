// Package v2rayxhttp 实现 XTLS/Xray-core 的 XHTTP (splithttp) 传输，
// 协议行为对齐 Xray-core v26.9.30 transport/internet/splithttp。
//
// 请求形态 (默认 session / seq 放在 path):
//
//	stream-one:  POST <path>                 请求体上行，响应体下行 (H2/H3 全双工)
//	stream-up:   GET  <path><session>        下行
//	             POST <path><session>        上行长请求体
//	packet-up:   GET  <path><session>        下行
//	             POST <path><session>/<seq>  每批上行数据一个请求，服务端按 seq 重排
//
// 上下行分离 (download_settings): 下行 GET 发往 download_settings 指定的
// 服务器 / TLS / dialer，上行仍走外层配置；服务端按 session 把两者关联。
package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxdialer "github.com/sagernet/sing-box/common/dialer"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	ctx    context.Context
	upload *endpoint
	// download 为 nil 时上下行共用 upload。
	download *endpoint
}

func NewClient(
	ctx context.Context,
	dialer N.Dialer,
	serverAddr M.Socksaddr,
	options *option.V2RayXHTTPOptions,
	tlsConfig boxtls.Config,
) (adapter.V2RayClientTransport, error) {
	cfg, err := newConfig(options)
	if err != nil {
		return nil, err
	}
	upload, err := newEndpoint(cfg, dialer, serverAddr, tlsConfig)
	if err != nil {
		return nil, err
	}
	client := &Client{
		ctx:    ctx,
		upload: upload,
	}
	if options != nil && options.DownloadSettings != nil {
		client.download, err = newDownloadEndpoint(ctx, cfg, options.DownloadSettings, dialer, serverAddr)
		if err != nil {
			return nil, E.Cause(err, "xhttp: download_settings")
		}
	}
	return client, nil
}

// newDownloadEndpoint 对应 Xray Dial() 中处理 downloadSettings 的部分。
func newDownloadEndpoint(
	ctx context.Context,
	uploadConfig *config,
	options *option.V2RayXHTTPDownloadOptions,
	uploadDialer N.Dialer,
	uploadAddr M.Socksaddr,
) (*endpoint, error) {
	if uploadConfig.mode == ModeStreamOne {
		return nil, E.New(`can not use download_settings in stream-one mode`)
	}
	if options.V2RayXHTTPOptions.DownloadSettings != nil {
		return nil, E.New("nested download_settings is not allowed")
	}
	cfg, err := newConfig(&options.V2RayXHTTPOptions)
	if err != nil {
		return nil, err
	}
	serverAddr := uploadAddr
	serverName := uploadAddr.AddrString()
	if options.Server != "" {
		serverAddr = options.ServerOptions.Build()
		serverName = options.Server
	}
	if options.ServerPort == 0 {
		serverAddr.Port = uploadAddr.Port
	}
	dialer := uploadDialer
	if !reflect.ValueOf(options.DialerOptions).IsZero() {
		dialer, err = boxdialer.New(ctx, options.DialerOptions, serverAddr.IsDomain())
		if err != nil {
			return nil, err
		}
	}
	var tlsConfig boxtls.Config
	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err = boxtls.NewClientWithOptions(boxtls.ClientOptions{
			Context:       ctx,
			Logger:        logger.NOP(),
			ServerAddress: serverName,
			Options:       *options.TLS,
		})
		if err != nil {
			return nil, err
		}
	}
	return newEndpoint(cfg, dialer, serverAddr, tlsConfig)
}

// DialContext 对应 Xray splithttp Dial()。
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	upload := c.upload
	download := c.download
	if download == nil {
		download = upload
	}

	mode := upload.cfg.mode
	if mode == ModeAuto {
		mode = ModePacketUp
		if upload.isReality {
			mode = ModeStreamOne
			if c.download != nil {
				mode = ModeStreamUp
			}
		}
	}
	var sessionId string
	if mode != ModeStreamOne {
		sessionId = upload.cfg.generateSessionID()
	}

	uploadClient, uploadXmux := upload.getClient()
	downloadClient, downloadXmux := uploadClient, uploadXmux
	if c.download != nil {
		downloadClient, downloadXmux = c.download.getClient()
	}
	uploadXmux.addRunning()
	if downloadXmux != uploadXmux {
		downloadXmux.addRunning()
	}
	connCtx, connCancel := context.WithCancel(c.ctx)
	var released atomic.Bool
	release := func() {
		if released.Swap(true) {
			return
		}
		connCancel()
		uploadXmux.doneRunning()
		if downloadXmux != uploadXmux {
			downloadXmux.doneRunning()
		}
	}
	uploadURL := upload.requestURL()

	if mode == ModeStreamOne {
		uploadXmux.leftRequests.Add(-1)
		pipeReader, pipeWriter := io.Pipe()
		reader, remoteAddr, localAddr, err := uploadClient.openStream(ctx, connCtx, uploadURL, "", pipeReader, false)
		if err != nil {
			_ = pipeWriter.Close()
			release()
			return nil, E.Cause(err, "xhttp: stream-one")
		}
		return newXHTTPConn(reader, pipeWriter, remoteAddr, localAddr, release), nil
	}

	// stream-down
	downloadXmux.leftRequests.Add(-1)
	reader, remoteAddr, localAddr, err := downloadClient.openStream(ctx, connCtx, download.requestURL(), sessionId, nil, false)
	if err != nil {
		release()
		return nil, E.Cause(err, "xhttp: stream-down")
	}

	if mode == ModeStreamUp {
		uploadXmux.leftRequests.Add(-1)
		pipeReader, pipeWriter := io.Pipe()
		_, _, _, err = uploadClient.openStream(ctx, connCtx, uploadURL, sessionId, pipeReader, true)
		if err != nil {
			_ = reader.Close()
			_ = pipeWriter.Close()
			release()
			return nil, E.Cause(err, "xhttp: stream-up")
		}
		return newXHTTPConn(reader, pipeWriter, remoteAddr, localAddr, release), nil
	}

	// packet-up
	maxUploadSize := int(upload.cfg.scMaxEachPostBytes.rand())
	uploadPipe := newUploadPipe(maxUploadSize)
	go c.runPacketUp(uploadPipe, uploadURL, sessionId, maxUploadSize, uploadClient, uploadXmux)
	return newXHTTPConn(reader, uploadPipe, remoteAddr, localAddr, release), nil
}

// runPacketUp 把 uploadPipe 里累积的数据切成不超过 maxUploadSize 的块逐个 POST。
// 每个 POST 写出请求后就继续发下一个，不等响应 (服务端按 seq 重排)；任一 POST
// 失败则中断管道，后续 Write 返回错误。
func (c *Client) runPacketUp(pipe *uploadPipe, requestURL, sessionId string, maxUploadSize int, client *dialerClient, xmux *xmuxClient) {
	upload := c.upload
	var (
		seq       uint64
		lastWrite time.Time
		failed    atomic.Bool
	)
	for {
		// by offloading the uploads into a buffered pipe, multiple conn.Write
		// calls get automatically batched together into larger POST requests.
		// without batching, bandwidth is extremely limited.
		data, err := pipe.readAll()
		if err != nil {
			return
		}
		for len(data) > 0 && !failed.Load() {
			chunk := data[:min(len(data), maxUploadSize)]
			data = data[len(chunk):]
			seqStr := strconv.FormatUint(seq, 10)
			seq++

			if upload.cfg.scMinPostsIntervalMs.From > 0 {
				time.Sleep(time.Duration(upload.cfg.scMinPostsIntervalMs.rand())*time.Millisecond - time.Since(lastWrite))
			}
			lastWrite = time.Now()

			if xmux.leftRequests.Add(-1) <= 0 || xmux.isUnreusable(lastWrite) {
				client, xmux = upload.getClient()
			}

			wrote := make(chan struct{})
			var wroteOnce sync.Once
			onWrote := func() { wroteOnce.Do(func() { close(wrote) }) }
			go func(client *dialerClient) {
				err := client.postPacket(c.ctx, requestURL, sessionId, seqStr, chunk, onWrote)
				onWrote()
				if err != nil {
					failed.Store(true)
					pipe.interrupt(E.Cause(err, "xhttp: failed to send upload"))
				}
			}(client)
			<-wrote
		}
	}
}

func (c *Client) Close() error {
	c.upload.close()
	if c.download != nil {
		c.download.close()
	}
	return nil
}
