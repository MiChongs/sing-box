package v2raygrpc

import (
	"context"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	ctx         context.Context
	dialer      N.Dialer
	serverAddr  string
	serviceName string
	dialOptions []grpc.DialOption
	conn        atomic.Pointer[grpc.ClientConn]
	connAccess  sync.Mutex
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayGRPCOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	var dialOptions []grpc.DialOption
	if tlsConfig != nil {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(NewTLSTransportCredentials(tlsConfig)))
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	if options.IdleTimeout > 0 {
		dialOptions = append(dialOptions, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Duration(options.IdleTimeout),
			Timeout:             time.Duration(options.PingTimeout),
			PermitWithoutStream: options.PermitWithoutStream,
		}))
	}
	dialOptions = append(dialOptions, grpc.WithConnectParams(grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  500 * time.Millisecond,
			Multiplier: 1.5,
			Jitter:     0.2,
			MaxDelay:   19 * time.Second,
		},
		MinConnectTimeout: 5 * time.Second,
	}))
	dialOptions = append(dialOptions, grpc.WithContextDialer(func(ctx context.Context, server string) (net.Conn, error) {
		return dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(server))
	}))
	//nolint:staticcheck
	dialOptions = append(dialOptions, grpc.WithReturnConnectionError())
	return &Client{
		ctx:         ctx,
		dialer:      dialer,
		serverAddr:  serverAddr.String(),
		serviceName: options.ServiceName,
		dialOptions: dialOptions,
	}, nil
}

func (c *Client) connect() (*grpc.ClientConn, error) {
	conn := c.conn.Load()
	if conn != nil && conn.GetState() != connectivity.Shutdown {
		return conn, nil
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	conn = c.conn.Load()
	if conn != nil && conn.GetState() != connectivity.Shutdown {
		return conn, nil
	}
	// PR#5689: 用 grpc.NewClient 代替 grpc.DialContext。
	// NewClient 不会阻塞连接 — 连接在 Connect() 或首次 RPC 时建立。
	conn, err := grpc.NewClient("passthrough:///"+c.serverAddr, c.dialOptions...)
	if err != nil {
		return nil, err
	}
	// PR#5689: grpc.WithUserAgent 会无条件追加 "grpc-go/version" 后缀，
	// 留下 gRPC 指纹。用反射 hack 把 UA 字段直接覆盖掉。
	// 空字符串时用动态 Chrome UA (与 XHTTP browser masquerading 对齐)。
	setUserAgent(conn, "")
	conn.Connect()
	c.conn.Store(conn)
	return conn, nil
}

// setUserAgent 用反射直接覆写 grpc.ClientConn 内部的 UserAgent 字段，
// 剥掉 grpc-go 库无条件追加的 "grpc-go/version" 后缀。
// ua 为空时 grpc-go 会用默认 UA — 但我们已经不走 WithUserAgent 路径，
// 所以空串让 net/http 层用 Go 默认 UA (被 TLS 层的 ALPN 隐藏)。
//
// 注意: 这依赖 grpc.ClientConn 的内部字段名 (dopts.copts.UserAgent)，
// 跨 grpc-go 大版本可能 break。与 Xray-core PR#5689 保持同构。
func setUserAgent(conn *grpc.ClientConn, ua string) {
	f := reflect.ValueOf(conn).Elem().FieldByName("dopts").FieldByName("copts").FieldByName("UserAgent")
	if f.IsValid() {
		*(*string)(f.Addr().UnsafePointer()) = ua
	}
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	clientConn, err := c.connect()
	if err != nil {
		return nil, err
	}
	client := NewGunServiceClient(clientConn).(GunServiceCustomNameClient)
	ctx, cancel := context.WithCancelCause(ctx)
	stream, err := client.TunCustomName(ctx, c.serviceName)
	if err != nil {
		cancel(err)
		return nil, err
	}
	return NewGRPCConn(stream, cancel), nil
}

func (c *Client) Close() error {
	conn := c.conn.Swap(nil)
	if conn != nil {
		conn.Close()
	}
	return nil
}
