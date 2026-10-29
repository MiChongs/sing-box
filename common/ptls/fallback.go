package ptls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrFallbackCompleted   = errors.New("ptls: L4 fallback relay completed")
	ErrFallbackRateLimited = errors.New("ptls: fallback QPS rate limit exceeded")
)

type closeWriter interface {
	CloseWrite() error
}

// FallbackRelayer 负责回退连接的生命周期、QPS 准入和 QoS 限速控制
type FallbackRelayer struct {
	server     string
	port       uint16
	timeout    time.Duration
	qpsLimiter *tokenBucket
	qosLimit   int64 // 字节/秒
}

func NewFallbackRelayer(server string, port uint16, qps int, qos string, timeout time.Duration) *FallbackRelayer {
	if qps <= 0 {
		qps = 5
	}
	burst := qps * 2
	if burst < 5 {
		burst = 5
	}

	qosBytes, _ := ParseBandwidth(qos)
	if qosBytes <= 0 {
		qosBytes = 50 * 1024 // 默认 50 KB/s
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &FallbackRelayer{
		server:     server,
		port:       port,
		timeout:    timeout,
		qpsLimiter: newTokenBucket(float64(qps), float64(burst)),
		qosLimit:   qosBytes,
	}
}

// Relay 执行具备三防保护的 L4 回退转发
func (r *FallbackRelayer) Relay(ctx context.Context, clientConn net.Conn, initialData []byte) error {
	defer clientConn.Close()

	// 1. QPS 准入防护：若超出速率，直接挂断，避免消耗对外连接池
	if r.qpsLimiter != nil && !r.qpsLimiter.Allow() {
		return ErrFallbackRateLimited
	}

	network, address, err := resolveTarget(r.server, r.port)
	if err != nil {
		return err
	}

	// 2. 最大连接时间硬超时 (Hard Timeout)
	relayCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: r.timeout}
	targetConn, err := dialer.DialContext(relayCtx, network, address)
	if err != nil {
		return err
	}
	defer targetConn.Close()

	// 监听生命周期超时，强制中断网络套接字
	go func() {
		<-relayCtx.Done()
		_ = targetConn.Close()
		_ = clientConn.Close()
	}()

	if len(initialData) > 0 {
		if _, err := targetConn.Write(initialData); err != nil {
			return err
		}
	}

	// 3. QoS 限速包装 (上下行独立限速)
	var clientReader io.Reader = clientConn
	var targetReader io.Reader = targetConn
	if r.qosLimit > 0 {
		clientReader = &rateLimitedReader{
			reader: clientConn,
			bucket: newBandwidthBucket(r.qosLimit, r.qosLimit*2),
		}
		targetReader = &rateLimitedReader{
			reader: targetConn,
			bucket: newBandwidthBucket(r.qosLimit, r.qosLimit*2),
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// 上行: Client -> Target
	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, clientReader)
		if cw, ok := targetConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		// 上行结束后，给下游预留响应窗口，防止半关闭挂死
		_ = targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	}()

	// 下行: Target -> Client
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetReader)
		if cw, ok := clientConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		// 响应发送完毕，强制中断客户端的阻塞读取，杜绝协程泄漏
		_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	}()

	wg.Wait()
	return ErrFallbackCompleted
}

var (
	defaultRelayerOnce sync.Once
	defaultRelayer     *FallbackRelayer
)

// FallbackRelay 兼容旧签名入口
func FallbackRelay(ctx context.Context, clientConn net.Conn, targetAddr string, initialData []byte, timeout time.Duration) error {
	defaultRelayerOnce.Do(func() {
		defaultRelayer = NewFallbackRelayer(targetAddr, 0, 5, "50kb/s", timeout)
	})
	return defaultRelayer.Relay(ctx, clientConn, initialData)
}

func resolveTarget(server string, port uint16) (network string, address string, err error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", "", errors.New("ptls: fallback server not configured")
	}

	if strings.HasPrefix(server, "unix:") {
		return "unix", strings.TrimPrefix(server, "unix:"), nil
	}
	if strings.HasPrefix(server, "/") || strings.HasPrefix(server, "./") || strings.HasPrefix(server, "../") ||
		strings.HasSuffix(server, ".sock") || strings.HasSuffix(server, ".socket") {
		return "unix", server, nil
	}

	network = "tcp"
	if port > 0 {
		address = net.JoinHostPort(server, strconv.Itoa(int(port)))
	} else {
		if _, _, splitErr := net.SplitHostPort(server); splitErr == nil {
			address = server
		} else {
			address = net.JoinHostPort(server, "443")
		}
	}
	return network, address, nil
}

// -----------------------------------------------------------------------------
// 流控组件：令牌桶与限速器
// -----------------------------------------------------------------------------

type tokenBucket struct {
	rate       float64
	burst      float64
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

func newTokenBucket(rate float64, burst float64) *tokenBucket {
	return &tokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     burst,
		lastUpdate: time.Now(),
	}
}

func (tb *tokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	tb.lastUpdate = now

	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}

type bandwidthBucket struct {
	bytesPerSec int64
	burst       int64
	tokens      int64
	lastUpdate  time.Time
	mu          sync.Mutex
}

func newBandwidthBucket(bytesPerSec int64, burst int64) *bandwidthBucket {
	if burst < bytesPerSec {
		burst = bytesPerSec
	}
	// io.Copy 默认缓冲区为 32KB，burst 不得低于 32KB，防止单次 Read 阻塞整个令牌桶
	if burst < 32768 {
		burst = 32768
	}
	return &bandwidthBucket{
		bytesPerSec: bytesPerSec,
		burst:       burst,
		tokens:      burst,
		lastUpdate:  time.Now(),
	}
}

func (b *bandwidthBucket) Wait(n int64) {
	if b == nil || b.bytesPerSec <= 0 || n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastUpdate).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b.lastUpdate = now

	b.tokens += int64(elapsed * float64(b.bytesPerSec))
	if b.tokens > b.burst {
		b.tokens = b.burst
	}

	b.tokens -= n
	if b.tokens < 0 {
		deficit := -b.tokens
		sleepDuration := time.Duration(float64(deficit) / float64(b.bytesPerSec) * float64(time.Second))
		time.Sleep(sleepDuration)
		b.tokens = 0
		b.lastUpdate = time.Now()
	}
}

type rateLimitedReader struct {
	reader io.Reader
	bucket *bandwidthBucket
}

func (r *rateLimitedReader) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	if n > 0 && r.bucket != nil {
		r.bucket.Wait(int64(n))
	}
	return n, err
}

func ParseBandwidth(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}
	s = strings.TrimSuffix(s, "/sec")
	s = strings.TrimSuffix(s, "/s")
	s = strings.TrimSuffix(s, "ps")
	s = strings.TrimSuffix(s, "sec")

	var multiplier int64 = 1
	switch {
	case strings.HasSuffix(s, "gib"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "gib")
	case strings.HasSuffix(s, "gb"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "gb")
	case strings.HasSuffix(s, "g"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "g")
	case strings.HasSuffix(s, "mib"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "mib")
	case strings.HasSuffix(s, "mb"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "mb")
	case strings.HasSuffix(s, "m"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "kib"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "kib")
	case strings.HasSuffix(s, "kb"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "kb")
	case strings.HasSuffix(s, "k"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "k")
	case strings.HasSuffix(s, "b"):
		multiplier = 1
		s = strings.TrimSuffix(s, "b")
	}

	val, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid bandwidth format: %s", s)
	}
	if val <= 0 {
		return 0, nil
	}
	return int64(val * float64(multiplier)), nil
}