package route

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	tf "github.com/sagernet/sing-box/common/tlsfragment"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

var _ adapter.ConnectionManager = (*ConnectionManager)(nil)

// joinDestinationAddresses 将目的地址切片格式化为 "[a,b,c]" 形式。
// 相比 strings.Join(common.Map(addrs, netip.Addr.String), ",") 省去一次
// 中间 []string 分配 + strings.Join 内部拼接缓冲，错误路径分配量显著降低。
func joinDestinationAddresses(addrs []netip.Addr) string {
	if len(addrs) == 0 {
		return "[]"
	}
	var sb strings.Builder
	// IPv4 ~15 字符、IPv6 ~40 字符，平均 20 足够，再加 "[]" 与分隔符
	sb.Grow(len(addrs)*22 + 2)
	sb.WriteByte('[')
	for i, a := range addrs {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(a.String())
	}
	sb.WriteByte(']')
	return sb.String()
}

type ConnectionManager struct {
	logger      logger.ContextLogger
	access      sync.Mutex
	connections list.List[io.Closer]
}

func NewConnectionManager(logger logger.ContextLogger) *ConnectionManager {
	return &ConnectionManager{
		logger: logger,
	}
}

func (m *ConnectionManager) Start(stage adapter.StartStage) error {
	return nil
}

func (m *ConnectionManager) Count() int {
	return m.connections.Len()
}

// CloseAll evicts every tracked connection and asks each to Close
// asynchronously. Callers no longer block on the per-conn close
// cost — critical on a network switch where N × Close() recurses
// into Smart.recordStats + bbolt writes + QUIC session teardown,
// serialised under this function's scope. For a busy config that
// can mean thousands of close()s in a tight loop, pegging CPU and
// holding the caller (ResetNetwork) for seconds.
//
// Semantics preserved: we still remove every tracked entry under
// the list lock before returning (so a subsequent TrackConn
// observes the list as empty). What changes is that the actual
// Close() of each evicted closer happens on a separate goroutine.
// If the caller needs synchronous completion, that contract was
// never advertised — Close() can take arbitrary time per conn,
// and no existing caller inspects post-return state beyond the
// fact that the tracker emptied.
func (m *ConnectionManager) CloseAll() {
	m.access.Lock()
	var closers []io.Closer
	for element := m.connections.Front(); element != nil; {
		nextElement := element.Next()
		closers = append(closers, element.Value)
		m.connections.Remove(element)
		element = nextElement
	}
	m.access.Unlock()
	if len(closers) == 0 {
		return
	}
	// Fire-and-forget: one dedicated goroutine serialises the
	// closes (preserves original per-close ordering) so we don't
	// spawn N goroutines for N conns under a network-switch
	// storm. The caller returns the moment the tracker is empty.
	go func() {
		for _, closer := range closers {
			common.Close(closer)
		}
	}()
}

func (m *ConnectionManager) Close() error {
	m.CloseAll()
	return nil
}

func (m *ConnectionManager) TrackConn(conn net.Conn) net.Conn {
	m.access.Lock()
	element := m.connections.PushBack(conn)
	m.access.Unlock()
	return &trackedConn{
		Conn:    conn,
		manager: m,
		element: element,
	}
}

func (m *ConnectionManager) TrackPacketConn(conn net.PacketConn) net.PacketConn {
	m.access.Lock()
	element := m.connections.PushBack(conn)
	m.access.Unlock()
	return &trackedPacketConn{
		PacketConn: conn,
		manager:    m,
		element:    element,
	}
}

func (m *ConnectionManager) NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remoteConn net.Conn
		err        error
	)
	if len(metadata.DestinationAddresses) > 0 || metadata.Destination.IsIP() {
		remoteConn, err = dialer.DialSerialNetwork(ctx, this, N.NetworkTCP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
	} else {
		remoteConn, err = this.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	}
	if err != nil {
		var remoteString string
		if len(metadata.DestinationAddresses) > 0 {
			remoteString = joinDestinationAddresses(metadata.DestinationAddresses)
		} else {
			remoteString = metadata.Destination.String()
		}
		var dialerString string
		if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
			dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			if outbound.Type() == C.TypeLoadBalance {
				dialerString += "[" + strings.Join(metadata.GetRealOutboundChain(), " -> ") + "]"
			}
		}
		err = E.Cause(err, "open connection to ", remoteString, dialerString)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	err = N.ReportConnHandshakeSuccess(conn, remoteConn)
	if err != nil {
		err = E.Cause(err, "report handshake success")
		remoteConn.Close()
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	if metadata.TLSFragment || metadata.TLSRecordFragment {
		remoteConn = tf.NewConn(remoteConn, ctx, metadata.TLSFragment, metadata.TLSRecordFragment, metadata.TLSFragmentFallbackDelay)
	}
	var done atomic.Bool
	if m.kickWriteHandshake(ctx, conn, remoteConn, false, &done, onClose) {
		return
	}
	if m.kickWriteHandshake(ctx, remoteConn, conn, true, &done, onClose) {
		return
	}
	go m.connectionCopy(ctx, conn, remoteConn, false, &done, onClose)
	go m.connectionCopy(ctx, remoteConn, conn, true, &done, onClose)
}

func (m *ConnectionManager) NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remotePacketConn   net.PacketConn
		remoteConn         net.Conn
		destinationAddress netip.Addr
		err                error
	)
	if metadata.UDPConnect {
		parallelDialer, isParallelDialer := this.(dialer.ParallelInterfaceDialer)
		if len(metadata.DestinationAddresses) > 0 {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = N.DialSerial(ctx, this, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses)
			}
		} else if metadata.Destination.IsIP() {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
			}
		} else {
			remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
		}
		if err != nil {
			var remoteString string
			if len(metadata.DestinationAddresses) > 0 {
				remoteString = joinDestinationAddresses(metadata.DestinationAddresses)
			} else {
				remoteString = metadata.Destination.String()
			}
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
				if outbound.Type() == C.TypeLoadBalance {
					dialerString += "[" + strings.Join(metadata.GetRealOutboundChain(), " -> ") + "]"
				}
			}
			err = E.Cause(err, "open packet connection to ", remoteString, dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
		remotePacketConn = bufio.NewUnbindPacketConn(remoteConn)
		connRemoteAddr := M.AddrFromNet(remoteConn.RemoteAddr())
		if connRemoteAddr != metadata.Destination.Addr {
			destinationAddress = connRemoteAddr
		}
	} else {
		if len(metadata.DestinationAddresses) > 0 {
			remotePacketConn, destinationAddress, err = dialer.ListenSerialNetworkPacket(ctx, this, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
		} else if packetDialer, withDestination := this.(dialer.PacketDialerWithDestination); withDestination {
			remotePacketConn, destinationAddress, err = packetDialer.ListenPacketWithDestination(ctx, metadata.Destination)
		} else {
			remotePacketConn, err = this.ListenPacket(ctx, metadata.Destination)
		}
		if err != nil {
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
				if outbound.Type() == C.TypeLoadBalance {
					dialerString += "[" + strings.Join(metadata.GetRealOutboundChain(), " -> ") + "]"
				}
			}
			err = E.Cause(err, "listen packet connection using ", dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
	}
	err = N.ReportPacketConnHandshakeSuccess(conn, remotePacketConn)
	if err != nil {
		conn.Close()
		remotePacketConn.Close()
		m.logger.ErrorContext(ctx, "report handshake success: ", err)
		return
	}
	if destinationAddress.IsValid() {
		var originDestination M.Socksaddr
		if metadata.RouteOriginalDestination.IsValid() {
			originDestination = metadata.RouteOriginalDestination
		} else {
			originDestination = metadata.Destination
		}
		if natConn, loaded := common.Cast[bufio.NATPacketConn](conn); loaded {
			natConn.UpdateDestination(destinationAddress)
		} else {
			destination := M.SocksaddrFrom(destinationAddress, metadata.Destination.Port)
			if metadata.Destination != destination {
				if metadata.UDPDisableDomainUnmapping {
					remotePacketConn = bufio.NewUnidirectionalNATPacketConn(bufio.NewPacketConn(remotePacketConn), destination, originDestination)
				} else {
					remotePacketConn = bufio.NewNATPacketConn(bufio.NewPacketConn(remotePacketConn), destination, originDestination)
				}
			} else if metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination {
				remotePacketConn = bufio.NewDestinationNATPacketConn(bufio.NewPacketConn(remotePacketConn), metadata.Destination, metadata.RouteOriginalDestination)
			}
		}
	} else if metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination {
		remotePacketConn = bufio.NewDestinationNATPacketConn(bufio.NewPacketConn(remotePacketConn), metadata.Destination, metadata.RouteOriginalDestination)
	}
	var udpTimeout time.Duration
	if metadata.UDPTimeout > 0 {
		udpTimeout = metadata.UDPTimeout
	} else {
		protocol := metadata.Protocol
		if protocol == "" {
			protocol = C.PortProtocols[metadata.Destination.Port]
		}
		if protocol != "" {
			udpTimeout = C.ProtocolTimeouts[protocol]
		}
	}
	if udpTimeout > 0 {
		ctx, conn = canceler.NewPacketConn(ctx, conn, udpTimeout)
	}
	destination := bufio.NewPacketConn(remotePacketConn)
	var done atomic.Bool
	go m.packetConnectionCopy(ctx, conn, destination, false, &done, onClose)
	go m.packetConnectionCopy(ctx, destination, conn, true, &done, onClose)
}

func (m *ConnectionManager) connectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	_, err := bufio.CopyWithIncreateBuffer(destination, source, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	if err != nil {
		common.Close(source, destination)
	} else if duplexDst, isDuplex := destination.(N.WriteCloser); isDuplex {
		err = duplexDst.CloseWrite()
		if err != nil {
			common.Close(source, destination)
		}
	} else {
		destination.Close()
	}
	if done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
		common.Close(source, destination)
	}
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "connection upload finished")
		} else if !E.IsClosedOrCanceled(err) {
			m.logger.ErrorContext(ctx, "connection upload closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection upload closed")
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "connection download finished")
		} else if !E.IsClosedOrCanceled(err) {
			m.logger.ErrorContext(ctx, "connection download closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection download closed")
		}
	}
}

func (m *ConnectionManager) kickWriteHandshake(ctx context.Context, source net.Conn, destination net.Conn, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) bool {
	if !N.NeedHandshakeForWrite(destination) {
		return false
	}
	var (
		cachedBuffer *buf.Buffer
		wrotePayload bool
	)
	sourceReader, readCounters := N.UnwrapCountReader(source, nil)
	destinationWriter, writeCounters := N.UnwrapCountWriter(destination, nil)
	if cachedReader, ok := sourceReader.(N.CachedReader); ok {
		cachedBuffer = cachedReader.ReadCached()
	}
	var err error
	if cachedBuffer != nil {
		wrotePayload = true
		dataLen := cachedBuffer.Len()
		_, err = destinationWriter.Write(cachedBuffer.Bytes())
		cachedBuffer.Release()
		if err == nil {
			for _, counter := range readCounters {
				counter(int64(dataLen))
			}
			for _, counter := range writeCounters {
				counter(int64(dataLen))
			}
		}
	} else {
		_ = destination.SetWriteDeadline(time.Now().Add(C.ReadPayloadTimeout))
		_, err = destinationWriter.Write(nil)
		_ = destination.SetWriteDeadline(time.Time{})
	}
	if err == nil {
		return false
	}
	if !wrotePayload && (E.IsMulti(err, os.ErrInvalid, context.DeadlineExceeded, io.EOF) || E.IsTimeout(err)) {
		return false
	}
	if !done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
	}
	common.Close(source, destination)
	if !direction {
		m.logger.ErrorContext(ctx, "connection upload handshake: ", err)
	} else {
		m.logger.ErrorContext(ctx, "connection download handshake: ", err)
	}
	return true
}

func (m *ConnectionManager) packetConnectionCopy(ctx context.Context, source N.PacketReader, destination N.PacketWriter, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	_, err := bufio.CopyPacket(destination, source)
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "packet upload finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet upload closed")
		} else {
			m.logger.DebugContext(ctx, "packet upload closed: ", err)
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "packet download finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet download closed")
		} else {
			m.logger.DebugContext(ctx, "packet download closed: ", err)
		}
	}
	if !done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
	}
	common.Close(source, destination)
}

type trackedConn struct {
	net.Conn
	manager *ConnectionManager
	element *list.Element[io.Closer]
}

func (c *trackedConn) Close() error {
	c.manager.access.Lock()
	c.manager.connections.Remove(c.element)
	c.manager.access.Unlock()
	return c.Conn.Close()
}

func (c *trackedConn) Upstream() any {
	return c.Conn
}

func (c *trackedConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedConn) WriterReplaceable() bool {
	return true
}

type trackedPacketConn struct {
	net.PacketConn
	manager *ConnectionManager
	element *list.Element[io.Closer]
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if packetReader, ok := c.PacketConn.(N.PacketReader); ok {
		return packetReader.ReadPacket(buffer)
	}
	_, addr, err := buffer.ReadPacketFrom(c.PacketConn)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.SocksaddrFromNet(addr).Unwrap(), err
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if packetWriter, ok := c.PacketConn.(N.PacketWriter); ok {
		return packetWriter.WritePacket(buffer, destination)
	}
	defer buffer.Release()
	_, err := c.PacketConn.WriteTo(buffer.Bytes(), destination.UDPAddr())
	return err
}

func (c *trackedPacketConn) Close() error {
	c.manager.access.Lock()
	c.manager.connections.Remove(c.element)
	c.manager.access.Unlock()
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) Upstream() any {
	return bufio.NewPacketConn(c.PacketConn)
}

func (c *trackedPacketConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedPacketConn) WriterReplaceable() bool {
	return true
}
