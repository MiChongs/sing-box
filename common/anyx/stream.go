package anyx

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

type stream struct {
	id          uint32
	session     *session
	destination M.Socksaddr

	readerAccess    sync.Mutex
	readAccess      sync.Mutex
	readPending     *buf.Buffer
	readCache       *buf.Buffer
	readSignal      chan struct{}
	readSpace       chan struct{}
	readEnd         bool
	readErr         error
	readWaitOptions common.TypedValue[N.ReadWaitOptions]

	readDeadline  pipe.Deadline
	writeDeadline pipe.Deadline

	writeAccess     sync.Mutex
	handshakeAccess sync.Mutex
	handshakeDone   atomic.Bool

	reportOnce sync.Once
	closeOnce  sync.Once
	closeErr   error
	done       chan struct{}
}

func newStream(id uint32, parent *session) *stream {
	created := &stream{
		id:         id,
		session:    parent,
		readSignal: make(chan struct{}, 1),
		readSpace:  make(chan struct{}, 1),
		done:       make(chan struct{}),
	}
	created.readDeadline = pipe.MakeDeadline()
	created.writeDeadline = pipe.MakeDeadline()
	return created
}

func (s *stream) push(buffer *buf.Buffer) {
	for {
		s.readAccess.Lock()
		if s.readEnd {
			s.readAccess.Unlock()
			buffer.Release()
			return
		}
		if s.readPending == nil {
			s.readPending = buffer
			s.readAccess.Unlock()
			select {
			case s.readSignal <- struct{}{}:
			default:
			}
			return
		}
		s.readAccess.Unlock()
		select {
		case <-s.readSpace:
		case <-s.done:
			buffer.Release()
			return
		}
	}
}

func (s *stream) waitReadLocked() (*buf.Buffer, error) {
	for {
		if s.readPending != nil {
			buffer := s.readPending
			s.readPending = nil
			select {
			case s.readSpace <- struct{}{}:
			default:
			}
			return buffer, nil
		}
		if s.readEnd {
			select {
			case s.readSignal <- struct{}{}:
			default:
			}
			return nil, s.readErr
		}
		s.readAccess.Unlock()
		select {
		case <-s.readSignal:
			s.readAccess.Lock()
		case <-s.readDeadline.Wait():
			s.readAccess.Lock()
			return nil, os.ErrDeadlineExceeded
		}
	}
}

func (s *stream) endRead(err error) {
	s.readAccess.Lock()
	if !s.readEnd {
		s.readEnd = true
		s.readErr = err
	}
	s.readAccess.Unlock()
	select {
	case s.readSignal <- struct{}{}:
	default:
	}
}

func (s *stream) discardRead(err error) {
	s.readAccess.Lock()
	if !s.readEnd {
		s.readEnd = true
		s.readErr = err
	}
	pending := s.readPending
	cache := s.readCache
	s.readPending = nil
	s.readCache = nil
	s.readAccess.Unlock()
	if pending != nil {
		pending.Release()
	}
	if cache != nil {
		cache.Release()
	}
	select {
	case s.readSignal <- struct{}{}:
	default:
	}
}

func (s *stream) handshake(limit *pipe.Deadline) error {
	if s.handshakeDone.Load() {
		return nil
	}
	s.handshakeAccess.Lock()
	defer s.handshakeAccess.Unlock()
	return s.writeRequestLocked(limit)
}

func (s *stream) writeRequestLocked(limit *pipe.Deadline) error {
	if s.handshakeDone.Load() {
		return nil
	}
	select {
	case <-s.done:
		return s.closeErr
	default:
	}
	addressLen := M.SocksaddrSerializer.AddrPortLen(s.destination)
	request := buf.NewSize(s.session.pendingLen + frameOverhead*2 + addressLen)
	request.Resize(s.session.pendingLen, 0)
	putFrameHeader(request.Extend(frameOverhead), commandSYN, s.id, 0)
	putFrameHeader(request.Extend(frameOverhead), commandPSH, s.id, addressLen)
	err := M.SocksaddrSerializer.WriteAddrPort(request, s.destination)
	if err != nil {
		request.Release()
		return err
	}
	err = s.session.writeRequest(s, request, limit)
	if err != nil {
		return err
	}
	s.handshakeDone.Store(true)
	return nil
}

func (s *stream) checkWrite() error {
	select {
	case <-s.done:
		return s.closeErr
	case <-s.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	default:
		return nil
	}
}

func (s *stream) takeReadLocked() (*buf.Buffer, error) {
	for {
		buffer := s.readCache
		s.readCache = nil
		if buffer == nil {
			var err error
			buffer, err = s.waitReadLocked()
			if err != nil {
				return nil, err
			}
		}
		if !buffer.IsEmpty() {
			return buffer, nil
		}
		buffer.Release()
	}
}

func (s *stream) keepReadLocked(buffer *buf.Buffer) {
	if buffer.IsEmpty() {
		buffer.Release()
		return
	}
	s.readCache = buffer
}

func (s *stream) Read(p []byte) (int, error) {
	err := s.handshake(&s.readDeadline)
	if err != nil {
		return 0, err
	}
	s.readerAccess.Lock()
	defer s.readerAccess.Unlock()
	s.readAccess.Lock()
	defer s.readAccess.Unlock()
	buffer, err := s.takeReadLocked()
	if err != nil {
		return 0, err
	}
	n := copy(p, buffer.Bytes())
	buffer.Advance(n)
	s.keepReadLocked(buffer)
	return n, nil
}

func (s *stream) ReadBuffer(buffer *buf.Buffer) error {
	err := s.handshake(&s.readDeadline)
	if err != nil {
		return err
	}
	s.readerAccess.Lock()
	defer s.readerAccess.Unlock()
	s.readAccess.Lock()
	defer s.readAccess.Unlock()
	cache, err := s.takeReadLocked()
	if err != nil {
		return err
	}
	n, err := buffer.Write(cache.Bytes())
	cache.Advance(n)
	s.keepReadLocked(cache)
	return err
}

func (s *stream) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	s.readWaitOptions.Store(options)
	return false
}

func (s *stream) WaitReadBuffer() (*buf.Buffer, error) {
	err := s.handshake(&s.readDeadline)
	if err != nil {
		return nil, err
	}
	s.readerAccess.Lock()
	defer s.readerAccess.Unlock()
	s.readAccess.Lock()
	defer s.readAccess.Unlock()
	buffer, err := s.takeReadLocked()
	if err != nil {
		return nil, err
	}
	return s.readWaitOptions.Load().Copy(buffer), nil
}

func (s *stream) Write(p []byte) (int, error) {
	err := s.checkWrite()
	if err != nil {
		return 0, err
	}
	err = s.handshake(&s.writeDeadline)
	if err != nil {
		return 0, err
	}
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	return s.session.writeData(s, p)
}

func (s *stream) WriteBuffer(buffer *buf.Buffer) error {
	err := s.checkWrite()
	if err != nil {
		buffer.Release()
		return err
	}
	err = s.handshake(&s.writeDeadline)
	if err != nil {
		buffer.Release()
		return err
	}
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	return s.writeBufferLocked(buffer)
}

func (s *stream) writeBufferLocked(buffer *buf.Buffer) error {
	dataLen := buffer.Len()
	if dataLen == 0 {
		buffer.Release()
		return nil
	}
	if dataLen > maxFrameSize || buffer.Start() < frameOverhead {
		defer buffer.Release()
		return common.Error(s.session.writeData(s, buffer.Bytes()))
	}
	putFrameHeader(buffer.ExtendHeader(frameOverhead), commandPSH, s.id, dataLen)
	return s.session.write(s, buffer, &s.writeDeadline)
}

func (s *stream) Close() error {
	closing := s.closeLocally(net.ErrClosed)
	s.discardRead(net.ErrClosed)
	if !closing {
		return nil
	}
	if s.handshakeAccess.TryLock() {
		defer s.handshakeAccess.Unlock()
		return s.session.finishStream(s.id, s.handshakeDone.Load())
	}
	go func() {
		s.handshakeAccess.Lock()
		defer s.handshakeAccess.Unlock()
		s.session.finishStream(s.id, s.handshakeDone.Load())
	}()
	return nil
}

func (s *stream) closeByPeer() {
	if s.closeLocally(net.ErrClosed) {
		s.session.finishStream(s.id, false)
	}
	s.endRead(io.EOF)
}

// sing-anytls 0.0.13 Stream.closeWithError routes through Session.streamClosed, which
// writes cmdFIN; only a peer-sent FIN and a session teardown skip the notification.
func (s *stream) closeWithError(err error) {
	if s.closeLocally(err) {
		s.session.finishStream(s.id, s.handshakeDone.Load())
	}
	s.endRead(err)
}

func (s *stream) closeLocally(err error) bool {
	var closing bool
	s.closeOnce.Do(func() {
		s.closeErr = err
		close(s.done)
		closing = true
	})
	return closing
}

// commandSYNACK travels from the server to the client only; the reference server closes
// a stream whose client sends one, naming the address carried in the frame.
func (s *stream) HandshakeSuccess() error {
	if s.session.isClient {
		return nil
	}
	var reported bool
	s.reportOnce.Do(func() {
		reported = true
	})
	if !reported || s.session.peerVersion.Load() < protocolVersion {
		return nil
	}
	return s.session.writeFrame(commandSYNACK, s.id, nil)
}

func (s *stream) HandshakeFailure(err error) error {
	if s.session.isClient {
		return nil
	}
	var reported bool
	s.reportOnce.Do(func() {
		reported = true
	})
	if !reported || err == nil || s.session.peerVersion.Load() < protocolVersion {
		return nil
	}
	return s.session.writeFrame(commandSYNACK, s.id, []byte(err.Error()))
}

func (s *stream) NeedHandshakeForRead() bool {
	return !s.handshakeDone.Load()
}

func (s *stream) NeedHandshakeForWrite() bool {
	return !s.handshakeDone.Load()
}

func (s *stream) FrontHeadroom() int {
	return frameOverhead
}

func (s *stream) WriterMTU() int {
	return maxFrameSize
}

func (s *stream) LocalAddr() net.Addr {
	return s.session.conn.LocalAddr()
}

func (s *stream) RemoteAddr() net.Addr {
	return s.session.conn.RemoteAddr()
}

func (s *stream) SetReadDeadline(t time.Time) error {
	s.readDeadline.Set(t)
	return nil
}

func (s *stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
}

func (s *stream) SetDeadline(t time.Time) error {
	s.readDeadline.Set(t)
	s.writeDeadline.Set(t)
	return nil
}

var (
	_ N.ExtendedConn     = (*stream)(nil)
	_ N.ReadWaiter       = (*stream)(nil)
	_ N.EarlyReader      = (*stream)(nil)
	_ N.EarlyWriter      = (*stream)(nil)
	_ N.FrontHeadroom    = (*stream)(nil)
	_ N.WriterWithMTU    = (*stream)(nil)
	_ N.HandshakeSuccess = (*stream)(nil)
	_ N.HandshakeFailure = (*stream)(nil)
)
