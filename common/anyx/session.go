package anyx

import (
	std_bufio "bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
	"github.com/sagernet/sing/common/x/list"
)

type session struct {
	conn         net.Conn
	reader       *std_bufio.Reader
	isClient     bool
	padding      *common.TypedValue[*paddingFactory]
	paddingLimit int
	logger       logger.ContextLogger

	writeAccess chan struct{}
	pending     *buf.Buffer
	pendingLen  int
	sendPadding bool
	packetCount uint32

	streamAccess sync.RWMutex
	streams      map[uint32]*stream
	streamID     atomic.Uint32
	peerVersion  atomic.Uint32

	timeoutAccess    sync.Mutex
	openTimeout      *time.Timer
	openTimeoutArmed atomic.Bool

	markForClose  atomic.Bool
	lifetimeTimer *time.Timer

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}

	client   *Client
	keepOnce atomic.Bool

	service          *Service
	serviceContext   context.Context
	source           M.Socksaddr
	settingsReceived bool

	idleSince time.Time
	element   *list.Element[*session]
}

func newClientSession(client *Client, conn net.Conn) *session {
	factory := client.padding.Load()
	settingsData := settings{
		settingVersion:    strconv.Itoa(protocolVersion),
		settingClient:     client.clientMetadata,
		settingPaddingMD5: factory.md5Sum,
	}.Bytes()
	pending := buf.NewSize(frameOverhead + len(settingsData))
	putFrameHeader(pending.Extend(frameOverhead), commandSettings, 0, len(settingsData))
	common.Must1(pending.Write(settingsData))
	s := &session{
		conn:        conn,
		reader:      std_bufio.NewReaderSize(conn, sessionReadBufferSize),
		isClient:    true,
		padding:     &client.padding,
		logger:      client.logger,
		writeAccess: make(chan struct{}, 1),
		pending:     pending,
		pendingLen:  pending.Len(),
		sendPadding: factory != nil && factory.stop > 0,
		streams:     make(map[uint32]*stream),
		done:        make(chan struct{}),
		client:      client,
	}
	s.startLifetimeTimer()
	go s.heartbeatLoop()
	return s
}

func (s *session) startLifetimeTimer() {
	if s.client == nil {
		return
	}
	maxTimeout := s.client.idleSessionTimeout
	if maxTimeout <= 0 {
		return
	}
	minTimeout := s.client.idleSessionMinTimeout
	if minTimeout <= 0 || minTimeout > maxTimeout {
		minTimeout = maxTimeout * 7 / 10
	}
	var wait time.Duration
	diff := maxTimeout - minTimeout
	if diff > 0 {
		offset, err := rand.Int(rand.Reader, big.NewInt(int64(diff)+1))
		if err == nil {
			wait = minTimeout + time.Duration(offset.Int64())
		} else {
			wait = minTimeout
		}
	} else {
		wait = minTimeout
	}
	s.lifetimeTimer = time.AfterFunc(wait, func() {
		if s.IsClosed() {
			return
		}
		s.streamAccess.Lock()
		if s.IsClosed() {
			s.streamAccess.Unlock()
			return
		}
		// 先原子置位 markForClose，彻底阻断并发的 openStream 抢入
		s.markForClose.Store(true)
		hasStreams := len(s.streams) > 0
		s.streamAccess.Unlock()

		if !hasStreams {
			_ = s.Close()
		}
	})
}

func newServerSession(ctx context.Context, service *Service, conn net.Conn, source M.Socksaddr) *session {
	factory := service.padding.Load()
	return &session{
		conn:           conn,
		reader:         std_bufio.NewReaderSize(conn, sessionReadBufferSize),
		padding:        &service.padding,
		paddingLimit:   service.paddingLimit,
		logger:         service.logger,
		writeAccess:    make(chan struct{}, 1),
		sendPadding:    factory != nil && factory.stop > 0,
		streams:        make(map[uint32]*stream),
		done:           make(chan struct{}),
		service:        service,
		serviceContext: ctx,
		source:         source,
	}
}

func putFrameHeader(header []byte, command byte, streamID uint32, length int) {
	header[0] = command
	binary.BigEndian.PutUint32(header[1:5], streamID)
	binary.BigEndian.PutUint16(header[5:7], uint16(length))
}

func (s *session) IsClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *session) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.conn.SetDeadline(time.Now())
		s.timeoutAccess.Lock()
		if s.openTimeout != nil {
			s.openTimeout.Stop()
		}
		s.timeoutAccess.Unlock()
		if s.lifetimeTimer != nil {
			s.lifetimeTimer.Stop()
		}
		s.closeErr = s.conn.Close()
		s.streamAccess.Lock()
		streams := s.streams
		s.streams = make(map[uint32]*stream)
		s.streamAccess.Unlock()
		for _, closing := range streams {
			closing.closeWithError(net.ErrClosed)
		}
		select {
		case s.writeAccess <- struct{}{}:
			if s.pending != nil {
				s.pending.Release()
				s.pending = nil
			}
			<-s.writeAccess
		default:
		}
		if s.client != nil {
			s.client.removeSession(s)
		}
	})
	return s.closeErr
}

func (s *session) openStream(destination M.Socksaddr) (*stream, error) {
	s.streamAccess.Lock()
	if s.IsClosed() || s.markForClose.Load() {
		s.streamAccess.Unlock()
		return nil, net.ErrClosed
	}
	streamID := s.streamID.Add(1)
	opened := newStream(streamID, s)
	opened.destination = destination
	s.streams[streamID] = opened
	s.streamAccess.Unlock()
	return opened, nil
}

func (s *session) finishStream(streamID uint32, notify bool) error {
	s.streamAccess.Lock()
	delete(s.streams, streamID)
	remaining := len(s.streams)
	s.streamAccess.Unlock()
	var err error
	if notify && !s.IsClosed() {
		err = s.writeFrame(commandFIN, streamID, nil)
	}
	if s.client != nil && !s.IsClosed() {
		if remaining == 0 && s.markForClose.Load() {
			_ = s.Close()
		} else {
			s.client.releaseSession(s)
		}
	}
	return err
}

func (s *session) hasStreams() bool {
	s.streamAccess.RLock()
	defer s.streamAccess.RUnlock()
	return len(s.streams) > 0
}

func (s *session) armOpenTimeout(streamID uint32) {
	if !s.isClient || streamID < 2 || s.peerVersion.Load() < protocolVersion {
		return
	}
	s.timeoutAccess.Lock()
	if s.openTimeout == nil {
		s.openTimeout = time.AfterFunc(streamOpenTimeout, func() {
			s.Close()
		})
	} else {
		s.openTimeout.Reset(streamOpenTimeout)
	}
	s.openTimeoutArmed.Store(true)
	s.timeoutAccess.Unlock()
}

func (s *session) stopOpenTimeout() {
	s.timeoutAccess.Lock()
	if s.openTimeout != nil {
		s.openTimeout.Stop()
	}
	s.openTimeoutArmed.Store(false)
	s.timeoutAccess.Unlock()
}

func (s *session) discard(length int) error {
	if length == 0 {
		return nil
	}
	_, err := s.reader.Discard(length)
	return err
}

func (s *session) readFrame(length int) (*buf.Buffer, error) {
	buffer := buf.NewSize(length)
	_, err := buffer.ReadFullFrom(s.reader, length)
	if err != nil {
		buffer.Release()
		return nil, err
	}
	return buffer, nil
}

func (s *session) readLoop() error {
	var header [frameOverhead]byte
	for {
		_, err := io.ReadFull(s.reader, header[:])
		if err != nil {
			return err
		}
		if s.openTimeoutArmed.Load() {
			s.stopOpenTimeout()
		}
		streamID := binary.BigEndian.Uint32(header[1:5])
		length := int(binary.BigEndian.Uint16(header[5:7]))
		switch header[0] {
		case commandPSH:
			err = s.handlePush(streamID, length)
		case commandSYN:
			err = s.handleSYN(streamID, length)
		case commandSYNACK:
			err = s.handleSYNACK(streamID, length)
		case commandFIN:
			err = s.handleFIN(streamID, length)
		case commandSettings:
			err = s.handleSettings(length)
		case commandServerSettings:
			err = s.handleServerSettings(length)
		case commandUpdatePaddingScheme:
			err = s.handleUpdatePaddingScheme(length)
		case commandAlert:
			err = s.handleAlert(length)
		case commandHeartRequest:
			err = s.discard(length)
			if err == nil {
				go func() {
					_ = s.writeFrame(commandHeartResponse, streamID, nil)
				}()
			}
		case commandWaste:
			if s.paddingLimit > 0 && length > s.paddingLimit {
				return E.New("anyx: waste frame length ", length, " exceeds limit ", s.paddingLimit)
			}
			err = s.discard(length)
		default:
			err = s.discard(length)
		}
		if err != nil {
			return err
		}
	}
}

func (s *session) handlePush(streamID uint32, length int) error {
	if length == 0 {
		return nil
	}
	s.streamAccess.RLock()
	target := s.streams[streamID]
	s.streamAccess.RUnlock()
	if target == nil {
		return s.discard(length)
	}
	options := target.readWaitOptions.Load()
	buffer := options.NewBufferSize(length)
	_, err := buffer.ReadFullFrom(s.reader, length)
	if err != nil {
		buffer.Release()
		return err
	}
	options.PostReturn(buffer)
	target.push(buffer)
	return nil
}

func (s *session) handleSYN(streamID uint32, length int) error {
	if s.isClient {
		return s.discard(length)
	}
	if !s.settingsReceived {
		s.writeFrame(commandAlert, 0, []byte(ErrMissingSettings.Error()))
		return ErrMissingSettings
	}
	err := s.discard(length)
	if err != nil {
		return err
	}
	s.streamAccess.Lock()
	if s.IsClosed() {
		s.streamAccess.Unlock()
		return net.ErrClosed
	}
	_, loaded := s.streams[streamID]
	if loaded {
		s.streamAccess.Unlock()
		return nil
	}
	accepted := newStream(streamID, s)
	accepted.handshakeDone.Store(true)
	s.streams[streamID] = accepted
	s.streamAccess.Unlock()
	go s.service.acceptStream(s, accepted)
	return nil
}

func (s *session) handleSYNACK(streamID uint32, length int) error {
	if !s.isClient {
		return s.discard(length)
	}
	if length == 0 {
		return nil
	}
	buffer, err := s.readFrame(length)
	if err != nil {
		return err
	}
	message := string(buffer.Bytes())
	buffer.Release()
	s.streamAccess.RLock()
	target := s.streams[streamID]
	s.streamAccess.RUnlock()
	if target != nil {
		target.closeWithError(E.New("anyx: remote: ", message))
	}
	return nil
}

func (s *session) handleFIN(streamID uint32, length int) error {
	err := s.discard(length)
	if err != nil {
		return err
	}
	s.streamAccess.Lock()
	target := s.streams[streamID]
	delete(s.streams, streamID)
	s.streamAccess.Unlock()
	if target != nil {
		target.closeByPeer()
	}
	return nil
}

func (s *session) handleSettings(length int) error {
	if s.isClient || length == 0 {
		return s.discard(length)
	}
	buffer, err := s.readFrame(length)
	if err != nil {
		return err
	}
	peerSettings := parseSettings(buffer.Bytes())
	buffer.Release()
	s.settingsReceived = true
	version, err := strconv.Atoi(peerSettings[settingVersion])
	if err != nil || version < protocolVersion {
		return nil
	}
	s.peerVersion.Store(uint32(version))
	return s.writeFrame(commandServerSettings, 0, settings{settingVersion: strconv.Itoa(protocolVersion)}.Bytes())
}

func (s *session) handleServerSettings(length int) error {
	if !s.isClient || length == 0 {
		return s.discard(length)
	}
	buffer, err := s.readFrame(length)
	if err != nil {
		return err
	}
	version, err := strconv.Atoi(parseSettings(buffer.Bytes())[settingVersion])
	buffer.Release()
	if err == nil && version > 0 {
		s.peerVersion.Store(uint32(version))
	}
	return nil
}

func (s *session) handleUpdatePaddingScheme(length int) error {
	return s.discard(length)
}

func (s *session) handleAlert(length int) error {
	if length == 0 {
		return nil
	}
	buffer, err := s.readFrame(length)
	if err != nil {
		return err
	}
	if !s.isClient {
		buffer.Release()
		return net.ErrClosed
	}
	alert := E.New("anyx: alert from peer: ", string(buffer.Bytes()))
	buffer.Release()
	s.logger.Error(alert)
	return alert
}

func (s *session) lockWriteUntil(target *stream, limit *pipe.Deadline) error {
	select {
	case <-target.done:
		return target.closeErr
	case <-limit.Wait():
		return os.ErrDeadlineExceeded
	default:
	}
	select {
	case s.writeAccess <- struct{}{}:
		return nil
	case <-limit.Wait():
		return os.ErrDeadlineExceeded
	case <-target.done:
		return target.closeErr
	}
}

func (s *session) lockWrite() error {
	select {
	case s.writeAccess <- struct{}{}:
		return nil
	case <-s.done:
		return net.ErrClosed
	}
}

func (s *session) unlockWrite() {
	<-s.writeAccess
}

func (s *session) write(target *stream, buffer *buf.Buffer, limit *pipe.Deadline) error {
	err := s.lockWriteUntil(target, limit)
	if err != nil {
		buffer.Release()
		return err
	}
	err = s.writeLocked(buffer)
	s.unlockWrite()
	if err != nil {
		s.Close()
	}
	return err
}

// sing-anytls 0.0.13 Session.OpenStream writes cmdSYN as its own padded record and
// Client.CreateProxy writes the destination without any payload as the next one; only on
// a new session are both still buffered behind the settings frame and flushed as one record.
func (s *session) writeRequest(target *stream, request *buf.Buffer, limit *pipe.Deadline) error {
	err := s.lockWriteUntil(target, limit)
	if err != nil {
		request.Release()
		return err
	}
	s.armOpenTimeout(target.id)
	if s.pending != nil {
		err = s.writeLocked(request)
	} else {
		err = s.writePacketLocked(request.To(frameOverhead))
		if err == nil {
			err = s.writePacketLocked(request.From(frameOverhead))
		}
		request.Release()
	}
	s.unlockWrite()
	if err != nil {
		s.Close()
	}
	return err
}

func (s *session) writeData(target *stream, data []byte) (int, error) {
	dataLen := len(data)
	if dataLen == 0 {
		return 0, nil
	}
	frameCount := (dataLen + maxFrameSize - 1) / maxFrameSize
	frame := buf.NewSize(dataLen + frameCount*frameOverhead)
	for len(data) > 0 {
		chunkLen := min(len(data), maxFrameSize)
		putFrameHeader(frame.Extend(frameOverhead), commandPSH, target.id, chunkLen)
		common.Must1(frame.Write(data[:chunkLen]))
		data = data[chunkLen:]
	}
	err := s.write(target, frame, &target.writeDeadline)
	if err != nil {
		return 0, err
	}
	return dataLen, nil
}

func (s *session) writeFrame(command byte, streamID uint32, data []byte) error {
	if len(data) > maxFrameSize {
		return E.New("anyx: control frame too large: ", len(data))
	}
	frame := buf.NewSize(frameOverhead + len(data))
	putFrameHeader(frame.Extend(frameOverhead), command, streamID, len(data))
	common.Must1(frame.Write(data))
	err := s.lockWrite()
	if err != nil {
		frame.Release()
		return err
	}
	s.conn.SetWriteDeadline(time.Now().Add(controlFrameWriteTimeout))
	err = s.writeLocked(frame)
	s.conn.SetWriteDeadline(time.Time{})
	s.unlockWrite()
	if err != nil {
		s.Close()
	}
	return err
}

func (s *session) writeLocked(buffer *buf.Buffer) error {
	pending := s.pending
	if pending != nil {
		s.pending = nil
		defer pending.Release()
		if buffer.Start() >= pending.Len() {
			copy(buffer.ExtendHeader(pending.Len()), pending.Bytes())
		} else {
			combined := buf.NewSize(pending.Len() + buffer.Len())
			common.Must1(combined.Write(pending.Bytes()))
			common.Must1(combined.Write(buffer.Bytes()))
			buffer.Release()
			buffer = combined
		}
	}
	defer func() {
		buffer.Release()
	}()
	return s.writePacketLocked(buffer.Bytes())
}

func (s *session) writePacketLocked(data []byte) error {
	if !s.sendPadding {
		return common.Error(s.conn.Write(data))
	}
	s.packetCount++
	factory := s.padding.Load()
	if s.packetCount >= factory.stop {
		s.sendPadding = false
		return common.Error(s.conn.Write(data))
	}
	for _, size := range factory.GenerateRecordPayloadSizes(s.packetCount) {
		if size == paddingCheckMark {
			if len(data) == 0 {
				return nil
			}
			continue
		}
		if len(data) > size {
			_, err := s.conn.Write(data[:size])
			if err != nil {
				return err
			}
			data = data[size:]
			continue
		}
		wasteCount := (size + maxFrameSize - 1) / maxFrameSize
		record := buf.NewSize(size + wasteCount*frameOverhead)
		if len(data) > 0 {
			common.Must1(record.Write(data))
			data = nil
			for remaining := size - record.Len(); remaining > frameOverhead; {
				wasteLen := min(remaining-frameOverhead, maxFrameSize)
				putFrameHeader(record.Extend(frameOverhead), commandWaste, 0, wasteLen)
				common.Must(record.WriteZeroN(wasteLen))
				remaining -= frameOverhead + wasteLen
			}
		} else {
			for remaining := size; remaining > 0; {
				wasteLen := min(remaining, maxFrameSize)
				putFrameHeader(record.Extend(frameOverhead), commandWaste, 0, wasteLen)
				common.Must(record.WriteZeroN(wasteLen))
				remaining -= wasteLen
			}
		}
		_, err := s.conn.Write(record.Bytes())
		record.Release()
		if err != nil {
			return err
		}
	}
	if len(data) == 0 {
		return nil
	}
	return common.Error(s.conn.Write(data))
}

func (s *session) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if s.IsClosed() {
				return
			}
			_ = s.writeFrame(commandHeartRequest, 0, nil)
		}
	}
}