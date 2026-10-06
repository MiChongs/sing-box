//go:build with_quic

package quicx

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func (s *serverSession[U]) loopMessages() {
	select {
	case <-s.connDone:
		return
	case <-s.authDone:
	}
	for {
		message, err := s.quicConn.ReceiveDatagram(s.ctx)
		if err != nil {
			s.closeWithError(E.Cause(err, "receive message"))
			return
		}
		hErr := s.handleMessage(message)
		if hErr != nil {
			s.closeWithError(E.Cause(hErr, "handle message"))
			return
		}
	}
}

func (s *serverSession[U]) handleMessage(data []byte) error {
	if len(data) < 2 {
		return E.New("invalid message")
	}
	if data[0] != Version {
		return E.New("unknown version ", data[0])
	}
	switch data[1] {
	case CommandPacket:
		message := allocMessage()
		err := decodeUDPMessage(message, data[2:])
		if err != nil {
			message.releaseMessage()
			return E.Cause(err, "decode UDP message")
		}
		return s.handleUDPMessage(message)
	case CommandHeartbeat:
		return nil
	default:
		return E.New("unknown command ", data[1])
	}
}

func (s *serverSession[U]) handleUDPMessage(message *udpMessage) error {
	if !message.destination.IsValid() {
		// A message without a destination cannot be routed, and the session is
		// created from the first message of its sessionID: creating one here
		// would route (and report) a session to ":0" and dial an outbound
		// packet connection it can never use. Fragments of one message all
		// carry the same destination, so the message is dropped whole.
		message.releaseMessage()
		return nil
	}
	sessionID := message.sessionID
	s.udpAccess.RLock()
	udpConn, loaded := s.udpConnMap[sessionID]
	s.udpAccess.RUnlock()
	if !loaded || common.Done(udpConn.ctx) {
		udpConn = newUDPPacketConn(auth.ContextWithUser(s.ctx, s.authUser), s.quicConn, sessionID, true, func() {
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		})
		s.udpAccess.Lock()
		s.udpConnMap[sessionID] = udpConn
		s.udpAccess.Unlock()
		newCtx, newConn := canceler.NewPacketConn(udpConn.ctx, udpConn, s.udpTimeout)
		go s.handler.NewPacketConnectionEx(newCtx, newConn, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), message.destination, nil)
	}
	return udpConn.inputPacket(message)
}
