//go:build with_quic

package quicx

import (
	E "github.com/sagernet/sing/common/exceptions"
)

func (c *Client) loopMessages(conn *clientQUICConnection) {
	for {
		message, err := conn.quicConn.ReceiveDatagram(c.ctx)
		if err != nil {
			conn.closeWithError(E.Cause(err, "receive message"))
			return
		}
		go func() {
			hErr := c.handleMessage(conn, message)
			if hErr != nil {
				conn.closeWithError(E.Cause(hErr, "handle message"))
			}
		}()
	}
}

func (c *Client) handleMessage(conn *clientQUICConnection, data []byte) error {
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
		return conn.handleUDPMessage(message)
	case CommandHeartbeat:
		return nil
	default:
		return E.New("unknown command ", data[1])
	}
}

func (c *clientQUICConnection) handleUDPMessage(message *udpMessage) error {
	c.udpAccess.RLock()
	udpConn, loaded := c.udpConnMap[message.sessionID]
	c.udpAccess.RUnlock()
	if !loaded {
		message.releaseMessage()
		return nil
	}
	select {
	case <-udpConn.ctx.Done():
		message.releaseMessage()
		return nil
	default:
	}
	return udpConn.inputPacket(message)
}
