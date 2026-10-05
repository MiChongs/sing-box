package easytier

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/easytier/easytier/easytier-go/platform"
	"github.com/stretchr/testify/require"
)

// 监听用途的 UDP socket 必须经 listenerControl 登记 eBPF self-bypass，
// 否则本机 eBPF 接管时回包会被 sendmsg 钩子劫持回 sing-box。
func TestBindUDPListenerPurposesUseListenerControl(t *testing.T) {
	t.Parallel()
	for _, purpose := range []platform.UDPBindPurpose{
		platform.UDPBindPortBoundListener,
		platform.UDPBindPortForward,
		platform.UDPBindPortLease,
	} {
		var registered []string
		factory := &socketFactory{
			listenerControl: func(network string, address string, _ syscall.RawConn) error {
				registered = append(registered, network)
				return nil
			},
		}
		conn, err := factory.BindUDP(context.Background(), platform.UDPBindOptions{
			LocalAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
			Purpose:   purpose,
		})
		require.NoError(t, err, "purpose %d", purpose)
		require.Equal(t, []string{"udp4"}, registered, "purpose %d", purpose)
		require.NoError(t, conn.Close())
	}
}

func TestDatagramConnCloseReleasesSelfBypass(t *testing.T) {
	t.Parallel()
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	var released int
	conn := newDatagramConn(packetConn)
	conn.cleanup = func() { released++ }
	require.NoError(t, conn.Close())
	require.Equal(t, 1, released)
	_, _, err = packetConn.ReadFrom(make([]byte, 1))
	require.ErrorIs(t, err, net.ErrClosed)
}
