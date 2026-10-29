//go:build with_quic

package nowhere

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/egress"
	"github.com/sagernet/sing-box/protocol/nowhere/core/morph"
	"github.com/sagernet/sing-box/protocol/nowhere/core/qio"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing-box/protocol/nowhere/internal/quicsettings"
	E "github.com/sagernet/sing/common/exceptions"
)

// nowhereEgressReconnectDelay matches the reference CLI: a dropped
// registration waits three seconds before the host dials the Portal again.
const nowhereEgressReconnectDelay = 3 * time.Second

func RegisterEgressInbound(registry *inbound.Registry) {
	inbound.Register[option.NowhereEgressInboundOptions](registry, C.TypeNowhereEgress, NewEgressInbound)
}

// EgressInbound is the Nowhere 3 Egress client. It never listens: it dials the
// Portal over QUIC, registers as the Portal's single exit, and serves the flows
// the Portal opens through the sing-box router. A second Egress is rejected by
// the Portal (ErrBusy) and keeps retrying without preempting the current owner.
type EgressInbound struct {
	inbound.Adapter
	ctx       context.Context
	logger    log.ContextLogger
	sharedKey string
	dialQUIC  func(ctx context.Context) (qio.Conn, error)
	upstream  *routerNw3Upstream

	runCtx    context.Context
	cancelRun context.CancelFunc
	done      chan struct{}
}

func NewEgressInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NowhereEgressInboundOptions) (adapter.Inbound, error) {
	if options.Password == "" {
		return nil, E.New("nowhere: missing password")
	}
	if err := wire.ValidateServiceKey(options.Password); err != nil {
		return nil, E.Cause(err, "nowhere: egress key")
	}
	if options.Server == "" || options.ServerPort == 0 {
		return nil, E.New("nowhere: missing server")
	}
	congestionControl, err := quicsettings.ParseCongestionControl(options.QUICCongestionControl)
	if err != nil {
		return nil, err
	}
	endpoint := options.ServerOptions.Build()
	egressDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
	})
	if err != nil {
		return nil, E.Cause(err, "nowhere: build egress dialer")
	}
	// The Portal connection itself uses the system-selected source address;
	// dial4/dial6 only apply to the exit dials toward targets.
	tlsConfig, err := buildNowhereV3ClientTLS(ctx, logger, endpoint.String(), option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: options.ServerName,
		Insecure:   options.Insecure,
	}, options.Pin)
	if err != nil {
		return nil, err
	}
	var morphKeys *morph.Keys
	if resolveNowhereMorph(options.Morph, nowhereStackNw3) {
		keys := nowhereV3MorphKeys(options.Password)
		morphKeys = &keys
	}
	dialQUIC := func(dialCtx context.Context) (qio.Conn, error) {
		return dialNowhereV3QUICCarrier(dialCtx, egressDialer, endpoint, tlsConfig, options.QUICOptions, congestionControl, morphKeys)
	}
	return &EgressInbound{
		Adapter:   inbound.NewAdapter(C.TypeNowhereEgress, tag),
		ctx:       ctx,
		logger:    logger,
		sharedKey: options.Password,
		dialQUIC:  dialQUIC,
		upstream:  newRouterNw3Upstream(tag, C.TypeNowhereEgress, "", router),
	}, nil
}

func (h *EgressInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	h.runCtx, h.cancelRun = context.WithCancel(h.ctx)
	h.done = make(chan struct{})
	go h.run(h.runCtx)
	if scope != nil {
		scope.Add(h.Close)
	}
	return nil
}

// run owns one registration at a time: egress.Run dials the Portal, registers,
// and serves flows until the connection drops. Every drop returns here, waits
// out the cooldown, and dials again, so a restarted Portal or a stolen exit is
// picked up without operator action.
func (h *EgressInbound) run(ctx context.Context) {
	defer close(h.done)
	for {
		err := egress.Run(ctx, egress.Config{
			SharedKey: h.sharedKey,
			DialQUIC:  h.dialQUIC,
			Upstream:  h.upstream,
		})
		if ctx.Err() != nil {
			return
		}
		switch {
		case errors.Is(err, egress.ErrBusy):
			h.logger.Warn("nowhere egress: portal already has an exit registered; retrying")
		case err != nil:
			h.logger.Warn(E.Cause(err, "nowhere egress: registration dropped; reconnecting"))
		default:
			h.logger.Warn("nowhere egress: registration closed; reconnecting")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(nowhereEgressReconnectDelay):
		}
	}
}

func (h *EgressInbound) Close() error {
	if h.cancelRun != nil {
		h.cancelRun()
	}
	if h.done != nil {
		<-h.done
	}
	return nil
}

var _ adapter.Inbound = (*EgressInbound)(nil)
