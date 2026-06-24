package clashapi

import (
	"bytes"
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid/v5"
)

func connectionRouter(ctx context.Context, network adapter.NetworkManager, trafficManager *trafficcontrol.Manager) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConnections(ctx, trafficManager))
	r.Delete("/", closeAllConnections(network, trafficManager))
	r.Delete("/{id}", closeConnection(trafficManager))
	// Smart-block: close the connection AND mark its upstream Smart-selected
	// node as blocked so the group stops selecting it for a cooldown window.
	// Mirrors mihomo's `DELETE /connections/smart/{id}`.
	r.Delete("/smart/{id}", smartBlockConnection(ctx, trafficManager))
	return r
}

func connectionsSnapshot(trafficManager *trafficcontrol.Manager) render.M {
	uplinkTotal, downlinkTotal := trafficManager.Total()
	connections := common.Filter(trafficManager.Connections(), func(metadata *trafficcontrol.TrackerMetadata) bool {
		return metadata.OutboundType != C.TypeDNS
	})
	return render.M{
		"downloadTotal": downlinkTotal,
		"uploadTotal":   uplinkTotal,
		"connections": common.Map(connections, func(metadata *trafficcontrol.TrackerMetadata) connectionObject {
			return connectionObject(*metadata)
		}),
		"memory": inuseMemory(),
	}
}

type connectionObject trafficcontrol.TrackerMetadata

func (c connectionObject) MarshalJSON() ([]byte, error) {
	var inbound string
	if c.Metadata.Inbound != "" {
		inbound = c.Metadata.InboundType + "/" + c.Metadata.Inbound
	} else {
		inbound = c.Metadata.InboundType
	}
	var domain string
	if c.Metadata.Destination.Fqdn != "" {
		domain = c.Metadata.Destination.Fqdn
	} else {
		domain = c.Metadata.Domain
	}
	var destinationAddr netip.Addr
	if len(c.Metadata.DestinationAddresses) > 0 {
		destinationAddr = c.Metadata.DestinationAddresses[0]
	} else {
		destinationAddr = c.Metadata.Destination.Addr
	}
	var processPath string
	if c.Metadata.ProcessInfo != nil {
		if c.Metadata.ProcessInfo.ProcessPath != "" {
			processPath = c.Metadata.ProcessInfo.ProcessPath
		} else if len(c.Metadata.ProcessInfo.AndroidPackageNames) > 0 {
			processPath = c.Metadata.ProcessInfo.AndroidPackageNames[0]
		}
		if processPath == "" {
			if c.Metadata.ProcessInfo.UserId != -1 {
				processPath = F.ToString(c.Metadata.ProcessInfo.UserId)
			}
		} else if c.Metadata.ProcessInfo.UserName != "" {
			processPath = F.ToString(processPath, " (", c.Metadata.ProcessInfo.UserName, ")")
		} else if c.Metadata.ProcessInfo.UserId != -1 {
			processPath = F.ToString(processPath, " (", c.Metadata.ProcessInfo.UserId, ")")
		}
	}
	var rule string
	if c.Rule != nil {
		rule = F.ToString(c.Rule, " => ", c.Rule.Action())
	} else {
		rule = "final"
	}
	chains := trafficcontrol.TrackerMetadata(c).Chains()
	return json.Marshal(map[string]any{
		"id": c.ID,
		"metadata": map[string]any{
			"network":         c.Metadata.Network,
			"type":            inbound,
			"sourceIP":        c.Metadata.Source.Addr,
			"destinationIP":   destinationAddr,
			"sourcePort":      F.ToString(c.Metadata.Source.Port),
			"destinationPort": F.ToString(c.Metadata.Destination.Port),
			"host":            domain,
			"sniffHost":       c.Metadata.SniffHost,
			"dnsMode":         "normal",
			"processPath":     processPath,
		},
		"upload":      c.Upload.Load(),
		"download":    c.Download.Load(),
		"start":       c.CreatedAt,
		"chains":      chains,
		"rule":        rule,
		"rulePayload": "",
	})
}

func getConnections(ctx context.Context, trafficManager *trafficcontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			render.JSON(w, r, connectionsSnapshot(trafficManager))
			return
		}

		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer conn.Close()

		intervalStr := r.URL.Query().Get("interval")
		interval := 1000
		if intervalStr != "" {
			t, err := strconv.Atoi(intervalStr)
			if err != nil {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, ErrBadRequest)
				return
			}

			interval = t
		}

		buf := &bytes.Buffer{}
		sendSnapshot := func() error {
			buf.Reset()
			encodeErr := json.NewEncoder(buf).Encode(connectionsSnapshot(trafficManager))
			if encodeErr != nil {
				return encodeErr
			}
			return wsutil.WriteServerText(conn, buf.Bytes())
		}

		if err = sendSnapshot(); err != nil {
			return
		}

		tick := time.NewTicker(time.Millisecond * time.Duration(interval))
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			if err = sendSnapshot(); err != nil {
				break
			}
		}
	}
}

func closeConnection(trafficManager *trafficcontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := uuid.FromStringOrNil(chi.URLParam(r, "id"))
		targetConnection := trafficManager.Connection(id)
		if targetConnection != nil {
			targetConnection.Close()
		}
		render.NoContent(w, r)
	}
}

func closeAllConnections(network adapter.NetworkManager, trafficManager *trafficcontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		trafficManager.CloseAllConnections()
		network.ResetNetwork()
		render.NoContent(w, r)
	}
}

// smartBlockConnection closes the connection identified by id and, if it was
// routed through a Smart group, additionally marks the selected node as
// blocked within that group. Looks up the group and its downstream node via
// the connection's RealOutboundChain.
func smartBlockConnection(ctx context.Context, trafficManager *trafficcontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := uuid.FromStringOrNil(chi.URLParam(r, "id"))
		if id == uuid.Nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		tracker := trafficManager.Connection(id)
		if tracker == nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		target := tracker.Metadata()
		tracker.Close()
		if target == nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		// Walk the chain looking for a Smart group. The slot immediately after
		// the Smart tag in the chain is the actual node it selected.
		chain := target.Metadata.GetRealOutboundChain()
		outboundMgr := service.FromContext[adapter.OutboundManager](ctx)
		if outboundMgr == nil {
			render.NoContent(w, r)
			return
		}
		var blocked struct {
			Group string `json:"group,omitempty"`
			Node  string `json:"node,omitempty"`
		}
		for i, tag := range chain {
			ob, ok := outboundMgr.Outbound(tag)
			if !ok {
				continue
			}
			sg, ok := ob.(*group.Smart)
			if !ok {
				continue
			}
			nodeTag := ""
			if i+1 < len(chain) {
				nodeTag = chain[i+1]
			}
			if nodeTag == "" {
				nodeTag = sg.Now()
			}
			if nodeTag == "" {
				break
			}
			if err := sg.MarkBlocked(nodeTag, group.DefaultBlockDuration); err == nil {
				blocked.Group = tag
				blocked.Node = nodeTag
			}
			break
		}

		render.JSON(w, r, blocked)
	}
}
