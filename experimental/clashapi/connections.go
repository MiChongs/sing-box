package clashapi

import (
	"bytes"
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/memstat"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/group"
	R "github.com/sagernet/sing-box/route/rule"
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
	r.Delete("/", closeAllConnections(ctx, network, trafficManager))
	r.Delete("/{id}", closeConnection(trafficManager))
	// Smart-block: close the connection AND mark its upstream Smart-selected
	// node as blocked so the group stops selecting it for a cooldown window.
	// Mirrors mihomo's `DELETE /connections/smart/{id}`.
	r.Delete("/smart/{id}", smartBlockConnection(ctx, trafficManager))
	return r
}

// connectionsSnapshotObject and connectionJSON encode through cached struct
// encoders. The dashboard polls this every second, and map-based encoding
// sorted and boxed every field of every connection on each tick.
type connectionsSnapshotObject struct {
	DownloadTotal int64            `json:"downloadTotal"`
	UploadTotal   int64            `json:"uploadTotal"`
	Connections   []connectionJSON `json:"connections"`
	Memory        uint64           `json:"memory"`
}

type connectionJSON struct {
	ID          uuid.UUID              `json:"id"`
	Metadata    connectionMetadataJSON `json:"metadata"`
	Upload      int64                  `json:"upload"`
	Download    int64                  `json:"download"`
	Start       time.Time              `json:"start"`
	Chains      []string               `json:"chains"`
	Rule        string                 `json:"rule"`
	RulePayload string                 `json:"rulePayload"`
}

type connectionMetadataJSON struct {
	Network         string     `json:"network"`
	Type            string     `json:"type"`
	SourceIP        netip.Addr `json:"sourceIP"`
	DestinationIP   netip.Addr `json:"destinationIP"`
	SourcePort      string     `json:"sourcePort"`
	DestinationPort string     `json:"destinationPort"`
	Host            string     `json:"host"`
	SniffHost       string     `json:"sniffHost"`
	DNSMode         string     `json:"dnsMode"`
	ProcessPath     string     `json:"processPath"`
}

// connectionsSnapshot reuses the connection slice of a previous snapshot of
// the same stream.
func connectionsSnapshot(trafficManager *trafficcontrol.Manager, connections []connectionJSON) connectionsSnapshotObject {
	uplinkTotal, downlinkTotal := trafficManager.Total()
	clear(connections)
	connections = connections[:0]
	for _, metadata := range trafficManager.Connections() {
		if metadata.OutboundType == C.TypeDNS {
			continue
		}
		connections = append(connections, (*connectionObject)(metadata).toJSON())
	}
	if connections == nil {
		connections = []connectionJSON{}
	}
	return connectionsSnapshotObject{
		DownloadTotal: downlinkTotal,
		UploadTotal:   uplinkTotal,
		Connections:   connections,
		Memory:        memstat.Inuse(),
	}
}

type connectionObject trafficcontrol.TrackerMetadata

func (c *connectionObject) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.toJSON())
}

func (c *connectionObject) toJSON() connectionJSON {
	metadata := (*trafficcontrol.TrackerMetadata)(c)
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
		if len(c.Metadata.ProcessInfo.PackageNames) > 0 {
			processPath = c.Metadata.ProcessInfo.PackageNames[0]
		} else if len(c.Metadata.ProcessInfo.ProcessPaths) > 0 {
			processPath = c.Metadata.ProcessInfo.ProcessPaths[0]
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
	// 同 mihomo 连接的 rule / rulePayload；未命中任何规则时落到 final 出站，相当于 mihomo 的 MATCH
	rule, rulePayload := "Match", ""
	if c.Rule != nil {
		rule, rulePayload = R.ClashRule(c.Rule)
	}
	return connectionJSON{
		ID: c.ID,
		Metadata: connectionMetadataJSON{
			Network:         c.Metadata.Network,
			Type:            inbound,
			SourceIP:        c.Metadata.Source.Addr,
			DestinationIP:   destinationAddr,
			SourcePort:      strconv.FormatUint(uint64(c.Metadata.Source.Port), 10),
			DestinationPort: strconv.FormatUint(uint64(c.Metadata.Destination.Port), 10),
			Host:            domain,
			SniffHost:       c.Metadata.SniffHost,
			DNSMode:         "normal",
			ProcessPath:     processPath,
		},
		Upload:      c.Upload.Load(),
		Download:    c.Download.Load(),
		Start:       c.CreatedAt,
		Chains:      metadata.ResolvedChain(),
		Rule:        rule,
		RulePayload: rulePayload,
	}
}

func getConnections(ctx context.Context, trafficManager *trafficcontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			render.JSON(w, r, connectionsSnapshot(trafficManager, nil))
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
		var connections []connectionJSON
		sendSnapshot := func() error {
			buf.Reset()
			snapshot := connectionsSnapshot(trafficManager, connections)
			connections = snapshot.Connections
			encodeErr := json.NewEncoder(buf).Encode(snapshot)
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

func closeAllConnections(ctx context.Context, network adapter.NetworkManager, trafficManager *trafficcontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		trafficManager.CloseAllConnections()
		network.ResetNetwork(ctx)
		render.NoContent(w, r)
	}
}

// smartBlockConnection closes the connection identified by id and blocks
// the member that carried it for the connection's target, until flushed
// (mihomo DELETE /connections/smart/{id}). The node is the chain slot after
// the Smart group (recorded by the dial trace).
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
		outboundMgr := service.FromContext[adapter.OutboundManager](ctx)
		if target == nil || outboundMgr == nil {
			tracker.Close()
			render.NoContent(w, r)
			return
		}
		var blocked struct {
			Group string `json:"group,omitempty"`
			Node  string `json:"node,omitempty"`
		}
		chain := common.Map(target.ResolvedOutboundChain(), adapter.Outbound.Tag)
		for i, tag := range chain {
			ob, ok := outboundMgr.Outbound(tag)
			if !ok {
				continue
			}
			sg, ok := ob.(*group.Smart)
			if !ok {
				region, isRegion := ob.(*group.SmartRegion)
				if !isRegion || region.Parent() == nil {
					continue
				}
				sg = region.Parent()
			}
			if i+1 >= len(chain) {
				break
			}
			metadata := target.Metadata
			host := metadata.Domain
			if metadata.Destination.IsDomain() {
				host = metadata.Destination.Fqdn
			}
			if sg.BlockConnection(metadata.Destination, host, metadata.SmartTarget, chain[i+1]) {
				blocked.Group, blocked.Node = tag, chain[i+1]
			}
			break
		}
		tracker.Close()
		render.JSON(w, r, blocked)
	}
}
