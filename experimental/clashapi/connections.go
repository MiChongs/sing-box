package clashapi

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid/v5"
)

func connectionRouter(ctx context.Context, router adapter.Router, trafficManager *trafficontrol.Manager) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConnections(ctx, trafficManager))
	r.Delete("/", closeAllConnections(router, trafficManager))
	r.Delete("/{id}", closeConnection(trafficManager))
	// Smart-block: close the connection AND mark its upstream Smart-selected
	// node as blocked so the group stops selecting it for a cooldown window.
	// Mirrors mihomo's `DELETE /connections/smart/{id}`.
	r.Delete("/smart/{id}", smartBlockConnection(ctx, trafficManager))
	return r
}

func getConnections(ctx context.Context, trafficManager *trafficontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			snapshot := trafficManager.Snapshot()
			render.JSON(w, r, snapshot)
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
			snapshot := trafficManager.Snapshot()
			if err := json.NewEncoder(buf).Encode(snapshot); err != nil {
				return err
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

func closeConnection(trafficManager *trafficontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := uuid.FromStringOrNil(chi.URLParam(r, "id"))
		snapshot := trafficManager.Snapshot()
		for _, c := range snapshot.Connections {
			if id == c.Metadata().ID {
				c.Close()
				break
			}
		}
		render.NoContent(w, r)
	}
}

func closeAllConnections(router adapter.Router, trafficManager *trafficontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		snapshot := trafficManager.Snapshot()
		for _, c := range snapshot.Connections {
			c.Close()
		}
		router.ResetNetwork()
		render.NoContent(w, r)
	}
}

// smartBlockConnection closes the connection identified by id and, if it was
// routed through a Smart group, additionally marks the selected node as
// blocked within that group. Looks up the group and its downstream node via
// the connection's RealOutboundChain.
func smartBlockConnection(ctx context.Context, trafficManager *trafficontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := uuid.FromStringOrNil(chi.URLParam(r, "id"))
		if id == uuid.Nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		snapshot := trafficManager.Snapshot()
		var target *trafficontrol.TrackerMetadata
		for _, c := range snapshot.Connections {
			meta := c.Metadata()
			if meta != nil && meta.ID == id {
				target = meta
				c.Close()
				break
			}
		}
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
