package v2rayxhttp

import (
	"math"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

// XMUX: 把逻辑连接分摊到多条底层 HTTP 连接 (H1 连接池 / H2 / H3 连接)，并按
// 次数、时长轮换底层连接。移植自 XTLS/Xray-core v26.9.30 splithttp/mux.go。
//
//   - max_concurrency:     每条底层连接上同时承载的逻辑连接上限
//   - max_connections:     底层连接数上限 (与 max_concurrency 互斥)
//   - c_max_reuse_times:   一条底层连接最多被分配给多少条逻辑连接
//   - h_max_request_times: 一条底层连接最多发出多少个 HTTP 请求
//   - h_max_reusable_secs: 一条底层连接创建多少秒后不再分配新请求

type xmuxConn interface {
	IsClosed() bool
	Close() error
}

type xmuxClient struct {
	conn         xmuxConn
	running      atomic.Int32
	leftUsage    int32
	leftRequests atomic.Int32
	unreusableAt time.Time
	notUsed      atomic.Bool
}

func (c *xmuxClient) addRunning() {
	c.running.Add(1)
}

func (c *xmuxClient) doneRunning() {
	c.running.Add(-1)
	c.maybeClose()
}

// close the xmuxConn if it is not used and has no running requests
func (c *xmuxClient) maybeClose() {
	if c.notUsed.Load() && c.running.Load() <= 0 {
		_ = c.conn.Close()
	}
}

func (c *xmuxClient) isUnreusable(now time.Time) bool {
	return !c.unreusableAt.IsZero() && now.After(c.unreusableAt)
}

// xmuxManager 不是并发安全的，调用方 (endpoint) 负责加锁。
type xmuxManager struct {
	config      xmuxConfig
	concurrency int32
	connections int32
	newConnFunc func() xmuxConn
	clients     []*xmuxClient
}

func newXmuxManager(config xmuxConfig, newConnFunc func() xmuxConn) *xmuxManager {
	return &xmuxManager{
		config:      config,
		concurrency: config.maxConcurrency.rand(),
		connections: config.maxConnections.rand(),
		newConnFunc: newConnFunc,
	}
}

func (m *xmuxManager) newXmuxClient() *xmuxClient {
	client := &xmuxClient{
		conn:      m.newConnFunc(),
		leftUsage: -1,
	}
	if x := m.config.cMaxReuseTimes.rand(); x > 0 {
		client.leftUsage = x - 1
	}
	client.leftRequests.Store(math.MaxInt32)
	if x := m.config.hMaxRequestTimes.rand(); x > 0 {
		client.leftRequests.Store(x)
	}
	if x := m.config.hMaxReusableSecs.rand(); x > 0 {
		client.unreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.clients = append(m.clients, client)
	return client
}

func (m *xmuxManager) getXmuxClient() *xmuxClient {
	now := time.Now()
	for i := 0; i < len(m.clients); {
		client := m.clients[i]
		if client.conn.IsClosed() ||
			client.leftUsage == 0 ||
			client.leftRequests.Load() <= 0 ||
			client.isUnreusable(now) {
			client.notUsed.Store(true)
			client.maybeClose()
			m.clients = append(m.clients[:i], m.clients[i+1:]...)
		} else {
			i++
		}
	}

	if len(m.clients) == 0 {
		return m.newXmuxClient()
	}
	if m.connections > 0 && len(m.clients) < int(m.connections) {
		return m.newXmuxClient()
	}

	candidates := m.clients
	if m.concurrency > 0 {
		candidates = make([]*xmuxClient, 0, len(m.clients))
		for _, client := range m.clients {
			if client.running.Load() < m.concurrency {
				candidates = append(candidates, client)
			}
		}
	}
	if len(candidates) == 0 {
		return m.newXmuxClient()
	}

	client := candidates[rand.IntN(len(candidates))]
	if client.leftUsage > 0 {
		client.leftUsage--
	}
	return client
}

func (m *xmuxManager) close() {
	for _, client := range m.clients {
		client.notUsed.Store(true)
		_ = client.conn.Close()
	}
	m.clients = nil
}
