package anyx

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
)

type keepSessionKey struct{}

func ContextWithKeepSession(ctx context.Context) context.Context {
	return context.WithValue(ctx, (*keepSessionKey)(nil), true)
}

func keepSessionFromContext(ctx context.Context) bool {
	keep, _ := ctx.Value((*keepSessionKey)(nil)).(bool)
	return keep
}

type ClientOptions struct {
	Password                 string
	ClientMetadata           string
	PaddingScheme            []byte
	PaddingSchemeInterval    time.Duration
	DialOut                  DialOutFunc
	IdleSessionCheckInterval time.Duration
	IdleSessionMinTimeout    time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
	DisableReuse             bool
	Logger                   logger.ContextLogger
}

type Client struct {
	password       [passwordLen]byte
	clientMetadata string
	dialOut        DialOutFunc
	logger         logger.ContextLogger
	padding        common.TypedValue[*paddingFactory]

	idleSessionMinTimeout time.Duration
	idleSessionTimeout    time.Duration
	minIdleSession        int
	disableReuse          bool
	closeIdle             atomic.Bool
	replenishing          atomic.Int32

	access       sync.Mutex
	closed       bool
	closeChan    chan struct{}
	sessions     map[*session]struct{}
	idleSessions list.List[*session]
}

func NewClient(options ClientOptions) (*Client, error) {
	paddingScheme := options.PaddingScheme
	if len(paddingScheme) == 0 {
		paddingScheme = []byte("auto")
	}
	factory, err := newPaddingFactory(paddingScheme)
	if err != nil {
		return nil, err
	}
	clientMetadata := options.ClientMetadata
	if clientMetadata == "" {
		clientMetadata = DefaultClientMetadata
	}

	idleSessionTimeout := options.IdleSessionTimeout
	if idleSessionTimeout <= minimumIdleSessionInterval {
		idleSessionTimeout = defaultIdleSessionTimeout
	}
	idleSessionMinTimeout := options.IdleSessionMinTimeout
	if idleSessionMinTimeout <= 0 || idleSessionMinTimeout > idleSessionTimeout {
		idleSessionMinTimeout = idleSessionTimeout * 7 / 10
	}

	client := &Client{
		password:              sha256.Sum256([]byte(options.Password)),
		clientMetadata:        clientMetadata,
		dialOut:               options.DialOut,
		logger:                options.Logger,
		idleSessionMinTimeout: idleSessionMinTimeout,
		idleSessionTimeout:    idleSessionTimeout,
		minIdleSession:        options.MinIdleSession,
		disableReuse:          options.DisableReuse,
		sessions:              make(map[*session]struct{}),
		closeChan:             make(chan struct{}),
	}
	if client.logger == nil {
		client.logger = logger.NOP()
	}
	client.padding.Store(factory)
	interval := options.PaddingSchemeInterval
	if interval == 0 {
		interval = 30 * time.Minute
	}
	if strings.TrimSpace(string(paddingScheme)) == "auto" && interval >= time.Minute {
		go client.autoPaddingLoop(interval)
	}
	return client, nil
}

func (c *Client) autoPaddingLoop(interval time.Duration) {
	minWait := interval * 7 / 10
	maxWait := interval * 13 / 10
	diff := maxWait - minWait
	for {
		wait := minWait
		if diff > 0 {
			offset, err := rand.Int(rand.Reader, big.NewInt(int64(diff)+1))
			if err == nil {
				wait = minWait + time.Duration(offset.Int64())
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			factory, err := newPaddingFactory([]byte("auto"))
			if err == nil {
				c.padding.Store(factory)
			}
		case <-c.closeChan:
			timer.Stop()
			return
		}
	}
}

func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsValid() {
		return nil, E.New("anyx: invalid destination: ", destination)
	}
	if len(destination.Fqdn) > 255 {
		return nil, E.New("anyx: domain too long: ", destination.Fqdn)
	}
	keepSession := keepSessionFromContext(ctx)
	var idle *session
	if !c.disableReuse {
		idle = c.takeIdleSession()
	}
	if idle != nil {
		opened, err := idle.openStream(destination)
		if err == nil && !idle.IsClosed() {
			if keepSession {
				idle.keepOnce.Store(true)
			}
			return opened, nil
		}
		if opened != nil {
			opened.Close()
		}
		idle.Close()
	}
	created, err := c.createSession(ctx)
	if err != nil {
		return nil, err
	}
	opened, err := created.openStream(destination)
	if err != nil {
		created.Close()
		return nil, err
	}
	if keepSession {
		created.keepOnce.Store(true)
	}
	return opened, nil
}

func (c *Client) createSession(ctx context.Context) (*session, error) {
	c.access.Lock()
	closed := c.closed
	c.access.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	conn, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}
	paddingLen := c.padding.Load().GenerateHandshakePaddingSize()
	request := buf.NewSize(passwordLen + 2 + paddingLen)
	common.Must1(request.Write(c.password[:]))
	binary.BigEndian.PutUint16(request.Extend(2), uint16(paddingLen))
	common.Must(request.WriteZeroN(paddingLen))
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		conn.SetWriteDeadline(deadline)
	}
	_, err = conn.Write(request.Bytes())
	request.Release()
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "anyx: write request")
	}
	conn.SetWriteDeadline(time.Time{})
	created := newClientSession(c, conn)
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		created.Close()
		return nil, net.ErrClosed
	}
	c.sessions[created] = struct{}{}
	c.access.Unlock()
	go func() {
		loopErr := created.readLoop()
		created.Close()
		if !E.IsClosedOrCanceled(loopErr) {
			c.logger.Debug(E.Cause(loopErr, "anyx: session closed"))
		}
	}()
	return created, nil
}

func (c *Client) takeIdleSession() *session {
	var toClose []*session
	var found *session

	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	for element := c.idleSessions.Front(); element != nil; {
		idle := element.Value
		next := element.Next()
		c.idleSessions.Remove(element)
		idle.element = nil
		if idle.IsClosed() || idle.markForClose.Load() {
			delete(c.sessions, idle)
			toClose = append(toClose, idle)
			element = next
			continue
		}
		found = idle
		break
	}
	c.access.Unlock()

	for _, s := range toClose {
		s.Close()
	}
	return found
}

func (c *Client) releaseSession(released *session) {
	if c.disableReuse {
		c.access.Lock()
		delete(c.sessions, released)
		c.access.Unlock()
		released.Close()
		return
	}
	c.access.Lock()
	if released.IsClosed() || c.closed {
		if released.element != nil {
			c.idleSessions.Remove(released.element)
			released.element = nil
		}
		delete(c.sessions, released)
		c.access.Unlock()
		released.Close()
		return
	}
	if released.markForClose.Load() {
		if released.element != nil {
			c.idleSessions.Remove(released.element)
			released.element = nil
		}
		if !released.hasStreams() {
			delete(c.sessions, released)
			c.access.Unlock()
			released.Close()
			return
		}
		c.access.Unlock()
		return
	}
	keepOnce := released.keepOnce.Swap(false)
	if !released.hasStreams() && c.closeIdle.Load() && !keepOnce {
		if released.element != nil {
			c.idleSessions.Remove(released.element)
			released.element = nil
		}
		delete(c.sessions, released)
		c.access.Unlock()
		released.Close()
		return
	}
	if released.element == nil {
		released.idleSince = time.Now()
		released.element = c.idleSessions.PushFront(released)
	}
	c.access.Unlock()
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.closeIdle.Store(!keep)
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return
	}
	var closing []*session
	for element := c.idleSessions.Front(); element != nil; {
		idle := element.Value
		element = element.Next()
		if idle.hasStreams() {
			continue
		}
		c.idleSessions.Remove(idle.element)
		idle.element = nil
		delete(c.sessions, idle)
		closing = append(closing, idle)
	}
	c.access.Unlock()
	for _, idle := range closing {
		idle.Close()
	}
}

func (c *Client) Reset() {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return
	}
	sessions := make([]*session, 0, len(c.sessions))
	for closing := range c.sessions {
		closing.element = nil
		sessions = append(sessions, closing)
	}
	clear(c.sessions)
	c.idleSessions.Init()
	c.access.Unlock()
	for _, closing := range sessions {
		closing.Close()
	}
}

func (c *Client) removeSession(removed *session) {
	c.access.Lock()
	if removed.element != nil {
		c.idleSessions.Remove(removed.element)
		removed.element = nil
	}
	delete(c.sessions, removed)
	needReplenish := !c.closed && !c.closeIdle.Load() && c.minIdleSession > 0 &&
		(len(c.sessions)+int(c.replenishing.Load())) < c.minIdleSession
	c.access.Unlock()

	if needReplenish {
		go c.replenishIdleSession()
	}
}

func (c *Client) replenishIdleSession() {
	c.access.Lock()
	if c.closed || c.closeIdle.Load() || c.minIdleSession <= 0 ||
		(len(c.sessions)+int(c.replenishing.Load())) >= c.minIdleSession {
		c.access.Unlock()
		return
	}
	c.replenishing.Add(1)
	c.access.Unlock()

	defer c.replenishing.Add(-1)

	ctx, cancel := context.WithTimeout(context.Background(), defaultIdleSessionTimeout)
	defer cancel()

	created, err := c.createSession(ctx)
	if err != nil {
		return
	}
	c.releaseSession(created)
}

func (c *Client) Close() error {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	c.closed = true
	close(c.closeChan)
	sessions := make([]*session, 0, len(c.sessions))
	for closing := range c.sessions {
		closing.element = nil
		sessions = append(sessions, closing)
	}
	clear(c.sessions)
	c.idleSessions.Init()
	c.access.Unlock()
	var err error
	for _, closing := range sessions {
		err = E.Errors(err, closing.Close())
	}
	return err
}
