package server

import (
	"context"
	"sync"
	"time"
)

type trackedTask struct {
	cancel     context.CancelCauseFunc
	close      func(error)
	stopBridge func()
	kind       taskKind
}

type taskKind uint8

const (
	taskConnection taskKind = iota
	taskRelay
)

type taskValueContext struct {
	context.Context
}

func (taskValueContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (taskValueContext) Done() <-chan struct{}       { return nil }
func (taskValueContext) Err() error                  { return nil }

type taskOwnership struct {
	tracker  *taskTracker
	id       uint64
	ctx      context.Context
	finish   func()
	mu       sync.Mutex
	consumed bool
}

func (o *taskOwnership) claim() (context.Context, func(), error) {
	if o == nil || o.tracker == nil {
		return nil, nil, ErrClosed
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.consumed {
		return nil, nil, ErrClosed
	}
	o.tracker.mu.Lock()
	task, active := o.tracker.tasks[o.id]
	closed := o.tracker.closed
	closeCause := o.tracker.closeCause
	if active && !closed {
		task.kind = taskRelay
		o.tracker.tasks[o.id] = task
		o.tracker.signalLocked()
	}
	o.tracker.mu.Unlock()
	if !active {
		return nil, nil, ErrClosed
	}
	if closed {
		if closeCause != nil {
			return nil, nil, closeCause
		}
		return nil, nil, ErrClosed
	}
	o.consumed = true
	return o.ctx, o.finish, nil
}

func (o *taskOwnership) finishCarrier() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.consumed {
		o.mu.Unlock()
		return
	}
	o.consumed = true
	finish := o.finish
	o.mu.Unlock()
	finish()
}

type taskOwnershipContextKey struct{}

func withTaskOwnership(ctx context.Context, ownership *taskOwnership) context.Context {
	return context.WithValue(ctx, taskOwnershipContextKey{}, ownership)
}

func taskOwnershipFrom(ctx context.Context) *taskOwnership {
	ownership, _ := ctx.Value(taskOwnershipContextKey{}).(*taskOwnership)
	return ownership
}

type taskTracker struct {
	mu         sync.Mutex
	tasks      map[uint64]trackedTask
	detached   map[uint64]trackedTask
	next       uint64
	changed    chan struct{}
	closed     bool
	closeCause error
}

func newTaskTracker() *taskTracker {
	return &taskTracker{
		tasks:    make(map[uint64]trackedTask),
		detached: make(map[uint64]trackedTask),
		changed:  make(chan struct{}),
	}
}

func (t *taskTracker) Start(parent context.Context) (context.Context, func(), error) {
	ctx, finish, _, err := t.start(parent, nil, true, taskRelay)
	return ctx, finish, err
}

func (t *taskTracker) StartTransport(parent context.Context, closer func(error)) (context.Context, func(), error) {
	ctx, finish, _, err := t.start(parent, closer, false, taskConnection)
	return ctx, finish, err
}

func (t *taskTracker) StartTransferableTransport(parent context.Context, closer func(error)) (context.Context, *taskOwnership, error) {
	ctx, finish, id, err := t.start(parent, closer, false, taskConnection)
	if err != nil {
		return nil, nil, err
	}
	return ctx, &taskOwnership{tracker: t, id: id, ctx: ctx, finish: finish}, nil
}

func (t *taskTracker) start(parent context.Context, closer func(error), cancelOnFinish bool, kind taskKind) (context.Context, func(), uint64, error) {
	if parent == nil {
		parent = context.Background()
	}
	t.mu.Lock()
	if t.closed {
		cause := t.closeCause
		t.mu.Unlock()
		if cause != nil {
			return nil, nil, 0, cause
		}
		return nil, nil, 0, ErrClosed
	}
	t.next++
	id := t.next
	ctx, cancel := context.WithCancelCause(taskValueContext{Context: parent})
	bridgeStop := make(chan struct{})
	bridgeExited := make(chan struct{})
	var bridgeOnce sync.Once
	stopBridge := func() {
		bridgeOnce.Do(func() {
			close(bridgeStop)
			<-bridgeExited
		})
	}
	if closer != nil {
		closeTransport := closer
		var closeOnce sync.Once
		closer = func(cause error) { closeOnce.Do(func() { closeTransport(cause) }) }
	}
	t.tasks[id] = trackedTask{cancel: cancel, close: closer, stopBridge: stopBridge, kind: kind}
	t.signalLocked()
	t.mu.Unlock()

	if parent.Done() == nil {
		close(bridgeExited)
	} else if parent.Err() != nil {
		cause := context.Cause(parent)
		if cause == nil {
			cause = parent.Err()
		}
		cancel(markForcedTermination(cause))
		close(bridgeExited)
	} else {
		go func() {
			defer close(bridgeExited)
			select {
			case <-parent.Done():
				cause := context.Cause(parent)
				if cause == nil {
					cause = parent.Err()
				}
				cancel(markForcedTermination(cause))
			case <-bridgeStop:
			}
		}()
	}

	var once sync.Once
	finish := func() {
		once.Do(func() {
			t.mu.Lock()
			if _, ok := t.tasks[id]; ok {
				delete(t.tasks, id)
				t.signalLocked()
			} else {
				delete(t.detached, id)
			}
			t.mu.Unlock()
			stopBridge()
			if cancelOnFinish {
				cancel(nil)
			}
		})
	}
	return ctx, finish, id, nil
}

func (t *taskTracker) BeginClose(cause error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		if cause == nil {
			cause = ErrClosed
		}
		t.closeCause = cause
		t.signalLocked()
	}
	t.mu.Unlock()
}

func (t *taskTracker) CancelAll(cause error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	cancels := make([]context.CancelCauseFunc, 0, len(t.tasks))
	for _, task := range t.tasks {
		cancels = append(cancels, task.cancel)
	}
	t.mu.Unlock()
	for _, cancel := range cancels {
		cancel(cause)
	}
}

func (t *taskTracker) CloseAll(cause error) {
	if t == nil {
		return
	}
	type closeEntry struct {
		id       uint64
		close    func(error)
		detached bool
	}
	t.mu.Lock()
	closers := make([]closeEntry, 0, len(t.tasks)+len(t.detached))
	for id, task := range t.tasks {
		if task.close != nil {
			closers = append(closers, closeEntry{id: id, close: task.close})
		}
	}
	for id, task := range t.detached {
		closers = append(closers, closeEntry{id: id, close: task.close, detached: true})
	}
	t.mu.Unlock()
	for _, entry := range closers {
		if entry.close != nil {
			entry.close(cause)
		}
		if entry.detached {
			t.mu.Lock()
			delete(t.detached, entry.id)
			t.mu.Unlock()
		}
	}
}

func (t *taskTracker) ForceDetach(cause error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.closed = true
	tasks := make([]trackedTask, 0, len(t.tasks))
	for id, task := range t.tasks {
		tasks = append(tasks, task)
		t.detached[id] = task
		delete(t.tasks, id)
	}
	t.signalLocked()
	t.mu.Unlock()
	for _, task := range tasks {
		task.cancel(cause)
		if task.stopBridge != nil {
			task.stopBridge()
		}
	}
}

func (t *taskTracker) ForceClose(cause error) {
	if t == nil {
		return
	}
	t.ForceDetach(cause)
	t.CloseAll(cause)
}

func (t *taskTracker) Wait(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		t.mu.Lock()
		if len(t.tasks) == 0 {
			t.mu.Unlock()
			return nil
		}
		changed := t.changed
		t.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *taskTracker) WaitRelays(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		t.mu.Lock()
		hasRelay := false
		for _, task := range t.tasks {
			if task.kind == taskRelay {
				hasRelay = true
				break
			}
		}
		if !hasRelay {
			t.mu.Unlock()
			return nil
		}
		changed := t.changed
		t.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *taskTracker) Close() {
	if t == nil {
		return
	}
	t.BeginClose(ErrClosed)
	_ = t.Wait(context.Background())
}

func (t *taskTracker) signalLocked() {
	close(t.changed)
	t.changed = make(chan struct{})
}
