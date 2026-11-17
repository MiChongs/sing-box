package dns

import (
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
)

var _ adapter.DNSResponseObserverRegistry = (*Router)(nil)

type dnsResponseObserverEntry struct {
	observer adapter.DNSResponseObserver
}

// dnsResponseObservers keeps an immutable snapshot for the DNS path, so a
// router without observers pays one atomic load per response.
type dnsResponseObservers struct {
	access   sync.Mutex
	snapshot atomic.Pointer[[]*dnsResponseObserverEntry]
}

func (o *dnsResponseObservers) register(observer adapter.DNSResponseObserver) func() {
	entry := &dnsResponseObserverEntry{observer: observer}
	o.access.Lock()
	var next []*dnsResponseObserverEntry
	if current := o.snapshot.Load(); current != nil {
		next = append(next, *current...)
	}
	next = append(next, entry)
	o.snapshot.Store(&next)
	o.access.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			o.access.Lock()
			defer o.access.Unlock()
			current := o.snapshot.Load()
			if current == nil {
				return
			}
			next := make([]*dnsResponseObserverEntry, 0, len(*current))
			for _, it := range *current {
				if it != entry {
					next = append(next, it)
				}
			}
			o.snapshot.Store(&next)
		})
	}
}

func (o *dnsResponseObservers) notify(message *mDNS.Msg, response *mDNS.Msg) {
	current := o.snapshot.Load()
	if current == nil {
		return
	}
	for _, entry := range *current {
		entry.observer(message, response)
	}
}
