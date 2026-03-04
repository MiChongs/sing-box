<<<<<<< HEAD
//go:build !linux && !darwin

package libbox

import "os"

func SubscribeNeighborTable(_ NeighborUpdateListener) (*NeighborSubscription, error) {
	return nil, os.ErrInvalid
}
||||||| parent of c69d3965f (Add Android support for MAC and hostname rule items)
=======
//go:build !linux

package libbox

import "os"

type NeighborEntry struct {
	Address    string
	MACAddress string
	Hostname   string
}

type NeighborEntryIterator interface {
	Next() *NeighborEntry
	HasNext() bool
}

type NeighborSubscription struct{}

func SubscribeNeighborTable(listener NeighborUpdateListener) (*NeighborSubscription, error) {
	return nil, os.ErrInvalid
}

func (s *NeighborSubscription) Close() {}
>>>>>>> c69d3965f (Add Android support for MAC and hostname rule items)
