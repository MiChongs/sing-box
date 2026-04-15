package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/common/hash"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/common/varbin"
)

type ClashServer interface {
	LifecycleService
	ConnectionTracker
	Mode() string
	ModeList() []string
	SetModeUpdateHook(hook *observable.Subscriber[struct{}])
	HistoryStorage() URLTestHistoryStorage
}

type URLTestHistory struct {
	Time  time.Time `json:"time"`
	Delay uint16    `json:"delay"`
}

type URLTestHistoryStorage interface {
	SetHook(hook *observable.Subscriber[struct{}])
	LoadURLTestHistory(tag string) *URLTestHistory
	DeleteURLTestHistory(tag string)
	StoreURLTestHistory(tag string, history *URLTestHistory)
	Close() error
}

type V2RayServer interface {
	LifecycleService
	StatsService() ConnectionTracker
}

// SmartService is the singleton that owns infrastructure shared by all Smart
// outbound groups: the LightGBM model, its auto-updater, and the training
// sample collector. It is registered on startup when experimental.smart is
// configured; Smart groups retrieve it via service.FromContext and opt in
// per-group via their use_lightgbm / collect_data flags.
//
// The concrete type lives in experimental/smart. Callers that need typed
// accessors (e.g. for LightGBM model / collector) should type-assert to the
// concrete *smart.Service.
type SmartService interface {
	LifecycleService
	// LightGBMEnabled reports whether the shared ML model is configured.
	LightGBMEnabled() bool
	// CollectorEnabled reports whether the shared training-data collector is configured.
	CollectorEnabled() bool
}

// GeoXService is the singleton that downloads and tracks global geo data
// assets (geoip.dat / geosite.dat / country.mmdb / GeoLite2-ASN.mmdb).
//
// Other services (currently only Smart group, via use_asn) retrieve local
// file paths through this service when their per-group config leaves the
// corresponding path empty.
type GeoXService interface {
	LifecycleService

	// Enabled reports whether experimental.geox.enabled was set.
	Enabled() bool

	// GeoIPPath returns the local path of the downloaded geoip.dat, or
	// "" if not configured / not yet downloaded.
	GeoIPPath() string
	// GeoSitePath returns the local path of the downloaded geosite.dat.
	GeoSitePath() string
	// MMDBPath returns the local path of the downloaded country.mmdb.
	MMDBPath() string
	// ASNPath returns the FIRST local ASN mmdb path (back-compat with the
	// single-source API). Empty if no ASN URL is configured. Callers that
	// want fallback across multiple providers should use ASNPaths().
	ASNPath() string
	// ASNPaths returns every configured ASN mmdb path in priority order.
	// Empty slice when no ASN URL is configured.
	ASNPaths() []string
}

type CacheFile interface {
	LifecycleService

	StoreFakeIP() bool
	FakeIPStorage

	StoreRDRC() bool
	RDRCStore

	StoreDNS() bool
	DNSCacheStore

	SetDisableExpire(disableExpire bool)
	SetOptimisticTimeout(timeout time.Duration)

	LoadMode() string
	StoreMode(mode string) error
	LoadSelected(group string) string
	StoreSelected(group string, selected string) error
	LoadGroupExpand(group string) (isExpand bool, loaded bool)
	StoreGroupExpand(group string, expand bool) error
	LoadRuleSet(tag string) *SavedBinary
	SaveRuleSet(tag string, set *SavedBinary) error
	LoadExternalUI(tag string) *SavedBinary
	SaveExternalUI(tag string, info *SavedBinary) error
	LoadSubscription(tag string) *SavedBinary
	SaveSubscription(tag string, sub *SavedBinary) error

	SmartDB() *bbolt.DB
}

type SavedBinary struct {
	Hash        hash.HashType
	Content     []byte
	LastUpdated time.Time
	LastEtag    string
}

func (s *SavedBinary) MarshalBinary() ([]byte, error) {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, uint8(1))
	if err != nil {
		return nil, err
	}
	hash, err := s.Hash.MarshalBinary()
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(hash)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(hash)
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.Content)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(s.Content)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.BigEndian, s.LastUpdated.Unix())
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.LastEtag)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.WriteString(s.LastEtag)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (s *SavedBinary) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	var version uint8
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil {
		return err
	}
	hashLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	hash := make([]byte, hashLength)
	_, err = io.ReadFull(reader, hash)
	if err != nil {
		return err
	}
	err = s.Hash.UnmarshalBinary(hash)
	if err != nil {
		return err
	}
	contentLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	s.Content = make([]byte, contentLength)
	_, err = io.ReadFull(reader, s.Content)
	if err != nil {
		return err
	}
	var lastUpdated int64
	err = binary.Read(reader, binary.BigEndian, &lastUpdated)
	if err != nil {
		return err
	}
	s.LastUpdated = time.Unix(lastUpdated, 0)
	etagLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	etagBytes := make([]byte, etagLength)
	_, err = io.ReadFull(reader, etagBytes)
	if err != nil {
		return err
	}
	s.LastEtag = string(etagBytes)
	return nil
}

type OutboundGroup interface {
	Outbound
	Now() string
	All() []string

	// Hidden reports the dashboard hint set in option.GroupCommonOption.
	// Returning true tells Clash-style front-ends to keep this group out
	// of the proxy switcher; routing rules continue to work either way.
	// All four built-in groups (Selector / URLTest / LoadBalance /
	// Smart) implement this — third-party group implementations should
	// return false when no hint is configured.
	Hidden() bool

	// Icon returns the opaque dashboard icon string from
	// option.GroupCommonOption (URL / data URI / emoji). Empty means
	// "no icon configured" and front-ends should fall back to their
	// default rendering.
	Icon() string
}

type URLTestGroup interface {
	OutboundGroup
	URLTest(ctx context.Context) (map[string]uint16, error)
}

type LoadBalanceGroup interface {
	OutboundGroup
	URLTest(ctx context.Context) (map[string]uint16, error)
}

type SelectorGroup interface {
	Selected() Outbound
}

func OutboundTag(detour Outbound) string {
	if group, isGroup := detour.(OutboundGroup); isGroup {
		if now := group.Now(); now != "" {
			return now
		}
	}
	return detour.Tag()
}
