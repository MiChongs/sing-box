package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/sagernet/sing-box/common/hash"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/varbin"
)

type URLTestHistory struct {
	Time  time.Time `json:"time"`
	Delay uint16    `json:"delay"`
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

	CacheID() string

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
}

type SavedBinary struct {
	Hash        hash.HashType
	Content     []byte
	LastUpdated time.Time
	LastEtag    string
	URLHash     []byte
}

func (s *SavedBinary) MarshalBinary() ([]byte, error) {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, uint8(2))
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
	_, err = varbin.WriteUvarint(&buffer, uint64(len(s.URLHash)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(s.URLHash)
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
	if contentLength > uint64(reader.Len()) {
		return E.New("invalid content length: ", contentLength)
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
	if etagLength > uint64(reader.Len()) {
		return E.New("invalid etag length: ", etagLength)
	}
	etagBytes := make([]byte, etagLength)
	_, err = io.ReadFull(reader, etagBytes)
	if err != nil {
		return err
	}
	s.LastEtag = string(etagBytes)
	if version < 2 {
		return nil
	}
	urlHashLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	if urlHashLength > uint64(reader.Len()) {
		return E.New("invalid url hash length: ", urlHashLength)
	}
	s.URLHash = make([]byte, urlHashLength)
	_, err = io.ReadFull(reader, s.URLHash)
	if err != nil {
		return err
	}
	return nil
}

type OutboundGroup interface {
	Outbound
	Now() string
	All() []string
}

type PreMatchOutboundGroup interface {
	OutboundGroup
	// selectOutbound resolves nested groups and returns nil when the selected outbound is not eligible for pre-match.
	// Implementations must not advance consumptive selection state when selectOutbound returns nil, but may retain
	// a stable mapping when it is required for the following L4 selection to replay the same outbound.
	SelectPreMatchOutbound(metadata *InboundContext, selectOutbound func(Outbound) (Outbound, PreMatchAction)) (Outbound, PreMatchAction)
}

// OutboundGroupHint exposes the dashboard hints from option.GroupCommonOption.
// Hidden asks Clash-style front-ends to keep the group out of the proxy
// switcher (routing is unaffected); Icon is an opaque URL / data URI / emoji,
// empty when not configured.
type OutboundGroupHint interface {
	Hidden() bool
	Icon() string
}

type URLTestGroup interface {
	OutboundGroup
	URLTest(ctx context.Context) (map[string]uint16, error)
	PerformUpdateCheck()
}

type LoadBalanceGroup interface {
	OutboundGroup
	URLTest(ctx context.Context) (map[string]uint16, error)
}

type SelectorGroup interface {
	Selected() Outbound
}
