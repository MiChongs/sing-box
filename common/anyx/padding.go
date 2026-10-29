package anyx

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	paddingCheckMark = -1
	maxPaddingSize   = 1 << 20
)

var DefaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)

type paddingRange struct {
	minSize int
	maxSize int
}

type paddingFactory struct {
	rawScheme []byte
	md5Sum    string
	stop      uint32
	records   map[uint32][]paddingRange
}

func newPaddingFactory(rawScheme []byte) (*paddingFactory, error) {
	trimmed := strings.TrimSpace(string(rawScheme))
	switch trimmed {
	case "off":
		return &paddingFactory{
			rawScheme: []byte("off"),
			md5Sum:    "off",
			stop:      0,
			records:   make(map[uint32][]paddingRange),
		}, nil
	case "auto":
		rawScheme = GenerateRandomPaddingScheme()
	}
	scheme := parseSettings(rawScheme)
	if len(scheme) == 0 {
		return nil, ErrPaddingScheme
	}
	stop, err := strconv.Atoi(scheme["stop"])
	if err != nil {
		return nil, E.Extend(ErrPaddingScheme, "parse stop: ", err)
	}
	sum := md5.Sum(rawScheme)
	factory := &paddingFactory{
		rawScheme: rawScheme,
		md5Sum:    hex.EncodeToString(sum[:]),
		stop:      uint32(stop),
		records:   make(map[uint32][]paddingRange),
	}
	for key, value := range scheme {
		packet, parseErr := strconv.ParseUint(key, 10, 32)
		if parseErr != nil || strconv.FormatUint(packet, 10) != key {
			continue
		}
		var ranges []paddingRange
		for item := range strings.SplitSeq(value, ",") {
			if item == "c" {
				ranges = append(ranges, paddingRange{minSize: paddingCheckMark})
				continue
			}
			minText, maxText, found := strings.Cut(item, "-")
			if !found {
				continue
			}
			minSize, minErr := strconv.Atoi(minText)
			if minErr != nil {
				continue
			}
			maxSize, maxErr := strconv.Atoi(maxText)
			if maxErr != nil {
				continue
			}
			if minSize > maxSize {
				minSize, maxSize = maxSize, minSize
			}
			if minSize <= 0 || maxSize > maxPaddingSize {
				continue
			}
			ranges = append(ranges, paddingRange{minSize: minSize, maxSize: maxSize})
		}
		if len(ranges) > 0 {
			factory.records[uint32(packet)] = ranges
		}
	}
	return factory, nil
}

func (f *paddingFactory) GenerateRecordPayloadSizes(packet uint32) []int {
	ranges := f.records[packet]
	if len(ranges) == 0 {
		return nil
	}
	sizes := make([]int, 0, len(ranges))
	for _, item := range ranges {
		switch {
		case item.minSize == paddingCheckMark:
			sizes = append(sizes, paddingCheckMark)
		case item.maxSize > item.minSize:
			offset := common.Must1(rand.Int(rand.Reader, big.NewInt(int64(item.maxSize-item.minSize))))
			sizes = append(sizes, item.minSize+int(offset.Int64()))
		default:
			sizes = append(sizes, item.minSize)
		}
	}
	return sizes
}

func (f *paddingFactory) GenerateHandshakePaddingSize() int {
	sizes := f.GenerateRecordPayloadSizes(0)
	if len(sizes) == 0 || sizes[0] < 0 {
		return 0
	}
	return sizes[0]
}

type fastRand struct {
	state uint64
}

func newFastRand() fastRand {
	var seed [8]byte
	_, err := rand.Read(seed[:])
	s := binary.LittleEndian.Uint64(seed[:])
	if err != nil || s == 0 {
		s = 0x853c49e6748fea9b
	}
	return fastRand{state: s}
}

func (r *fastRand) next() uint64 {
	r.state ^= r.state >> 12
	r.state ^= r.state << 25
	r.state ^= r.state >> 27
	return r.state * 0x2545F4914F6CDD1D
}

func (r *fastRand) intBetween(min, max int) int {
	if min >= max {
		return min
	}
	return min + int(r.next()%uint64(max-min+1))
}

func (r *fastRand) scope(min, max int) (int, int) {
	start := r.intBetween(min, max)
	lowEnd := (start + max) / 2
	highEnd := max + (max-min)/2
	if lowEnd > highEnd {
		highEnd = lowEnd
	}
	end := r.intBetween(lowEnd, highEnd)
	return start, end
}

var mainCategories = [3][2]int{
	{100, 200}, // Small
	{300, 400}, // Medium
	{500, 900}, // Large
}

func appendScopeStr(buf []byte, start, end int) []byte {
	buf = strconv.AppendInt(buf, int64(start), 10)
	buf = append(buf, '-')
	return strconv.AppendInt(buf, int64(end), 10)
}

func GenerateRandomPaddingScheme() []byte {
	r := newFastRand()

	stopVal := r.intBetween(6, 10)
	dataPackets := stopVal - 2

	lengths := make([]int, dataPackets)
	burstIdx := r.intBetween(0, min(3, dataPackets-1))
	lengths[burstIdx] = r.intBetween(4, 6)

	budget := 16 - lengths[burstIdx]
	for p := 0; p < dataPackets; p++ {
		if p == burstIdx {
			continue
		}
		lengths[p] = 1
		budget--
	}
	for budget > 0 {
		target := r.intBetween(0, dataPackets-1)
		if target != burstIdx && lengths[target] < 3 {
			lengths[target]++
			budget--
		} else {
			break
		}
	}

	buf := make([]byte, 0, 384)

	buf = append(buf, "stop="...)
	buf = strconv.AppendInt(buf, int64(stopVal), 10)
	buf = append(buf, '\n')

	s0, e0 := r.scope(34, 50)
	buf = append(buf, "0="...)
	buf = appendScopeStr(buf, s0, e0)
	buf = append(buf, '\n')

	s1, e1 := r.scope(100, 250)
	buf = append(buf, "1="...)
	buf = appendScopeStr(buf, s1, e1)
	buf = append(buf, '\n')

	intervalGenerated := false

	for p := 0; p < dataPackets; p++ {
		packetNum := p + 2
		buf = strconv.AppendInt(buf, int64(packetNum), 10)
		buf = append(buf, '=')

		unitCount := lengths[p]
		for u := 0; u < unitCount; u++ {
			// 前置 interval 判定 (5% 概率)
			if r.intBetween(1, 100) <= 5 {
				intervalGenerated = true
				si, ei := r.scope(10, 30)
				buf = appendScopeStr(buf, si, ei)
				buf = append(buf, ',')
			}

			// Main 载荷范围
			sizeCategory := r.intBetween(0, 2)
			sm, em := r.scope(mainCategories[sizeCategory][0], mainCategories[sizeCategory][1])
			buf = appendScopeStr(buf, sm, em)

			// 单元间或后置 interval 判定 (5% 概率)
			if r.intBetween(1, 100) <= 5 {
				intervalGenerated = true
				buf = append(buf, ',')
				si, ei := r.scope(10, 30)
				buf = appendScopeStr(buf, si, ei)
			}

			// 单元切分标记
			if u < unitCount-1 {
				buf = append(buf, ",c,"...)
			}
		}

		// 末尾 interval 判定 (5% 概率)
		if r.intBetween(1, 100) <= 5 {
			intervalGenerated = true
			buf = append(buf, ',')
			si, ei := r.scope(10, 30)
			buf = appendScopeStr(buf, si, ei)
		}

		if p < dataPackets-1 {
			buf = append(buf, '\n')
		}
	}

	// 确定性保底：若全流程未随机命中 interval，强制追加到首个数据包末尾，消除递归与重试开销
	if !intervalGenerated {
		si, ei := r.scope(10, 30)
		buf = append(buf, ',')
		buf = appendScopeStr(buf, si, ei)
	}

	return buf
}