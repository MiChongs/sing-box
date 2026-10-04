package cachefile

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/hash"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/varbin"
)

// The branch envelope has its own version namespace. Its payload is the
// unchanged upstream SavedBinary wire format, including that format's version.
const (
	branchBinaryMagic        = "\x00reF1nd:SavedBinary\x00"
	branchBinaryVersion byte = 1
)

func marshalBranchBinary(value *adapter.SavedBinary) ([]byte, error) {
	payload, err := value.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.WriteString(branchBinaryMagic)
	buffer.WriteByte(branchBinaryVersion)
	_, err = varbin.WriteUvarint(&buffer, uint64(len(payload)))
	if err != nil {
		return nil, err
	}
	buffer.Write(payload)
	buffer.Write(value.Hash.Bytes())
	return buffer.Bytes(), nil
}

func unmarshalBranchBinary(data []byte) (*adapter.SavedBinary, error) {
	if !bytes.HasPrefix(data, []byte(branchBinaryMagic)) {
		return nil, E.New("invalid branch cache magic")
	}
	reader := bytes.NewReader(data[len(branchBinaryMagic):])
	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != branchBinaryVersion {
		return nil, E.New("unsupported branch cache version: ", version)
	}
	length, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, err
	}
	value := new(adapter.SavedBinary)
	if reader.Len() < value.Hash.Len() || length != uint64(reader.Len()-value.Hash.Len()) {
		return nil, E.New("invalid branch cache payload length")
	}
	payload := make([]byte, int(length))
	_, err = io.ReadFull(reader, payload)
	if err != nil {
		return nil, err
	}
	// Reject unknown upstream versions independently of the branch version.
	if len(payload) == 0 || (payload[0] != 1 && payload[0] != 2) {
		return nil, E.New("unsupported SavedBinary version")
	}
	err = value.UnmarshalBinary(payload)
	if err != nil {
		return nil, err
	}
	extension := make([]byte, value.Hash.Len())
	_, err = io.ReadFull(reader, extension)
	if err != nil {
		return nil, err
	}
	err = value.Hash.UnmarshalBinary(extension)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (c *CacheFile) loadBranchBinary(kind []byte, tag string, legacy bool) *adapter.SavedBinary {
	var result *adapter.SavedBinary
	err := c.view(func(tx *bbolt.Tx) error {
		if namespace := c.bucket(tx, bucketBranch); namespace != nil {
			if bucket := namespace.Bucket(kind); bucket != nil {
				if data := bucket.Get([]byte(tag)); data != nil {
					var err error
					result, err = unmarshalBranchBinary(data)
					// A corrupt or unsupported new record must not resurrect an old record.
					return err
				}
			}
		}
		if !legacy {
			return os.ErrNotExist
		}
		bucket := c.bucket(tx, kind)
		if bucket == nil {
			return os.ErrNotExist
		}
		data := bucket.Get([]byte(tag))
		if len(data) == 0 || (data[0] != 1 && data[0] != 2) {
			return os.ErrInvalid
		}
		// Earlier branch releases wrote this bucket in their own layout, with
		// the static file hash in front of the content.
		if legacyBranch, err := unmarshalLegacyBranchBinary(data); err == nil {
			result = legacyBranch
			return nil
		}
		result = new(adapter.SavedBinary)
		if err := result.UnmarshalBinary(data); err != nil {
			return err
		}
		// Legacy records contain the bytes themselves. This also lets the later
		// static-file rule-set loader compare an existing file with its old cache.
		if len(result.Content) > 0 {
			result.Hash = hash.MakeHash(result.Content)
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return result
}

func (c *CacheFile) saveBranchBinary(kind []byte, tag string, value *adapter.SavedBinary) error {
	data, err := marshalBranchBinary(value)
	if err != nil {
		return err
	}
	return c.batch(func(tx *bbolt.Tx) error {
		namespace, err := c.createBucket(tx, bucketBranch)
		if err != nil {
			return err
		}
		bucket, err := namespace.CreateBucketIfNotExists(kind)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(tag), data)
	})
}

// unmarshalLegacyBranchBinary decodes records written by branch releases before
// the branch envelope: version, hash, content, last updated, etag and (since
// version 2) URL hash. It only accepts a record it consumes exactly, so upstream
// records in the same bucket fall through to the upstream decoder.
func unmarshalLegacyBranchBinary(data []byte) (*adapter.SavedBinary, error) {
	reader := bytes.NewReader(data)
	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != 1 && version != 2 {
		return nil, E.New("unsupported legacy branch cache version: ", version)
	}
	value := new(adapter.SavedBinary)
	hashBytes, err := readLegacyBytes(reader)
	if err != nil {
		return nil, err
	}
	if len(hashBytes) != value.Hash.Len() {
		return nil, E.New("invalid legacy branch cache hash length: ", len(hashBytes))
	}
	err = value.Hash.UnmarshalBinary(hashBytes)
	if err != nil {
		return nil, err
	}
	value.Content, err = readLegacyBytes(reader)
	if err != nil {
		return nil, err
	}
	var lastUpdated int64
	err = binary.Read(reader, binary.BigEndian, &lastUpdated)
	if err != nil {
		return nil, err
	}
	value.LastUpdated = time.Unix(lastUpdated, 0)
	etag, err := readLegacyBytes(reader)
	if err != nil {
		return nil, err
	}
	value.LastEtag = string(etag)
	if version >= 2 {
		value.URLHash, err = readLegacyBytes(reader)
		if err != nil {
			return nil, err
		}
	}
	if reader.Len() != 0 {
		return nil, E.New("trailing data in legacy branch cache record")
	}
	if len(value.Content) > 0 && !value.Hash.Equal(hash.MakeHash(value.Content)) {
		return nil, E.New("legacy branch cache hash does not match its content")
	}
	return value, nil
}

func readLegacyBytes(reader *bytes.Reader) ([]byte, error) {
	length, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, err
	}
	if length > uint64(reader.Len()) {
		return nil, E.New("invalid legacy branch cache field length: ", length)
	}
	if length == 0 {
		return nil, nil
	}
	value := make([]byte, int(length))
	_, err = io.ReadFull(reader, value)
	if err != nil {
		return nil, err
	}
	return value, nil
}
