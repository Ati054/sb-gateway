// Package subscriptioncatalog stores private node records in immutable,
// content-addressed disk generations. It does not interpret node credentials or
// assign subscription-scoped IDs. A caller owns each Reader and must close it.
package subscriptioncatalog

import (
	"encoding/hex"
	"encoding/json"
	"errors"
)

const SchemaVersion = 1

// Key is an opaque SHA256 identity, encoded as lowercase hex in JSON.
// A zero identity is absent and is not added to an identity index.
type Key [32]byte

func (key Key) MarshalJSON() ([]byte, error) {
	result := make([]byte, 66)
	result[0], result[65] = '"', '"'
	hex.Encode(result[1:65], key[:])
	return result, nil
}

func (key *Key) UnmarshalJSON(data []byte) error {
	if len(data) != 66 || data[0] != '"' || data[65] != '"' {
		return ErrInvalidRecord
	}
	parsed, err := ParseKey(string(data[1:65]))
	if err != nil {
		return err
	}
	*key = parsed
	return nil
}

func ParseKey(value string) (Key, error) {
	var result Key
	if !validDigest(value) {
		return result, ErrInvalidRecord
	}
	_, _ = hex.Decode(result[:], []byte(value))
	return result, nil
}

type Kind uint8

const (
	Stable Kind = iota + 1
	Endpoint
	Logical
)

// ID is caller-scoped. Node may retain a provider's base ID. The three JSON
// fields are opaque values. Metadata must contain only caller-approved fields.
type Record struct {
	ID       string          `json:"id"`
	Stable   Key             `json:"stable"`
	Endpoint Key             `json:"endpoint"`
	Logical  Key             `json:"logical"`
	Metadata json.RawMessage `json:"metadata"`
	Node     json.RawMessage `json:"node"`
	Secrets  json.RawMessage `json:"secrets"`
}

type MetadataRecord struct {
	ID   string          `json:"id"`
	Data json.RawMessage `json:"data"`
}

type FileDigest struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Ref contains no filesystem paths. Indexes are ID, Stable, Endpoint and Logical.
// Generation hashes every file digest, including the secret-bearing records.
type Ref struct {
	Schema     int           `json:"schema"`
	Generation string        `json:"generation"`
	Count      uint64        `json:"count"`
	Records    FileDigest    `json:"records"`
	Metadata   FileDigest    `json:"metadata"`
	Indexes    [4]FileDigest `json:"indexes"`
}

// Limits bound bytes and working memory, never node count. Disk accounting is
// per build and includes temporary files, excluding retained generations.
// Zero fields use defaults. Explicit positive caller quotas are independent.
type Limits struct {
	MaxRecordBytes    int64
	MaxCanonicalBytes int64
	MaxDiskBytes      int64
	SortChunkBytes    int64
	MergeFanIn        int
}

func DefaultLimits() Limits {
	return Limits{MaxRecordBytes: 8 << 20, MaxCanonicalBytes: 512 << 20,
		MaxDiskBytes: 1 << 30, SortChunkBytes: 1 << 20, MergeFanIn: 16}
}

var (
	ErrInvalidRecord    = errors.New("catalog: invalid record")
	ErrInvalidRef       = errors.New("catalog: invalid reference")
	ErrInvalidLimits    = errors.New("catalog: invalid limits")
	ErrDuplicateID      = errors.New("catalog: duplicate ID")
	ErrNotFound         = errors.New("catalog: not found")
	ErrAmbiguous        = errors.New("catalog: ambiguous identity")
	ErrLimit            = errors.New("catalog: byte limit exceeded")
	ErrIntegrity        = errors.New("catalog: integrity check failed")
	ErrUnsafePath       = errors.New("catalog: unsafe filesystem entry")
	ErrIO               = errors.New("catalog: storage operation failed")
	ErrNoSpace          = errors.New("catalog: storage full")
	ErrClosed           = errors.New("catalog: closed")
	ErrBusy             = errors.New("catalog: generation is leased")
	ErrLeaseUnsupported = errors.New("catalog: filesystem leases unsupported")
)

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}
