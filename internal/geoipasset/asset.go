// Package geoipasset publishes content-addressed Xray country databases.
package geoipasset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

const MaxPackBytes = 4 << 20

var (
	packPattern = regexp.MustCompile(`^geoip-([a-z]{2})$`)
	namePattern = regexp.MustCompile(`^sb-geoip-([a-z]{2})-([a-f0-9]{64})\.dat$`)
	publication sync.Mutex
)

// Encode preserves every canonical IPv4/IPv6 prefix in the portable JSON pack.
func Encode(id string, body []byte) ([]byte, error) {
	match := packPattern.FindStringSubmatch(id)
	if match == nil || len(body) > MaxPackBytes {
		return nil, errors.New("invalid GeoIP pack identity or size")
	}
	var document struct {
		Version int `json:"version"`
		Rules   []struct {
			IP []string `json:"ip_cidr"`
		} `json:"rules"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode GeoIP pack: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF || len(document.Rules) != 1 || len(document.Rules[0].IP) == 0 || len(document.Rules[0].IP) > 250_000 || (document.Version != 0 && document.Version != 3) {
		return nil, errors.New("GeoIP CIDR document is invalid")
	}
	country := protowire.AppendTag(nil, 1, protowire.BytesType)
	country = protowire.AppendString(country, strings.ToUpper(match[1]))
	for _, value := range document.Rules[0].IP {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Masked().String() != value {
			return nil, errors.New("GeoIP CIDR is invalid")
		}
		cidr := protowire.AppendTag(nil, 1, protowire.BytesType)
		cidr = protowire.AppendBytes(cidr, prefix.Addr().AsSlice())
		cidr = protowire.AppendTag(cidr, 2, protowire.VarintType)
		cidr = protowire.AppendVarint(cidr, uint64(prefix.Bits()))
		country = protowire.AppendTag(country, 2, protowire.BytesType)
		country = protowire.AppendBytes(country, cidr)
	}
	return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), country), nil
}

func Ensure(root, id string) (string, error) {
	if !packPattern.MatchString(id) {
		return "", errors.New("invalid GeoIP pack identity")
	}
	body, err := readRegular(filepath.Join(root, id+".json"), MaxPackBytes)
	if err != nil {
		return "", err
	}
	return Publish(root, id, body)
}

// Publish never overwrites a database: Xray's shared cache keys include its name.
// The asset reaches durable storage before its JSON pack/config can be published.
func Publish(root, id string, body []byte) (string, error) {
	data, err := Encode(id, body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	code := strings.TrimPrefix(id, "geoip-")
	name := "sb-geoip-" + code + "-" + hex.EncodeToString(sum[:]) + ".dat"
	publication.Lock()
	defer publication.Unlock()
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(root, name)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		file, err := os.CreateTemp(root, ".geoip-*")
		if err != nil {
			return "", err
		}
		defer os.Remove(file.Name())
		if err = file.Chmod(0600); err == nil {
			_, err = file.Write(data)
		}
		if err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return "", err
		}
		if err := os.Link(file.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	actual, err := readRegular(path, int64(len(data)))
	if err != nil || !bytes.Equal(actual, data) {
		return "", errors.New("immutable GeoIP asset is damaged or unsafe")
	}
	// An unpublished Check/Apply candidate must survive concurrent cleanup.
	now := time.Now()
	if err := os.Chtimes(path, now, now); err != nil {
		return "", err
	}
	if err := syncDirectory(root); err != nil {
		return "", err
	}
	return "ext:" + name + ":" + code, nil
}

func ReferenceName(reference string) (string, bool) {
	parts := strings.Split(reference, ":")
	if len(parts) != 3 || parts[0] != "ext" {
		return "", false
	}
	match := namePattern.FindStringSubmatch(parts[1])
	return parts[1], match != nil && match[1] == parts[2]
}

func IsManagedName(name string) bool { return namePattern.MatchString(name) }

// Verify checks a persisted reference without loading its database into Go RAM.
func Verify(root, reference string) error {
	name, valid := ReferenceName(reference)
	if !valid {
		return errors.New("invalid GeoIP asset reference")
	}
	path := filepath.Join(root, name)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return errors.New("unsafe GeoIP asset")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("GeoIP asset changed during open")
	}
	digest := sha256.New()
	n, err := io.Copy(digest, io.LimitReader(file, (8<<20)+1))
	if err != nil {
		return err
	}
	match := namePattern.FindStringSubmatch(name)
	if n > 8<<20 || hex.EncodeToString(digest.Sum(nil)) != match[2] {
		return errors.New("GeoIP asset checksum mismatch")
	}
	return nil
}

func readRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("GeoIP input is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("GeoIP input changed during open")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, errors.New("GeoIP input exceeds the limit")
	}
	return body, nil
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
