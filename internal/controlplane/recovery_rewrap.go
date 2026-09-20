package controlplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

const (
	recoveryMagic             = "SBGWREC2"
	recoveryFormatVersion     = 2
	recoveryArchiveCipher     = "AES-256-GCM-CHUNKED"
	recoveryWrapperSlotBytes  = 512
	recoveryWrapperRecordHead = 48
	recoveryWrapperMarker     = "WRP2"
	recoveryMaxHeaderBytes    = 16 << 10
	recoveryMaxArchiveBytes   = 66 << 20
)

var recoveryArchiveName = regexp.MustCompile(`^SB-GATEWAY-state-\d{8}T\d{6}Z-[0-9a-f]{12}\.sbgw$`)

type recoveryWrapperSlot struct {
	index      int
	generation uint64
	wrapper    recoveryKeyWrap
}

type recoveryArchivePrefix struct {
	active        recoveryWrapperSlot
	header        map[string]any
	payloadOffset int64
}

type recoveryRewrapPlan struct {
	name   string
	path   string
	offset int64
	record []byte
}

func (server *Server) rewrapRecoveryProtection(currentPassword, newPassword string) ([]string, error) {
	server.recoveryMu.Lock()
	defer server.recoveryMu.Unlock()

	if err := validateRecoveryPassword(newPassword); err != nil {
		return nil, err
	}
	encodedMaster, err := server.secrets.read(recoveryMasterKeyRef, true)
	if err != nil {
		return nil, err
	}
	master, err := decodeRecoveryMasterKey(encodedMaster)
	if err != nil {
		return nil, err
	}
	encodedOldWrapper, err := server.secrets.read(recoveryKeyWrapRef, true)
	if err != nil {
		return nil, err
	}
	oldWrapper, err := decodeRecoveryKeyWrap(encodedOldWrapper)
	if err != nil {
		return nil, err
	}
	unwrapped, err := unwrapRecoveryMasterKey(oldWrapper, currentPassword)
	if err != nil || recoveryKeyID(unwrapped) != recoveryKeyID(master) {
		return nil, errors.New("current administrator password does not unlock recovery protection")
	}
	newWrapper, err := wrapRecoveryMasterKey(master, newPassword)
	if err != nil {
		return nil, err
	}

	archiveRoot := filepath.Join(server.opts.DataDir, "recovery-backups")
	names, err := retainedRecoveryArchiveNames(archiveRoot)
	if err != nil {
		return nil, err
	}
	plans := make([]recoveryRewrapPlan, 0, len(names))
	for _, name := range names {
		path := filepath.Join(archiveRoot, name)
		prefix, err := readRecoveryArchivePrefix(path)
		if err != nil {
			return nil, fmt.Errorf("retained recovery archive %s is invalid: %w", name, err)
		}
		if prefix.active.wrapper.KeyID != recoveryKeyID(master) {
			return nil, fmt.Errorf("retained recovery archive %s uses another master key", name)
		}
		if prefix.active.generation == math.MaxUint64 {
			return nil, fmt.Errorf("retained recovery archive %s exhausted wrapper generations", name)
		}
		inactive := 1 - prefix.active.index
		record, err := encodeRecoveryWrapperSlot(prefix.active.generation+1, newWrapper)
		if err != nil {
			return nil, err
		}
		plans = append(plans, recoveryRewrapPlan{
			name:   name,
			path:   path,
			offset: int64(len(recoveryMagic) + inactive*recoveryWrapperSlotBytes),
			record: record,
		})
	}

	for _, plan := range plans {
		if err := writeRecoveryWrapperSlot(plan.path, plan.offset, plan.record); err != nil {
			return nil, fmt.Errorf("update retained recovery archive %s: %w", plan.name, err)
		}
	}
	newWrapperBody, err := encodeRecoveryKeyWrap(newWrapper)
	if err != nil {
		return nil, err
	}
	if err := server.secrets.write(recoveryBackupPwdRef, newPassword, true); err != nil {
		return nil, err
	}
	if err := server.secrets.write(recoveryKeyWrapRef, string(newWrapperBody), true); err != nil {
		_ = server.secrets.write(recoveryBackupPwdRef, currentPassword, true)
		return nil, err
	}
	return names, nil
}

func retainedRecoveryArchiveNames(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list recovery archives: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && recoveryArchiveName.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

func readRecoveryArchivePrefix(path string) (recoveryArchivePrefix, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return recoveryArchivePrefix{}, errors.New("recovery archive must be a regular file")
	}
	minimum := int64(len(recoveryMagic) + 2*recoveryWrapperSlotBytes + 4 + 1 + 16)
	if info.Size() < minimum || info.Size() > recoveryMaxArchiveBytes {
		return recoveryArchivePrefix{}, errors.New("recovery archive size is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return recoveryArchivePrefix{}, err
	}
	defer file.Close()
	fixed := make([]byte, len(recoveryMagic)+2*recoveryWrapperSlotBytes+4)
	if _, err := io.ReadFull(file, fixed); err != nil {
		return recoveryArchivePrefix{}, errors.New("recovery archive prefix is truncated")
	}
	if string(fixed[:len(recoveryMagic)]) != recoveryMagic {
		return recoveryArchivePrefix{}, errors.New("recovery archive format is not supported")
	}
	slots := make([]recoveryWrapperSlot, 0, 2)
	for index := 0; index < 2; index++ {
		start := len(recoveryMagic) + index*recoveryWrapperSlotBytes
		if slot, ok := decodeRecoveryWrapperSlot(index, fixed[start:start+recoveryWrapperSlotBytes]); ok {
			slots = append(slots, slot)
		}
	}
	if len(slots) == 0 {
		return recoveryArchivePrefix{}, errors.New("recovery archive has no valid key wrapper")
	}
	active := slots[0]
	for _, slot := range slots[1:] {
		if slot.generation > active.generation {
			active = slot
		}
	}
	headerSizeOffset := len(recoveryMagic) + 2*recoveryWrapperSlotBytes
	headerSize := int(binary.BigEndian.Uint32(fixed[headerSizeOffset:]))
	if headerSize < 1 || headerSize > recoveryMaxHeaderBytes {
		return recoveryArchivePrefix{}, errors.New("recovery archive header size is invalid")
	}
	headerBody := make([]byte, headerSize)
	if _, err := io.ReadFull(file, headerBody); err != nil {
		return recoveryArchivePrefix{}, errors.New("recovery archive header is truncated")
	}
	header := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(headerBody))
	decoder.UseNumber()
	if err := decoder.Decode(&header); err != nil {
		return recoveryArchivePrefix{}, errors.New("recovery archive header is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return recoveryArchivePrefix{}, errors.New("recovery archive header is invalid")
	}
	version, ok := jsonInt(header["format_version"])
	if !ok || version != recoveryFormatVersion || header["cipher"] != recoveryArchiveCipher {
		return recoveryArchivePrefix{}, errors.New("recovery archive format is not supported")
	}
	return recoveryArchivePrefix{
		active:        active,
		header:        header,
		payloadOffset: int64(len(fixed) + headerSize),
	}, nil
}

func encodeRecoveryArchivePrefix(header map[string]any, wrapper recoveryKeyWrap) ([]byte, error) {
	headerBody, err := canonicalJSON(header)
	if err != nil {
		return nil, err
	}
	if len(headerBody) < 1 || len(headerBody) > recoveryMaxHeaderBytes {
		return nil, errors.New("recovery archive header size is invalid")
	}
	version, ok := jsonInt(header["format_version"])
	if !ok || version != recoveryFormatVersion || header["cipher"] != recoveryArchiveCipher {
		return nil, errors.New("recovery archive format is not supported")
	}
	slot, err := encodeRecoveryWrapperSlot(1, wrapper)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, len(recoveryMagic)+2*recoveryWrapperSlotBytes+4+len(headerBody))
	copy(prefix, recoveryMagic)
	copy(prefix[len(recoveryMagic):], slot)
	headerSizeOffset := len(recoveryMagic) + 2*recoveryWrapperSlotBytes
	binary.BigEndian.PutUint32(prefix[headerSizeOffset:], uint32(len(headerBody)))
	copy(prefix[headerSizeOffset+4:], headerBody)
	return prefix, nil
}

func encodeRecoveryWrapperSlot(generation uint64, wrapper recoveryKeyWrap) ([]byte, error) {
	if generation == 0 {
		return nil, errors.New("recovery wrapper generation is invalid")
	}
	payload, err := encodeRecoveryKeyWrap(wrapper)
	if err != nil {
		return nil, err
	}
	if len(payload) > recoveryWrapperSlotBytes-recoveryWrapperRecordHead {
		return nil, errors.New("recovery key wrapper exceeds its fixed slot")
	}
	record := make([]byte, recoveryWrapperSlotBytes)
	copy(record[:4], recoveryWrapperMarker)
	binary.BigEndian.PutUint64(record[4:12], generation)
	binary.BigEndian.PutUint16(record[12:14], uint16(len(payload)))
	copy(record[recoveryWrapperRecordHead:], payload)
	digest := recoveryWrapperSlotDigest(record[:16], payload)
	copy(record[16:recoveryWrapperRecordHead], digest[:])
	return record, nil
}

func decodeRecoveryWrapperSlot(index int, record []byte) (recoveryWrapperSlot, bool) {
	if len(record) != recoveryWrapperSlotBytes || string(record[:4]) != recoveryWrapperMarker {
		return recoveryWrapperSlot{}, false
	}
	generation := binary.BigEndian.Uint64(record[4:12])
	payloadSize := int(binary.BigEndian.Uint16(record[12:14]))
	if generation == 0 || payloadSize < 1 || payloadSize > recoveryWrapperSlotBytes-recoveryWrapperRecordHead {
		return recoveryWrapperSlot{}, false
	}
	payload := record[recoveryWrapperRecordHead : recoveryWrapperRecordHead+payloadSize]
	digest := recoveryWrapperSlotDigest(record[:16], payload)
	if !bytes.Equal(record[16:recoveryWrapperRecordHead], digest[:]) {
		return recoveryWrapperSlot{}, false
	}
	wrapper, err := decodeRecoveryKeyWrap(string(payload))
	if err != nil {
		return recoveryWrapperSlot{}, false
	}
	return recoveryWrapperSlot{index: index, generation: generation, wrapper: wrapper}, true
}

func recoveryWrapperSlotDigest(metadata, payload []byte) [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte("SBGWREC2:key-slot:"))
	_, _ = digest.Write(metadata)
	_, _ = digest.Write(payload)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func writeRecoveryWrapperSlot(path string, offset int64, record []byte) error {
	if len(record) != recoveryWrapperSlotBytes {
		return errors.New("recovery wrapper slot has an invalid size")
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	written, err := file.WriteAt(record, offset)
	if err != nil {
		return err
	}
	if written != len(record) {
		return io.ErrShortWrite
	}
	return file.Sync()
}

func recoveryWrapperObject(wrapper recoveryKeyWrap) map[string]any {
	return map[string]any{
		"cipher":      wrapper.Cipher,
		"kdf":         wrapper.KDF,
		"key_id":      wrapper.KeyID,
		"nonce":       wrapper.Nonce,
		"salt":        wrapper.Salt,
		"wrapped_key": wrapper.WrappedKey,
	}
}
