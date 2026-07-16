package controlstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	diskFormatVersion   = 1
	manifestBytes       = 120
	snapshotHeaderBytes = 104
	walHeaderBytes      = 96
	walFramePrefixBytes = 52
	walFrameFixedBytes  = 116
)

var (
	manifestMagic = [8]byte{'S', 'T', 'C', 'U', 'R', 'R', '0', '1'}
	snapshotMagic = [8]byte{'S', 'T', 'C', 'S', 'N', 'A', '0', '1'}
	walMagic      = [8]byte{'S', 'T', 'C', 'W', 'A', 'L', '0', '1'}
	recordDomain  = []byte("steward-control-wal-record-v1\x00")
)

type manifest struct {
	Generation    uint64
	SnapshotHash  [sha256.Size]byte
	WALHeaderHash [sha256.Size]byte
}

type snapshotEnvelope struct {
	Generation uint64
	Sequence   uint64
	LastHash   [sha256.Size]byte
	Payload    []byte
}

type walHeader struct {
	Generation uint64
	Sequence   uint64
	LastHash   [sha256.Size]byte
}

type walRecord struct {
	Sequence uint64
	Previous [sha256.Size]byte
	Payload  []byte
	Hash     [sha256.Size]byte
}

func marshalManifest(value manifest) []byte {
	raw := make([]byte, manifestBytes)
	copy(raw[:8], manifestMagic[:])
	raw[8] = diskFormatVersion
	binary.BigEndian.PutUint64(raw[16:24], value.Generation)
	copy(raw[24:56], value.SnapshotHash[:])
	copy(raw[56:88], value.WALHeaderHash[:])
	digest := sha256.Sum256(raw[:88])
	copy(raw[88:120], digest[:])
	return raw
}

func unmarshalManifest(raw []byte) (manifest, error) {
	if len(raw) != manifestBytes || !bytes.Equal(raw[:8], manifestMagic[:]) || raw[8] != diskFormatVersion ||
		!allZero(raw[9:16]) {
		return manifest{}, errors.New("control CURRENT manifest header is invalid")
	}
	expected := sha256.Sum256(raw[:88])
	if !bytes.Equal(expected[:], raw[88:120]) {
		return manifest{}, errors.New("control CURRENT manifest checksum is invalid")
	}
	value := manifest{Generation: binary.BigEndian.Uint64(raw[16:24])}
	copy(value.SnapshotHash[:], raw[24:56])
	copy(value.WALHeaderHash[:], raw[56:88])
	if value.Generation == 0 {
		return manifest{}, errors.New("control CURRENT manifest generation is zero")
	}
	return value, nil
}

func marshalSnapshot(value snapshotEnvelope) ([]byte, error) {
	if value.Generation == 0 || len(value.Payload) == 0 {
		return nil, errors.New("control snapshot requires a generation and payload")
	}
	raw := make([]byte, snapshotHeaderBytes+len(value.Payload))
	copy(raw[:8], snapshotMagic[:])
	raw[8] = diskFormatVersion
	binary.BigEndian.PutUint64(raw[16:24], value.Generation)
	binary.BigEndian.PutUint64(raw[24:32], value.Sequence)
	copy(raw[32:64], value.LastHash[:])
	binary.BigEndian.PutUint64(raw[64:72], uint64(len(value.Payload)))
	digest := sha256.Sum256(value.Payload)
	copy(raw[72:104], digest[:])
	copy(raw[104:], value.Payload)
	return raw, nil
}

func unmarshalSnapshot(raw []byte, payloadLimit int) (snapshotEnvelope, error) {
	if len(raw) < snapshotHeaderBytes || !bytes.Equal(raw[:8], snapshotMagic[:]) || raw[8] != diskFormatVersion ||
		!allZero(raw[9:16]) {
		return snapshotEnvelope{}, errors.New("control snapshot header is invalid")
	}
	length := binary.BigEndian.Uint64(raw[64:72])
	if length == 0 || length > uint64(payloadLimit) || length != uint64(len(raw)-snapshotHeaderBytes) {
		return snapshotEnvelope{}, errors.New("control snapshot payload length is invalid")
	}
	expected := sha256.Sum256(raw[snapshotHeaderBytes:])
	if !bytes.Equal(expected[:], raw[72:104]) {
		return snapshotEnvelope{}, errors.New("control snapshot payload checksum is invalid")
	}
	value := snapshotEnvelope{
		Generation: binary.BigEndian.Uint64(raw[16:24]), Sequence: binary.BigEndian.Uint64(raw[24:32]),
		Payload: append([]byte(nil), raw[snapshotHeaderBytes:]...),
	}
	copy(value.LastHash[:], raw[32:64])
	if value.Generation == 0 {
		return snapshotEnvelope{}, errors.New("control snapshot generation is zero")
	}
	return value, nil
}

func marshalWALHeader(value walHeader) ([]byte, error) {
	if value.Generation == 0 {
		return nil, errors.New("control WAL generation is zero")
	}
	raw := make([]byte, walHeaderBytes)
	copy(raw[:8], walMagic[:])
	raw[8] = diskFormatVersion
	binary.BigEndian.PutUint64(raw[16:24], value.Generation)
	binary.BigEndian.PutUint64(raw[24:32], value.Sequence)
	copy(raw[32:64], value.LastHash[:])
	digest := sha256.Sum256(raw[:64])
	copy(raw[64:96], digest[:])
	return raw, nil
}

func unmarshalWALHeader(raw []byte) (walHeader, error) {
	if len(raw) != walHeaderBytes || !bytes.Equal(raw[:8], walMagic[:]) || raw[8] != diskFormatVersion ||
		!allZero(raw[9:16]) {
		return walHeader{}, errors.New("control WAL header is invalid")
	}
	expected := sha256.Sum256(raw[:64])
	if !bytes.Equal(expected[:], raw[64:96]) {
		return walHeader{}, errors.New("control WAL header checksum is invalid")
	}
	value := walHeader{Generation: binary.BigEndian.Uint64(raw[16:24]), Sequence: binary.BigEndian.Uint64(raw[24:32])}
	copy(value.LastHash[:], raw[32:64])
	if value.Generation == 0 {
		return walHeader{}, errors.New("control WAL generation is zero")
	}
	return value, nil
}

func marshalWALRecord(sequence uint64, previous [sha256.Size]byte, payload []byte, limit int) ([]byte, walRecord, error) {
	if sequence == 0 || len(payload) == 0 {
		return nil, walRecord{}, errors.New("control WAL record requires sequence and payload")
	}
	bodyLength := walFrameFixedBytes + len(payload)
	if bodyLength > limit {
		return nil, walRecord{}, ErrCapacityExceeded
	}
	body := make([]byte, bodyLength)
	body[0] = diskFormatVersion
	binary.BigEndian.PutUint64(body[8:16], sequence)
	copy(body[16:48], previous[:])
	binary.BigEndian.PutUint32(body[48:52], uint32(len(payload)))
	payloadHash := sha256.Sum256(payload)
	copy(body[52:84], payloadHash[:])
	copy(body[84:84+len(payload)], payload)
	recordHash := hashRecord(body[:84+len(payload)])
	copy(body[84+len(payload):], recordHash[:])
	raw := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(raw[:4], uint32(len(body)))
	copy(raw[4:], body)
	return raw, walRecord{Sequence: sequence, Previous: previous, Payload: append([]byte(nil), payload...), Hash: recordHash}, nil
}

func unmarshalWALRecord(body []byte, limit int) (walRecord, error) {
	if len(body) < walFrameFixedBytes || len(body) > limit || body[0] != diskFormatVersion || !allZero(body[1:8]) {
		return walRecord{}, errors.New("control WAL frame header is invalid")
	}
	payloadLength := int(binary.BigEndian.Uint32(body[48:52]))
	if payloadLength == 0 || payloadLength != len(body)-walFrameFixedBytes {
		return walRecord{}, errors.New("control WAL frame payload length is invalid")
	}
	payload := body[84 : 84+payloadLength]
	expectedPayload := sha256.Sum256(payload)
	if !bytes.Equal(expectedPayload[:], body[52:84]) {
		return walRecord{}, errors.New("control WAL frame payload checksum is invalid")
	}
	expectedRecord := hashRecord(body[:84+payloadLength])
	if !bytes.Equal(expectedRecord[:], body[84+payloadLength:]) {
		return walRecord{}, errors.New("control WAL frame record hash is invalid")
	}
	value := walRecord{Sequence: binary.BigEndian.Uint64(body[8:16]), Payload: append([]byte(nil), payload...), Hash: expectedRecord}
	copy(value.Previous[:], body[16:48])
	if value.Sequence == 0 {
		return walRecord{}, errors.New("control WAL frame sequence is zero")
	}
	return value, nil
}

// validateIncompleteWALFramePrefix distinguishes a plausible partial append
// from corruption of the unauthenticated outer frame length. Once the fixed
// body prefix has reached disk, its independently encoded payload length and
// sequence must agree with the outer length before recovery may discard it.
func validateIncompleteWALFramePrefix(prefix []byte, declaredLength int64) error {
	if len(prefix) < walFramePrefixBytes {
		return nil
	}
	if prefix[0] != diskFormatVersion || !allZero(prefix[1:8]) || binary.BigEndian.Uint64(prefix[8:16]) == 0 {
		return errors.New("control WAL incomplete frame prefix is invalid")
	}
	payloadLength := uint64(binary.BigEndian.Uint32(prefix[48:52]))
	if payloadLength == 0 || uint64(walFrameFixedBytes)+payloadLength != uint64(declaredLength) {
		return errors.New("control WAL outer frame length disagrees with its retained body prefix")
	}
	return nil
}

func hashRecord(raw []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write(recordDomain)
	_, _ = hash.Write(raw)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func hashBytes(raw []byte) [sha256.Size]byte { return sha256.Sum256(raw) }

func allZero(raw []byte) bool {
	for _, value := range raw {
		if value != 0 {
			return false
		}
	}
	return true
}

func generationName(kind string, generation uint64) string {
	return fmt.Sprintf("%s.%020d", kind, generation)
}
