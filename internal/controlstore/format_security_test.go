package controlstore

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

func TestDurableEnvelopeFormatsRejectCorruption(t *testing.T) {
	manifestRaw := marshalManifest(manifest{Generation: 1})
	if _, err := unmarshalManifest(manifestRaw); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(raw []byte) []byte { return raw[:len(raw)-1] },
		func(raw []byte) []byte { raw[0] ^= 0xff; return raw },
		func(raw []byte) []byte { raw[8]++; return raw },
		func(raw []byte) []byte { raw[9] = 1; return raw },
		func(raw []byte) []byte { raw[len(raw)-1] ^= 0xff; return raw },
		func(raw []byte) []byte {
			binary.BigEndian.PutUint64(raw[16:24], 0)
			digest := sha256.Sum256(raw[:88])
			copy(raw[88:], digest[:])
			return raw
		},
	} {
		if _, err := unmarshalManifest(mutate(append([]byte(nil), manifestRaw...))); err == nil {
			t.Fatal("corrupt CURRENT manifest was accepted")
		}
	}

	if _, err := marshalSnapshot(snapshotEnvelope{}); err == nil {
		t.Fatal("empty snapshot was accepted")
	}
	snapshotRaw, err := marshalSnapshot(snapshotEnvelope{Generation: 1, Payload: []byte("state")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unmarshalSnapshot(snapshotRaw, 5); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(raw []byte) []byte { return raw[:snapshotHeaderBytes-1] },
		func(raw []byte) []byte { raw[0] ^= 0xff; return raw },
		func(raw []byte) []byte { raw[8]++; return raw },
		func(raw []byte) []byte { raw[9] = 1; return raw },
		func(raw []byte) []byte { binary.BigEndian.PutUint64(raw[64:72], 0); return raw },
		func(raw []byte) []byte { binary.BigEndian.PutUint64(raw[64:72], 6); return raw },
		func(raw []byte) []byte { raw[72] ^= 0xff; return raw },
		func(raw []byte) []byte { binary.BigEndian.PutUint64(raw[16:24], 0); return raw },
	} {
		if _, err := unmarshalSnapshot(mutate(append([]byte(nil), snapshotRaw...)), 5); err == nil {
			t.Fatal("corrupt snapshot envelope was accepted")
		}
	}

	if _, err := marshalWALHeader(walHeader{}); err == nil {
		t.Fatal("zero-generation WAL header was accepted")
	}
	headerRaw, err := marshalWALHeader(walHeader{Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unmarshalWALHeader(headerRaw); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(raw []byte) []byte { return raw[:len(raw)-1] },
		func(raw []byte) []byte { raw[0] ^= 0xff; return raw },
		func(raw []byte) []byte { raw[8]++; return raw },
		func(raw []byte) []byte { raw[9] = 1; return raw },
		func(raw []byte) []byte { raw[len(raw)-1] ^= 0xff; return raw },
		func(raw []byte) []byte {
			binary.BigEndian.PutUint64(raw[16:24], 0)
			digest := sha256.Sum256(raw[:64])
			copy(raw[64:], digest[:])
			return raw
		},
	} {
		if _, err := unmarshalWALHeader(mutate(append([]byte(nil), headerRaw...))); err == nil {
			t.Fatal("corrupt WAL header was accepted")
		}
	}
}

func TestWALFrameFormatRejectsCorruptionAndOversize(t *testing.T) {
	var previous [sha256.Size]byte
	if _, _, err := marshalWALRecord(0, previous, []byte("payload"), 1024); err == nil {
		t.Fatal("zero-sequence WAL record was accepted")
	}
	if _, _, err := marshalWALRecord(1, previous, nil, 1024); err == nil {
		t.Fatal("empty WAL record was accepted")
	}
	if _, _, err := marshalWALRecord(1, previous, []byte("payload"), walFrameFixedBytes); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("oversized WAL record error = %v", err)
	}
	raw, _, err := marshalWALRecord(1, previous, []byte("payload"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	body := raw[4:]
	if _, err := unmarshalWALRecord(body, 1024); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(raw []byte) []byte { return raw[:walFrameFixedBytes-1] },
		func(raw []byte) []byte { raw[0]++; return raw },
		func(raw []byte) []byte { raw[1] = 1; return raw },
		func(raw []byte) []byte { binary.BigEndian.PutUint32(raw[48:52], 0); return raw },
		func(raw []byte) []byte { binary.BigEndian.PutUint32(raw[48:52], 8); return raw },
		func(raw []byte) []byte { raw[52] ^= 0xff; return raw },
		func(raw []byte) []byte { raw[len(raw)-1] ^= 0xff; return raw },
		func(raw []byte) []byte {
			binary.BigEndian.PutUint64(raw[8:16], 0)
			payloadLength := int(binary.BigEndian.Uint32(raw[48:52]))
			digest := hashRecord(raw[:84+payloadLength])
			copy(raw[84+payloadLength:], digest[:])
			return raw
		},
	} {
		if _, err := unmarshalWALRecord(mutate(append([]byte(nil), body...)), 1024); err == nil {
			t.Fatal("corrupt WAL frame was accepted")
		}
	}
	if _, err := unmarshalWALRecord(body, len(body)-1); err == nil {
		t.Fatal("WAL frame above its configured limit was accepted")
	}
	if !allZero([]byte{0, 0, 0}) || allZero([]byte{0, 1, 0}) {
		t.Fatal("reserved-byte validation is inconsistent")
	}
}
