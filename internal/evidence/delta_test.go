package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestExportAndVerifyDeltaFromExactCoordinate(t *testing.T) {
	log, path, public := newLog(t)
	first, err := log.Append(event(AdmissionAllow))
	if err != nil {
		t.Fatal(err)
	}
	secondEvent := event(InferenceAuthorize)
	secondEvent.TenantID = "tenant-b"
	if _, err := log.Append(secondEvent); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(event(JournalCommit)); err != nil {
		t.Fatal(err)
	}

	var complete []VerifiedReceipt
	completeHead, err := VerifyRecords(path, public, "node-a", 1, func(record VerifiedReceipt) error {
		complete = append(complete, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := log.ExportDelta(Coordinate{})
	if err != nil {
		t.Fatal(err)
	}
	if delta.Head != completeHead || len(delta.Frames) != len(complete) {
		t.Fatalf("delta=%#v complete head=%#v records=%d", delta, completeHead, len(complete))
	}
	for index := range complete {
		if !bytes.Equal(delta.Frames[index], complete[index].Frame) {
			t.Fatalf("delta frame %d changed native signed bytes", index)
		}
	}
	verified, err := VerifyDelta(delta.Frames, public, "node-a", 1, Coordinate{}, func(tenantID string) bool {
		return tenantID == "tenant-a" || tenantID == "tenant-b"
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified != completeHead {
		t.Fatalf("verified delta head=%#v want %#v", verified, completeHead)
	}

	firstCoordinate := Coordinate{Sequence: first.Sequence, ChainHash: complete[0].ChainHash}
	suffix, err := log.ExportDelta(firstCoordinate)
	if err != nil {
		t.Fatal(err)
	}
	if len(suffix.Frames) != 2 || !bytes.Equal(suffix.Frames[0], complete[1].Frame) {
		t.Fatalf("suffix frames=%d", len(suffix.Frames))
	}
	suffixHead, err := VerifyDelta(suffix.Frames, public, "node-a", 1, firstCoordinate, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if suffixHead != completeHead {
		t.Fatalf("suffix head=%#v want %#v", suffixHead, completeHead)
	}

	atHead, err := log.ExportDelta(Coordinate{Sequence: completeHead.Sequence, ChainHash: completeHead.ChainHash})
	if err != nil {
		t.Fatal(err)
	}
	if len(atHead.Frames) != 0 || atHead.Head != completeHead {
		t.Fatalf("idempotent delta=%#v", atHead)
	}
	emptyHead, err := VerifyDelta(nil, public, "node-a", 1,
		Coordinate{Sequence: completeHead.Sequence, ChainHash: completeHead.ChainHash}, func(string) bool { return true })
	if err != nil || emptyHead != completeHead {
		t.Fatalf("empty verified head=%#v err=%v", emptyHead, err)
	}

	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	validation, err := OpenForValidation(path, public, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer validation.Close()
	readOnlyDelta, err := validation.ExportDelta(firstCoordinate)
	if err != nil {
		t.Fatal(err)
	}
	if readOnlyDelta.Head != completeHead || len(readOnlyDelta.Frames) != 2 {
		t.Fatalf("read-only delta=%#v", readOnlyDelta)
	}
}

func TestExportDeltaRequiresAnExactPresentCoordinate(t *testing.T) {
	log, _, _ := newLog(t)
	if _, err := log.Append(event(AdmissionAllow)); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(event(InferenceAuthorize)); err != nil {
		t.Fatal(err)
	}
	valid, err := log.ExportDelta(Coordinate{})
	if err != nil {
		t.Fatal(err)
	}
	wrong := valid.Head.ChainHash
	wrong[0] ^= 1
	for name, test := range map[string]struct {
		coordinate Coordinate
		mismatch   bool
	}{
		"nonzero genesis hash": {coordinate: Coordinate{ChainHash: wrong}},
		"wrong retained hash": {
			coordinate: Coordinate{Sequence: valid.Head.Sequence, ChainHash: wrong}, mismatch: true,
		},
		"sequence beyond head": {
			coordinate: Coordinate{Sequence: valid.Head.Sequence + 1, ChainHash: valid.Head.ChainHash}, mismatch: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := log.ExportDelta(test.coordinate)
			if err == nil || errors.Is(err, ErrDeltaCoordinate) != test.mismatch {
				t.Fatalf("ExportDelta coordinate error = %v, mismatch=%v", err, test.mismatch)
			}
		})
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := log.ExportDelta(Coordinate{}); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed ExportDelta error=%v", err)
	}
}

func TestCurrentHeadTracksFsyncedAppendsAndRejectsClosedLog(t *testing.T) {
	log, _, _ := newLog(t)
	if _, err := log.Append(event(AdmissionAllow)); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(event(JournalCommit)); err != nil {
		t.Fatal(err)
	}
	head, err := log.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}
	if head.NodeID != log.nodeID || head.Epoch != log.epoch || head.Sequence != 2 ||
		head.ChainHash != log.lastHash || head.KeyID != log.keyID {
		t.Fatalf("current head = %#v", head)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := log.CurrentHead(); err == nil {
		t.Fatal("closed evidence log returned a current head")
	}
	var absent *Log
	if _, err := absent.CurrentHead(); err == nil {
		t.Fatal("nil evidence log returned a current head")
	}
}

func TestExportDeltaIsRecordBoundedAndResumable(t *testing.T) {
	log, _, public := newLog(t)
	defer log.Close()
	for index := 0; index < MaxDeltaRecords+1; index++ {
		value := event(AdmissionAllow)
		value.Generation = uint64(index + 1)
		if _, err := log.Append(value); err != nil {
			t.Fatal(err)
		}
	}
	first, err := log.ExportDelta(Coordinate{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Frames) != MaxDeltaRecords || first.Head.Sequence != MaxDeltaRecords || !first.More {
		t.Fatalf("first delta frames=%d head=%#v", len(first.Frames), first.Head)
	}
	total := 0
	for _, frame := range first.Frames {
		total += len(frame)
	}
	if total > MaxDeltaBytes {
		t.Fatalf("exported delta bytes=%d exceed %d", total, MaxDeltaBytes)
	}
	firstVerified, err := VerifyDelta(first.Frames, public, "node-a", 1, Coordinate{}, func(string) bool { return true })
	if err != nil || firstVerified != first.Head {
		t.Fatalf("first verified=%#v err=%v", firstVerified, err)
	}
	second, err := log.ExportDelta(Coordinate{Sequence: first.Head.Sequence, ChainHash: first.Head.ChainHash})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Frames) != 1 || second.Head.Sequence != MaxDeltaRecords+1 || second.More {
		t.Fatalf("second delta frames=%d head=%#v", len(second.Frames), second.Head)
	}
}

func TestExportDeltaSparseIndexAvoidsQuadraticCatchUpAcrossReopen(t *testing.T) {
	log, path, public := newLog(t)
	records := 4*MaxDeltaRecords + 17
	for index := 0; index < records; index++ {
		value := event(AdmissionAllow)
		value.Generation = uint64(index + 1)
		if _, err := log.Append(value); err != nil {
			t.Fatal(err)
		}
	}
	private := append(ed25519.PrivateKey(nil), log.private...)
	assertIndexedCatchUp := func(t *testing.T, opened *Log) {
		t.Helper()
		coordinate := Coordinate{}
		totalScanned := 0
		batches := 0
		for {
			delta, scanned, err := opened.exportDelta(coordinate)
			if err != nil {
				t.Fatal(err)
			}
			if scanned > MaxDeltaRecords {
				t.Fatalf("aligned batch replayed %d records, want at most %d", scanned, MaxDeltaRecords)
			}
			totalScanned += scanned
			batches++
			verified, err := VerifyDelta(delta.Frames, public, "node-a", 1, coordinate, func(string) bool { return true })
			if err != nil || verified != delta.Head {
				t.Fatalf("verified batch head=%#v want %#v err=%v", verified, delta.Head, err)
			}
			coordinate = Coordinate{Sequence: delta.Head.Sequence, ChainHash: delta.Head.ChainHash}
			if !delta.More {
				break
			}
		}
		if totalScanned != records || batches != 5 {
			t.Fatalf("catch-up scanned=%d batches=%d, want records=%d batches=5", totalScanned, batches, records)
		}
		atHead, scanned, err := opened.exportDelta(coordinate)
		if err != nil || scanned != records%MaxDeltaRecords || len(atHead.Frames) != 0 || atHead.More {
			t.Fatalf("equal-coordinate delta=%#v scanned=%d err=%v", atHead, scanned, err)
		}
		if len(opened.checkpoints) != records/MaxDeltaRecords+1 {
			t.Fatalf("checkpoint count=%d want=%d", len(opened.checkpoints), records/MaxDeltaRecords+1)
		}
	}

	assertIndexedCatchUp(t, log)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, private, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertIndexedCatchUp(t, reopened)
}

func TestExportDeltaSparseIndexBoundsUnalignedCoordinateReplay(t *testing.T) {
	log, path, public := newLog(t)
	defer log.Close()
	records := 4*MaxDeltaRecords + 40
	for index := 0; index < records; index++ {
		value := event(AdmissionAllow)
		value.Generation = uint64(index + 1)
		if _, err := log.Append(value); err != nil {
			t.Fatal(err)
		}
	}
	target := uint64(2*MaxDeltaRecords + 17)
	var coordinate Coordinate
	if _, err := VerifyRecords(path, public, "node-a", 1, func(record VerifiedReceipt) error {
		if record.Receipt.Sequence == target {
			coordinate = Coordinate{Sequence: target, ChainHash: record.ChainHash}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	delta, scanned, err := log.exportDelta(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Frames) != MaxDeltaRecords || scanned != 17+MaxDeltaRecords || !delta.More {
		t.Fatalf("unaligned export frames=%d scanned=%d more=%v", len(delta.Frames), scanned, delta.More)
	}
}

func TestExportDeltaEqualCoordinateFailsClosedAfterOutOfBandTamper(t *testing.T) {
	log, path, _ := newLog(t)
	if _, err := log.Append(event(AdmissionAllow)); err != nil {
		t.Fatal(err)
	}
	head, err := log.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}
	private := append(ed25519.PrivateKey(nil), log.private...)
	tamperEvidenceTailPreservingMetadata(t, path)
	if _, scanned, err := log.exportDelta(Coordinate{
		Sequence: head.Sequence, ChainHash: head.ChainHash,
	}); err == nil || scanned != 1 {
		t.Fatalf("tampered equal-coordinate export scanned=%d err=%v", scanned, err)
	}
	if _, err := log.Append(event(JournalCommit)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("append after detected replay corruption error=%v", err)
	}
	if _, err := Open(path, private, "node-a", 1); err == nil {
		t.Fatal("reopen accepted the tampered evidence log")
	}
}

func TestAppendFailsClosedAfterOutOfBandTailTamper(t *testing.T) {
	log, path, _ := newLog(t)
	if _, err := log.Append(event(AdmissionAllow)); err != nil {
		t.Fatal(err)
	}
	tamperEvidenceTailPreservingMetadata(t, path)
	if _, err := log.Append(event(JournalCommit)); err == nil {
		t.Fatal("append extended a corrupted evidence tail")
	}
	if _, err := log.Append(event(JournalCommit)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("second append after tail corruption error=%v", err)
	}
}

func tamperEvidenceTailPreservingMetadata(t *testing.T, path string) {
	t.Helper()
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(raw[len(raw)-1:], int64(len(raw)-1)); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, beforeInfo.ModTime(), beforeInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
}

func TestExportDeltaReplayVerificationFailureClosesTheWriter(t *testing.T) {
	log, path, _ := newLog(t)
	for _, kind := range []EventType{AdmissionAllow, JournalCommit} {
		if _, err := log.Append(event(kind)); err != nil {
			t.Fatal(err)
		}
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	last := int64(len(raw) - 1)
	if _, err := file.WriteAt([]byte{raw[last] ^ 1}, last); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, beforeInfo.ModTime(), beforeInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := log.ExportDelta(Coordinate{}); err == nil {
		t.Fatal("indexed replay accepted a tampered signed frame")
	}
	if _, err := log.Append(event(JournalCommit)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("append after replay verification failure error=%v", err)
	}
}

func TestExportDeltaConcurrentAppendMaintainsVerifiedCheckpointState(t *testing.T) {
	log, _, public := newLog(t)
	defer log.Close()
	const records = MaxDeltaRecords + 17
	notify := make(chan struct{}, 1)
	completed := make(chan error, 1)
	go func() {
		for index := 0; index < records; index++ {
			value := event(AdmissionAllow)
			value.Generation = uint64(index + 1)
			if _, err := log.Append(value); err != nil {
				completed <- err
				return
			}
			select {
			case notify <- struct{}{}:
			default:
			}
			runtime.Gosched()
		}
		completed <- nil
	}()

	coordinate := Coordinate{}
	done := false
	for {
		delta, err := log.ExportDelta(coordinate)
		if err != nil {
			t.Fatal(err)
		}
		if len(delta.Frames) > 0 {
			verified, err := VerifyDelta(delta.Frames, public, "node-a", 1, coordinate, func(string) bool { return true })
			if err != nil || verified != delta.Head {
				t.Fatalf("concurrent delta head=%#v want %#v err=%v", verified, delta.Head, err)
			}
			coordinate = Coordinate{Sequence: delta.Head.Sequence, ChainHash: delta.Head.ChainHash}
			continue
		}
		if done {
			head, err := log.CurrentHead()
			if err != nil {
				t.Fatal(err)
			}
			if coordinate.Sequence != head.Sequence || coordinate.ChainHash != head.ChainHash {
				t.Fatalf("final exported coordinate=%#v head=%#v", coordinate, head)
			}
			break
		}
		select {
		case <-notify:
		case err := <-completed:
			if err != nil {
				t.Fatal(err)
			}
			done = true
		}
	}
}

func TestVerifyDeltaRejectsIdentityChainTenantAndSchemaViolations(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := Open(t.TempDir()+"/receipts.log", private, "node-a", 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(event(AdmissionAllow)); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(event(JournalCommit)); err != nil {
		t.Fatal(err)
	}
	delta, err := log.ExportDelta(Coordinate{})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	allow := func(string) bool { return true }

	tests := []struct {
		name   string
		frames [][]byte
		key    ed25519.PublicKey
		node   string
		epoch  uint64
		prior  Coordinate
		member func(string) bool
	}{
		{name: "wrong key", frames: delta.Frames, key: mustOtherPublic(t), node: "node-a", epoch: 7, member: allow},
		{name: "wrong node", frames: delta.Frames, key: public, node: "node-b", epoch: 7, member: allow},
		{name: "wrong epoch", frames: delta.Frames, key: public, node: "node-a", epoch: 8, member: allow},
		{name: "wrong prior hash", frames: delta.Frames, key: public, node: "node-a", epoch: 7,
			prior: Coordinate{Sequence: 1, ChainHash: [sha256.Size]byte{1}}, member: allow},
		{name: "reordered", frames: [][]byte{delta.Frames[1], delta.Frames[0]}, key: public, node: "node-a", epoch: 7, member: allow},
		{name: "tenant rejected", frames: delta.Frames, key: public, node: "node-a", epoch: 7, member: func(string) bool { return false }},
		{name: "nil tenant callback", frames: delta.Frames, key: public, node: "node-a", epoch: 7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyDelta(test.frames, test.key, test.node, test.epoch, test.prior, test.member); err == nil {
				t.Fatal("VerifyDelta accepted invalid evidence")
			}
		})
	}

	tampered := cloneFrames(delta.Frames)
	tampered[0][len(tampered[0])-1] ^= 1
	if _, err := VerifyDelta(tampered, public, "node-a", 7, Coordinate{}, allow); err == nil {
		t.Fatal("VerifyDelta accepted a modified signature")
	}

	unknownEvent := resignFrameWithPayloadMutation(t, delta.Frames[0], private, func(payload []byte) []byte {
		nodeLength := int(binary.BigEndian.Uint16(payload[1:3]))
		eventOffset := 1 + 2 + nodeLength + 8 + 8 + sha256.Size
		payload[eventOffset] = 255
		return payload
	})
	if _, err := VerifyDelta([][]byte{unknownEvent}, public, "node-a", 7, Coordinate{}, allow); err == nil {
		t.Fatal("VerifyDelta accepted an unknown receipt event")
	}

	trailingField := resignFrameWithPayloadMutation(t, delta.Frames[0], private, func(payload []byte) []byte {
		return append(payload, 0)
	})
	if _, err := VerifyDelta([][]byte{trailingField}, public, "node-a", 7, Coordinate{}, allow); err == nil {
		t.Fatal("VerifyDelta accepted a receipt with trailing schema bytes")
	}
}

func TestVerifyDeltaEnforcesRecordFrameAndDecodedByteBounds(t *testing.T) {
	allow := func(string) bool { return true }
	public := mustOtherPublic(t)
	tooMany := make([][]byte, MaxDeltaRecords+1)
	if _, err := VerifyDelta(tooMany, public, "node-a", 1, Coordinate{}, allow); err == nil || !strings.Contains(err.Error(), "records") {
		t.Fatalf("record bound error=%v", err)
	}
	if _, err := VerifyDelta([][]byte{{0, 0, 0, 0}}, public, "node-a", 1, Coordinate{}, allow); err == nil ||
		!strings.Contains(err.Error(), "frame size") {
		t.Fatalf("short frame error=%v", err)
	}
	oversized := make([]byte, MaxEnvelopeBytes+5)
	if _, err := VerifyDelta([][]byte{oversized}, public, "node-a", 1, Coordinate{}, allow); err == nil ||
		!strings.Contains(err.Error(), "frame size") {
		t.Fatalf("oversized frame error=%v", err)
	}
	largeFrames := make([][]byte, 11)
	for index := range largeFrames {
		largeFrames[index] = make([]byte, MaxEnvelopeBytes+4)
		binary.BigEndian.PutUint32(largeFrames[index][:4], MaxEnvelopeBytes)
	}
	if _, err := VerifyDelta(largeFrames, public, "node-a", 1, Coordinate{}, allow); err == nil ||
		!strings.Contains(err.Error(), "decoded bytes") {
		t.Fatalf("decoded byte bound error=%v", err)
	}
	nonzeroGenesis := Coordinate{ChainHash: [sha256.Size]byte{1}}
	if _, err := VerifyDelta(nil, public, "node-a", 1, nonzeroGenesis, allow); err == nil ||
		!strings.Contains(err.Error(), "genesis") {
		t.Fatalf("genesis coordinate error=%v", err)
	}
	overflowFrame := []byte{0, 0, 0, 1, 1}
	if _, err := VerifyDelta([][]byte{overflowFrame}, public, "node-a", 1,
		Coordinate{Sequence: ^uint64(0)}, allow); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("sequence overflow error=%v", err)
	}
}

func cloneFrames(frames [][]byte) [][]byte {
	cloned := make([][]byte, len(frames))
	for index, frame := range frames {
		cloned[index] = append([]byte(nil), frame...)
	}
	return cloned
}

func mustOtherPublic(t *testing.T) ed25519.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func resignFrameWithPayloadMutation(t *testing.T, frame []byte, private ed25519.PrivateKey, mutate func([]byte) []byte) []byte {
	t.Helper()
	envelope, err := unmarshalEnvelope(frame[4:])
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload = mutate(append([]byte(nil), envelope.Payload...))
	envelope.Signature = ed25519.Sign(private, PreAuthEncoding(envelope.PayloadType, envelope.Payload))
	raw, err := marshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return frameBytes(raw)
}
