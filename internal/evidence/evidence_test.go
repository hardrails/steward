package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func newLog(t *testing.T) (*Log, string, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipts.log")
	log, err := Open(path, private, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	return log, path, public
}

func event(kind EventType) Event {
	return Event{Type: kind, TenantID: "tenant-a", RuntimeRef: "runtime-a",
		CapsuleDigest: "sha256:capsule", PolicyDigest: "sha256:policy", Generation: 1,
		GrantID: "grant-a", Outcome: Allowed, ErrorCode: "none", MetadataHash: "sha256:meta"}
}

func TestAppendAndVerifyChain(t *testing.T) {
	log, path, public := newLog(t)
	first, err := log.Append(event(AdmissionAllow))
	if err != nil {
		t.Fatal(err)
	}
	secondEvent := event(InferenceAuthorize)
	secondEvent.Outcome = Committed
	second, err := log.Append(secondEvent)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	last, err := Verify(path, public, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if last == nil || last.Sequence != second.Sequence || second.PreviousHash == first.PreviousHash {
		t.Fatalf("unexpected verified chain: first=%#v second=%#v last=%#v", first, second, last)
	}
}

func TestVerifyRecordsReturnsPortableHeadAndClosedNames(t *testing.T) {
	log, path, public := newLog(t)
	for _, kind := range []EventType{AdmissionAllow, JournalPrepare, JournalCommit} {
		if _, err := log.Append(event(kind)); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var records []VerifiedReceipt
	head, err := VerifyRecords(path, public, "node-a", 1, func(record VerifiedReceipt) error {
		records = append(records, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if head.Sequence != 3 || head.NodeID != "node-a" || head.Epoch != 1 || head.KeyID != KeyID(public) ||
		head.ChainHash == [32]byte{} || len(records) != 3 || records[2].ChainHash != head.ChainHash {
		t.Fatalf("head=%#v records=%#v", head, records)
	}
	for index, record := range records {
		if len(record.Frame) < 5 || int(binary.BigEndian.Uint32(record.Frame[:4])) != len(record.Frame)-4 {
			t.Fatalf("record %d does not retain its exact length-prefixed signed frame", index)
		}
	}
	if EventName(JournalCommit) != "journal_commit" || EventName(255) != "" ||
		OutcomeName(Committed) != "committed" || OutcomeName(255) != "" {
		t.Fatal("closed evidence vocabulary names are incorrect")
	}
	wantErr := errors.New("visitor stopped")
	if _, err := VerifyRecords(path, public, "node-a", 1, func(VerifiedReceipt) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("visitor error = %v, want %v", err, wantErr)
	}
}

func TestVerifyRejectsTamperTruncateReorderAndWrongKey(t *testing.T) {
	log, path, public := newLog(t)
	if _, err := log.Append(event(AdmissionAllow)); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(event(InferenceAuthorize)); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("tamper", func(t *testing.T) {
		raw := append([]byte(nil), original...)
		raw[len(raw)-1] ^= 1
		mustWrite(t, path, raw)
		if _, err := Verify(path, public, "node-a", 1); err == nil {
			t.Fatal("verification accepted tampering")
		}
	})
	t.Run("truncate", func(t *testing.T) {
		mustWrite(t, path, original[:len(original)-1])
		if _, err := Verify(path, public, "node-a", 1); err == nil {
			t.Fatal("verification accepted truncation")
		}
	})
	t.Run("reorder", func(t *testing.T) {
		firstEnd := 4 + int(uint32(original[0])<<24|uint32(original[1])<<16|uint32(original[2])<<8|uint32(original[3]))
		raw := append(append([]byte(nil), original[firstEnd:]...), original[:firstEnd]...)
		mustWrite(t, path, raw)
		if _, err := Verify(path, public, "node-a", 1); err == nil {
			t.Fatal("verification accepted reordered frames")
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		mustWrite(t, path, original)
		other, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(path, other, "node-a", 1); err == nil {
			t.Fatal("verification accepted wrong key")
		}
	})
}

func TestOpenFailsClosedOnTruncatedExistingLog(t *testing.T) {
	log, path, _ := newLog(t)
	if _, err := log.Append(event(AdmissionAllow)); err != nil {
		t.Fatal(err)
	}
	private := append(ed25519.PrivateKey(nil), log.private...)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, raw[:len(raw)-2])
	if _, err := Open(path, private, "node-a", 1); err == nil {
		t.Fatal("Open accepted truncated evidence")
	}
}

func TestOpenForValidationIsStrictlyReadOnly(t *testing.T) {
	log, path, public := newLog(t)
	if _, err := log.Append(event(AdmissionAllow)); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	validation, err := OpenForValidation(path, public, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if validation.NextSequence() != 2 || !bytes.Equal(validation.PublicKey(), public) {
		t.Fatalf("validation state next=%d key=%x", validation.NextSequence(), validation.PublicKey())
	}
	if _, err := validation.Append(event(AdmissionDeny)); err == nil || !strings.Contains(err.Error(), "validation only") {
		t.Fatalf("read-only Append error = %v", err)
	}
	if err := validation.Close(); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || beforeInfo.Mode() != afterInfo.Mode() || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("read-only validation changed evidence bytes or metadata")
	}
	missing := filepath.Join(filepath.Dir(path), "missing.log")
	if _, err := OpenForValidation(missing, public, "node-a", 1); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing evidence error = %v", err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("validation created missing evidence: %v", err)
	}
}

func TestInspectFormatReportsExistingVersionAndRejectsUnsafeOrMalformedLogs(t *testing.T) {
	log, path, _ := newLog(t)
	for _, kind := range []EventType{AdmissionAllow, JournalCommit} {
		if _, err := log.Append(event(kind)); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	summary, err := InspectFormat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Present || summary.FormatVersion != receiptVersion || summary.Records != 2 {
		t.Fatalf("format summary = %#v", summary)
	}
	if _, err := InspectFormat(""); err == nil {
		t.Fatal("InspectFormat accepted an empty path")
	}
	if _, err := InspectFormat(filepath.Join(filepath.Dir(path), "missing.log")); err == nil ||
		!strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing format error = %v", err)
	}
	if _, err := InspectFormat(filepath.Dir(path)); err == nil {
		t.Fatal("InspectFormat accepted a directory")
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectFormat(path); err == nil {
		t.Fatal("InspectFormat accepted group/world-readable evidence")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, original[:len(original)-1])
	if _, err := InspectFormat(path); err == nil || !strings.Contains(err.Error(), "inspect evidence") {
		t.Fatalf("truncated format error = %v", err)
	}
}

func TestOpenRejectsConcurrentWriterThroughHardLink(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "evidence.bin")
	alias := filepath.Join(directory, "evidence-alias.bin")
	first, err := Open(path, private, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if second, err := Open(alias, private, "node-a", 1); err == nil ||
		!strings.Contains(err.Error(), "already open by another writer") {
		if second != nil {
			_ = second.Close()
		}
		_ = first.Close()
		t.Fatalf("concurrent hard-link writer err=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(alias, private, "node-a", 1)
	if err != nil {
		t.Fatalf("open after writer close: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveCreateRejectsSymlinkInsertedAfterMissingCheck(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "evidence.bin")
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	var hookErr error
	file, _, err := openEvidenceForAppendAfterMissing(path, func() {
		hookErr = os.Symlink(target, path)
	})
	if file != nil {
		_ = file.Close()
	}
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink insertion error=%v", err)
	}
	raw, readErr := os.ReadFile(target)
	info, statErr := os.Stat(target)
	if readErr != nil || statErr != nil {
		t.Fatalf("inspect symlink target read_err=%v stat_err=%v", readErr, statErr)
	}
	if string(raw) != "sentinel" || info.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target raw=%q mode=%v", raw, info.Mode())
	}
}

func TestLogFailsClosedWhenConfiguredPathIsUnlinkedOrReplaced(t *testing.T) {
	t.Run("unlinked", func(t *testing.T) {
		log, path, _ := newLog(t)
		if _, err := log.Append(event(AdmissionAllow)); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(event(JournalCommit)); err == nil ||
			!strings.Contains(err.Error(), "evidence path") {
			t.Fatalf("append after unlink error=%v", err)
		}
		if _, err := log.Append(event(JournalCommit)); err == nil ||
			!strings.Contains(err.Error(), "closed") {
			t.Fatalf("second append after unlink error=%v", err)
		}
	})

	t.Run("replaced", func(t *testing.T) {
		log, path, _ := newLog(t)
		if _, err := log.Append(event(AdmissionAllow)); err != nil {
			t.Fatal(err)
		}
		private := append(ed25519.PrivateKey(nil), log.private...)
		moved := path + ".moved"
		if err := os.Rename(path, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(event(JournalCommit)); err == nil ||
			!strings.Contains(err.Error(), "no longer names") {
			t.Fatalf("append after path replacement error=%v", err)
		}
		reopened, err := Open(moved, private, "node-a", 1)
		if err != nil {
			t.Fatalf("reopen original inode after fail-close: %v", err)
		}
		defer reopened.Close()
		head, err := reopened.CurrentHead()
		if err != nil || head.Sequence != 1 {
			t.Fatalf("reopened head=%#v err=%v", head, err)
		}
	})
}

func TestEvidenceRejectsUnsafeFilesMalformedFramesAndBounds(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "unsafe.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, private, "node-a", 1); err == nil {
		t.Fatal("Open accepted over-permissive evidence file")
	}

	for name, raw := range map[string][]byte{
		"short-header": {0, 0, 0},
		"zero-frame":   {0, 0, 0, 0},
		"huge-frame":   evidenceFrameHeader(MaxEnvelopeBytes + 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, private, "node-a", 1); err == nil {
				t.Fatal("Open accepted malformed evidence frame")
			}
		})
	}

	log, path, _ := newLog(t)
	tooLarge := event(AdmissionAllow)
	tooLarge.RuntimeRef = strings.Repeat("x", 513)
	if _, err := log.Append(tooLarge); err == nil {
		t.Fatal("Append accepted oversized runtime ref")
	}
	bad := event(AdmissionAllow)
	bad.Type = EventType(255)
	if _, err := log.Append(bad); err == nil {
		t.Fatal("Append accepted unknown event type")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(event(AdmissionAllow)); err == nil {
		t.Fatal("Append after Close succeeded")
	}
	if _, err := Verify(path, nil, "node-a", 1); err == nil {
		t.Fatal("Verify accepted invalid public key")
	}
}

func TestVerifyAnyRecordsAuthenticatesNativeAndPortableEvidence(t *testing.T) {
	log, nativePath, public := newLog(t)
	first := event(AdmissionAllow)
	first.Outcome = Allowed
	second := event(Revocation)
	second.Outcome = Denied
	second.ErrorCode = ""
	second.MetadataHash = ""
	for _, value := range []Event{first, second} {
		if _, err := log.Append(value); err != nil {
			t.Fatal(err)
		}
	}
	if log.NextSequence() != 3 {
		t.Fatalf("next sequence = %d, want 3", log.NextSequence())
	}
	keyCopy := log.PublicKey()
	if !reflect.DeepEqual(keyCopy, public) {
		t.Fatal("PublicKey returned the wrong key")
	}
	keyCopy[0] ^= 1
	if reflect.DeepEqual(log.PublicKey(), keyCopy) {
		t.Fatal("PublicKey exposed mutable key storage")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	var nativeRecords []VerifiedReceipt
	nativeHead, err := VerifyAnyRecords(nativePath, public, "node-a", 1, func(record VerifiedReceipt) error {
		nativeRecords = append(nativeRecords, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	portablePath := writePortableEvidence(t, nativeRecords, nativeHead)
	var portableRecords []VerifiedReceipt
	portableHead, err := VerifyAnyRecords(portablePath, public, "node-a", 1, func(record VerifiedReceipt) error {
		portableRecords = append(portableRecords, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if portableHead != nativeHead || !reflect.DeepEqual(portableRecords, nativeRecords) {
		t.Fatalf("portable verification changed authenticated evidence:\nhead=%#v want %#v\nrecords=%#v want %#v",
			portableHead, nativeHead, portableRecords, nativeRecords)
	}

	wantErr := errors.New("portable visitor stopped")
	if _, err := VerifyAnyRecords(portablePath, public, "node-a", 1, func(VerifiedReceipt) error {
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("visitor error = %v, want %v", err, wantErr)
	}

	emptyLog, emptyNative, emptyPublic := newLog(t)
	if err := emptyLog.Close(); err != nil {
		t.Fatal(err)
	}
	emptyHead, err := VerifyAnyRecords(emptyNative, emptyPublic, "node-a", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if emptyHead.Sequence != 0 || emptyHead.ChainHash != [32]byte{} {
		t.Fatalf("empty native head = %#v", emptyHead)
	}
	emptyPortable := writePortableEvidence(t, nil, emptyHead)
	if got, err := VerifyAnyRecords(emptyPortable, emptyPublic, "node-a", 1, nil); err != nil || got != emptyHead {
		t.Fatalf("empty portable head = %#v, err = %v", got, err)
	}
}

func TestVerifyAnyRecordsRejectsPortableEvidenceSubstitutionAndTruncation(t *testing.T) {
	log, nativePath, public := newLog(t)
	if _, err := log.Append(event(InferenceAuthorize)); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var records []VerifiedReceipt
	head, err := VerifyRecords(nativePath, public, "node-a", 1, func(record VerifiedReceipt) error {
		records = append(records, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	validPath := writePortableEvidence(t, records, head)
	valid, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(valid), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("portable lines = %d, want receipt and head", len(lines))
	}

	mutateJSON := func(t *testing.T, index int, mutate func(map[string]any)) []byte {
		t.Helper()
		changed := append([]string(nil), lines...)
		var value map[string]any
		if err := json.Unmarshal([]byte(changed[index]), &value); err != nil {
			t.Fatal(err)
		}
		mutate(value)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		changed[index] = string(raw)
		return []byte(strings.Join(changed, "\n") + "\n")
	}
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{"projection substitution", mutateJSON(t, 0, func(value map[string]any) { value["tenant_id"] = "tenant-b" }), "does not match its signed frame"},
		{"non-canonical frame", mutateJSON(t, 0, func(value map[string]any) { value["signed_frame"] = "AA==\n" }), "non-canonical signed frame"},
		{"short frame", mutateJSON(t, 0, func(value map[string]any) {
			value["signed_frame"] = base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 1})
		}), "short signed frame"},
		{"invalid frame length", mutateJSON(t, 0, func(value map[string]any) {
			value["signed_frame"] = base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 2, 1})
		}), "invalid signed frame"},
		{"wrong format", mutateJSON(t, 0, func(value map[string]any) { value["format"] = "application/example" }), "invalid kind or format"},
		{"unknown kind", mutateJSON(t, 0, func(value map[string]any) { value["kind"] = "checkpoint" }), "unknown kind"},
		{"missing receipt field", mutateJSON(t, 0, func(value map[string]any) { delete(value, "signed_frame") }), "required portable evidence fields"},
		{"receipt with head field", mutateJSON(t, 0, func(value map[string]any) { value["head"] = map[string]any{} }), "required portable evidence fields"},
		{"wrong final head", mutateJSON(t, 1, func(value map[string]any) { value["head"].(map[string]any)["sequence"] = float64(9) }), "final head does not match"},
		{"head missing field", mutateJSON(t, 1, func(value map[string]any) { delete(value["head"].(map[string]any), "key_id") }), "all required fields"},
		{"head with receipt field", mutateJSON(t, 1, func(value map[string]any) { value["tenant_id"] = "tenant-a" }), "receipt-only fields"},
		{"missing head", []byte(lines[0] + "\n"), "missing its final head"},
		{"content after head", append(append([]byte(nil), valid...), []byte(lines[0]+"\n")...), "content after its final head"},
		{"truncated final line", []byte(strings.TrimSuffix(string(valid), "\n")), "truncated or lacks its final newline"},
		{"empty line", append([]byte("\n"), valid...), "is empty"},
		{"duplicate JSON member", []byte(strings.Replace(lines[0], `"kind":"receipt"`, `"kind":"receipt","kind":"receipt"`, 1) + "\n" + lines[1] + "\n"), "duplicate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "evidence.ndjson")
			mustWrite(t, path, test.raw)
			if _, err := VerifyAnyRecords(path, public, "node-a", 1, nil); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verification err = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestVerifyAnyRecordsEnforcesInputAndLineBounds(t *testing.T) {
	log, _, public := newLog(t)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if _, err := VerifyAnyRecords(directory, public, "node-a", 1, nil); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory verification err = %v", err)
	}

	oversizedExport := filepath.Join(t.TempDir(), "oversized.ndjson")
	file, err := os.OpenFile(oversizedExport, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxExportBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAnyRecords(oversizedExport, public, "node-a", 1, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized export err = %v", err)
	}

	oversizedNative := filepath.Join(t.TempDir(), "oversized.log")
	file, err = os.OpenFile(oversizedNative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxLogBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAnyRecords(oversizedNative, public, "node-a", 1, nil); err == nil || !strings.Contains(err.Error(), "evidence log exceeds") {
		t.Fatalf("oversized native log err = %v", err)
	}

	longLine := filepath.Join(t.TempDir(), "long-line.ndjson")
	mustWrite(t, longLine, append([]byte("{"+strings.Repeat(" ", maxExportLine)), '\n'))
	if _, err := VerifyAnyRecords(longLine, public, "node-a", 1, nil); err == nil || !strings.Contains(err.Error(), "line 1 exceeds") {
		t.Fatalf("oversized line err = %v", err)
	}
	if _, err := VerifyAnyRecords(longLine, nil, "node-a", 1, nil); err == nil || !strings.Contains(err.Error(), "arguments") {
		t.Fatalf("invalid argument err = %v", err)
	}
}

func TestClosedEvidenceVocabularyHasStableNames(t *testing.T) {
	events := []EventType{AdmissionAllow, AdmissionDeny, JournalPrepare, JournalCommit, JournalCompensate,
		GatewayRegistration, InferenceAuthorize, InferenceTerminal, ServiceMapping, LifecycleStart,
		LifecycleStop, LifecycleDestroy, StatePurge, PolicyReload, Drift, Revocation}
	for _, value := range events {
		if EventName(value) == "" {
			t.Fatalf("event %d has no name", value)
		}
	}
	for _, value := range []Outcome{Allowed, Denied, Committed, Failed, Compensated} {
		if OutcomeName(value) == "" {
			t.Fatalf("outcome %d has no name", value)
		}
	}
}

func writePortableEvidence(t *testing.T, records []VerifiedReceipt, head Head) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.ndjson")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	for _, verified := range records {
		receipt := verified.Receipt
		value := map[string]any{
			"format": ExportFormat, "kind": "receipt", "signed_frame": base64.StdEncoding.EncodeToString(verified.Frame),
			"node_id": receipt.NodeID, "epoch": receipt.Epoch, "sequence": receipt.Sequence,
			"previous_hash": formattedHash(receipt.PreviousHash), "chain_hash": formattedHash(verified.ChainHash),
			"event": EventName(receipt.Type), "tenant_id": receipt.TenantID, "runtime_ref": receipt.RuntimeRef,
			"capsule_digest": receipt.CapsuleDigest, "policy_digest": receipt.PolicyDigest, "generation": receipt.Generation,
			"grant_id": receipt.GrantID, "outcome": OutcomeName(receipt.Outcome),
		}
		if receipt.ErrorCode != "" {
			value["error_code"] = receipt.ErrorCode
		}
		if receipt.MetadataHash != "" {
			value["metadata_hash"] = receipt.MetadataHash
		}
		if err := encoder.Encode(value); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Encode(map[string]any{
		"format": ExportFormat, "kind": "head", "head": map[string]any{
			"node_id": head.NodeID, "epoch": head.Epoch, "sequence": head.Sequence,
			"chain_hash": formattedHash(head.ChainHash), "key_id": head.KeyID,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func evidenceFrameHeader(size int) []byte {
	raw := make([]byte, 4)
	binary.BigEndian.PutUint32(raw, uint32(size))
	return raw
}

func mustWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
