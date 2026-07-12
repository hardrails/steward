package admission

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestFenceStorePersistsAndRejectsRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.bin")
	if err := InitializeFenceStore(path); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFenceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record := testFenceRecord("tenant-a", "agent", 2)
	if err := store.Commit(record, 3); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFenceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Fences("tenant-a", "agent"); got.Generation != 2 || got.PolicyEpoch != 3 {
		t.Fatalf("fences = %#v", got)
	}
	rollback := record
	rollback.Generation = 1
	if err := reopened.Commit(rollback, 3); err == nil {
		t.Fatal("generation rollback accepted")
	}
	different := record
	different.CapsuleDigest = "sha256:" + repeatHex('b')
	if err := reopened.Commit(different, 3); err == nil {
		t.Fatal("equal generation for different capsule accepted")
	}
}

func TestFenceStoreRejectsTruncationAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fences.bin")
	if err := InitializeFenceStore(path); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFenceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(testFenceRecord("t", "i", 1), 1); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, raw[:len(raw)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFenceStore(path); err == nil {
		t.Fatal("truncated store accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFenceStore(path); err == nil {
		t.Fatal("over-permissive store accepted")
	}
}

func TestFenceStoreMustBeInitializedExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.bin")
	if _, err := OpenFenceStore(path); err == nil {
		t.Fatal("missing fence store was silently recreated")
	}
	if err := InitializeFenceStore(path); err != nil {
		t.Fatal(err)
	}
	if err := InitializeFenceStore(path); err == nil {
		t.Fatal("existing fence store was overwritten")
	}
}

func TestFenceStoreRejectsInvalidCommitsAndPolicyRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.bin")
	if err := InitializeFenceStore(path); err != nil {
		t.Fatal(err)
	}
	store, _ := OpenFenceStore(path)
	base := testFenceRecord("tenant", "instance", 2)
	if err := store.Commit(base, 3); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(base, 2); err == nil {
		t.Fatal("policy rollback accepted")
	}
	for _, mutate := range []func(*FenceRecord){
		func(r *FenceRecord) { r.TenantID = "" },
		func(r *FenceRecord) { r.InstanceID = "" },
		func(r *FenceRecord) { r.Generation = 0 },
		func(r *FenceRecord) { r.CapsuleDigest = "bad" },
		func(r *FenceRecord) { r.PolicyDigest = "bad" },
		func(r *FenceRecord) { r.LineageID = "" },
		func(r *FenceRecord) { r.WorkloadDigest = "bad" },
		func(r *FenceRecord) { r.ImageConfigDigest = "bad" },
		func(r *FenceRecord) { r.RoutePolicyDigest = "bad" },
	} {
		record := base
		mutate(&record)
		if err := store.Commit(record, 3); err == nil {
			t.Fatal("invalid fence record accepted")
		}
	}
	for _, mutate := range []func(*FenceRecord){
		func(r *FenceRecord) { r.PolicyDigest = "sha256:" + repeatHex('e') },
		func(r *FenceRecord) { r.LineageID = "other" },
		func(r *FenceRecord) { r.WorkloadDigest = "sha256:" + repeatHex('e') },
		func(r *FenceRecord) { r.ImageConfigDigest = "sha256:" + repeatHex('e') },
		func(r *FenceRecord) { r.RoutePolicyDigest = "sha256:" + repeatHex('e') },
	} {
		record := base
		mutate(&record)
		if err := store.Commit(record, 3); err == nil {
			t.Fatal("equal generation changed signed lineage")
		}
	}
	next := base
	next.Generation++
	next.Present = false
	if err := store.Commit(next, 4); err != nil {
		t.Fatal(err)
	}
	if store.Count() != 1 || len(store.Records()) != 1 {
		t.Fatal("record inventory mismatch")
	}
}

func TestFenceStoreRejectsMalformedSnapshots(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":    {},
		"header":   []byte("not-a-fence-store"),
		"trailing": append([]byte{'S', 'T', 'F', 'N', fenceVersion, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fences.bin")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenFenceStore(path); err == nil {
				t.Fatal("malformed snapshot accepted")
			}
		})
	}
	dir := filepath.Join(t.TempDir(), "directory")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFenceStore(dir); err == nil {
		t.Fatal("directory accepted as fence store")
	}
	if _, _, ok := takeFenceText([]byte{0, 5, 'x'}, 4); ok {
		t.Fatal("invalid length accepted")
	}
}

func TestFenceStoreRejectsMalformedRecords(t *testing.T) {
	valid := testFenceRecord("tenant", "instance", 1)
	write := func(t *testing.T, raw []byte) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "fences.bin")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFenceStore(path); err == nil {
			t.Fatal("malformed fence record accepted")
		}
	}
	encodeRecord := func(record FenceRecord, present byte) []byte {
		raw := []byte{'S', 'T', 'F', 'N', fenceVersion}
		raw = binary.BigEndian.AppendUint64(raw, 1)
		raw = binary.BigEndian.AppendUint32(raw, 1)
		raw = appendFenceText(raw, record.TenantID)
		raw = appendFenceText(raw, record.InstanceID)
		raw = binary.BigEndian.AppendUint64(raw, record.Generation)
		raw = appendFenceText(raw, record.CapsuleDigest)
		raw = appendFenceText(raw, record.PolicyDigest)
		raw = appendFenceText(raw, record.LineageID)
		raw = appendFenceText(raw, record.WorkloadDigest)
		raw = appendFenceText(raw, record.ImageConfigDigest)
		raw = appendFenceText(raw, record.RoutePolicyDigest)
		return append(raw, present)
	}

	for name, mutate := range map[string]func(*FenceRecord){
		"tenant":         func(record *FenceRecord) { record.TenantID = "" },
		"instance":       func(record *FenceRecord) { record.InstanceID = "" },
		"coordinates":    func(record *FenceRecord) { record.Generation = 0 },
		"policy":         func(record *FenceRecord) { record.PolicyDigest = "invalid" },
		"lineage":        func(record *FenceRecord) { record.LineageID = "" },
		"workloadDigest": func(record *FenceRecord) { record.WorkloadDigest = "invalid" },
		"imageDigest":    func(record *FenceRecord) { record.ImageConfigDigest = "invalid" },
		"routeDigest":    func(record *FenceRecord) { record.RoutePolicyDigest = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			record := valid
			mutate(&record)
			write(t, encodeRecord(record, 1))
		})
	}
	t.Run("presence", func(t *testing.T) { write(t, encodeRecord(valid, 2)) })

	t.Run("duplicate", func(t *testing.T) {
		one := encodeRecord(valid, 1)
		recordBytes := one[17:]
		raw := append([]byte(nil), one...)
		binary.BigEndian.PutUint32(raw[13:17], 2)
		raw = append(raw, recordBytes...)
		write(t, raw)
	})
}

func TestFenceStoreLoadsLegacyRecordWithoutInventingRoutePolicy(t *testing.T) {
	record := testFenceRecord("tenant", "instance", 1)
	raw := []byte{'S', 'T', 'F', 'N', legacyFenceVersion}
	raw = binary.BigEndian.AppendUint64(raw, 1)
	raw = binary.BigEndian.AppendUint32(raw, 1)
	raw = appendFenceText(raw, record.TenantID)
	raw = appendFenceText(raw, record.InstanceID)
	raw = binary.BigEndian.AppendUint64(raw, record.Generation)
	raw = appendFenceText(raw, record.CapsuleDigest)
	raw = appendFenceText(raw, record.PolicyDigest)
	raw = appendFenceText(raw, record.LineageID)
	raw = appendFenceText(raw, record.WorkloadDigest)
	raw = appendFenceText(raw, record.ImageConfigDigest)
	raw = append(raw, 1)
	path := filepath.Join(t.TempDir(), "fences.bin")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFenceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := store.Record(record.TenantID, record.InstanceID)
	if !ok || loaded.RoutePolicyDigest != "" {
		t.Fatalf("legacy route policy binding = %q, want empty fail-closed marker", loaded.RoutePolicyDigest)
	}
}

func TestFenceStorePathAndEncodingBounds(t *testing.T) {
	if err := InitializeFenceStore(""); err == nil {
		t.Fatal("empty initialization path accepted")
	}
	if _, err := OpenFenceStore(""); err == nil {
		t.Fatal("empty open path accepted")
	}

	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InitializeFenceStore(filepath.Join(parent, "fences.bin")); err == nil {
		t.Fatal("file parent accepted as directory")
	}

	oversized := filepath.Join(t.TempDir(), "oversized.bin")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxFenceBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFenceStore(oversized); err == nil {
		t.Fatal("oversized fence store accepted")
	}

	store := &FenceStore{byInstance: make(map[string]FenceRecord, 65536)}
	for index := 0; index < 65536; index++ {
		store.byInstance[strconv.Itoa(index)] = FenceRecord{}
	}
	if _, err := store.encode(); err == nil {
		t.Fatal("unbounded record count accepted")
	}
}

func testFenceRecord(tenant, instance string, generation uint64) FenceRecord {
	return FenceRecord{
		TenantID: tenant, InstanceID: instance, Generation: generation,
		CapsuleDigest: "sha256:" + repeatHex('a'), PolicyDigest: "sha256:" + repeatHex('b'),
		LineageID: "lineage", WorkloadDigest: "sha256:" + repeatHex('c'),
		ImageConfigDigest: "sha256:" + repeatHex('d'), RoutePolicyDigest: "sha256:" + repeatHex('f'), Present: true,
	}
}

func repeatHex(value byte) string {
	raw := make([]byte, 64)
	for index := range raw {
		raw[index] = value
	}
	return string(raw)
}
