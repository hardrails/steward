package evidence

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
)

func TestActivationMarkersAreIdempotentWithoutGrowingTheLog(t *testing.T) {
	log, path, _ := newLog(t)
	defer log.Close()

	begin := activationMarkerEvent(ActivationBegin)
	firstBegin, err := log.AppendActivationBegin(begin)
	if err != nil {
		t.Fatal(err)
	}
	if firstBegin.Version != receiptVersionV2 {
		t.Fatalf("activation begin version=%d want %d", firstBegin.Version, receiptVersionV2)
	}
	beginBytes := readEvidenceBytes(t, path)
	beginNext := log.NextSequence()

	replayedBegin, err := log.AppendActivationBegin(begin)
	if err != nil {
		t.Fatal(err)
	}
	if replayedBegin != firstBegin {
		t.Fatalf("replayed begin=%#v want %#v", replayedBegin, firstBegin)
	}
	if log.NextSequence() != beginNext ||
		!bytes.Equal(readEvidenceBytes(t, path), beginBytes) {
		t.Fatal("exact activation begin retry grew or changed the evidence log")
	}

	checkpoint := activationMarkerEvent(ActivationCheckpoint)
	firstCheckpoint, err := log.AppendActivationCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if firstCheckpoint.Version != receiptVersionV2 {
		t.Fatalf("activation checkpoint version=%d want %d", firstCheckpoint.Version, receiptVersionV2)
	}
	checkpointBytes := readEvidenceBytes(t, path)
	checkpointNext := log.NextSequence()

	replayedCheckpoint, err := log.AppendActivationCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if replayedCheckpoint != firstCheckpoint {
		t.Fatalf("replayed checkpoint=%#v want %#v", replayedCheckpoint, firstCheckpoint)
	}
	if log.NextSequence() != checkpointNext ||
		!bytes.Equal(readEvidenceBytes(t, path), checkpointBytes) {
		t.Fatal("exact activation checkpoint retry grew or changed the evidence log")
	}
}

func TestActivationMarkersUpgradeLegacyEvidenceToSemanticFormatTwo(t *testing.T) {
	log, path, public := newLog(t)
	private := append(ed25519.PrivateKey(nil), log.private...)

	ordinary, err := log.Append(event(AdmissionAllow))
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.Version != receiptVersionV1 {
		t.Fatalf("ordinary receipt version=%d want %d", ordinary.Version, receiptVersionV1)
	}
	begin, err := log.AppendActivationBegin(activationMarkerEvent(ActivationBegin))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := log.AppendActivationCheckpoint(
		activationMarkerEvent(ActivationCheckpoint),
	)
	if err != nil {
		t.Fatal(err)
	}
	if begin.Version != receiptVersionV2 ||
		checkpoint.Version != receiptVersionV2 {
		t.Fatalf(
			"activation versions begin=%d checkpoint=%d want %d",
			begin.Version, checkpoint.Version, receiptVersionV2,
		)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	summary, err := InspectFormat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Present || summary.FormatVersion != receiptVersionV2 ||
		summary.Records != 3 {
		t.Fatalf("mixed-format summary=%#v", summary)
	}
	last, err := Verify(path, public, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if last == nil || last.Version != receiptVersionV2 ||
		last.Type != ActivationCheckpoint {
		t.Fatalf("mixed-format final receipt=%#v", last)
	}
	reopened, err := Open(path, private, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if replayed, err := reopened.AppendActivationCheckpoint(
		activationMarkerEvent(ActivationCheckpoint),
	); err != nil || replayed != checkpoint {
		t.Fatalf("mixed-format checkpoint replay=%#v error=%v", replayed, err)
	}
}

func TestReceiptVersionsAreBoundToTheirClosedEventVocabulary(t *testing.T) {
	log, _, _ := newLog(t)
	defer log.Close()

	ordinary, err := log.Append(event(AdmissionAllow))
	if err != nil {
		t.Fatal(err)
	}
	ordinary.Version = receiptVersionV2
	if _, err := marshalReceipt(ordinary); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("closed event vocabulary")) {
		t.Fatalf("format 2 ordinary-event error=%v", err)
	}

	begin, err := log.AppendActivationBegin(activationMarkerEvent(ActivationBegin))
	if err != nil {
		t.Fatal(err)
	}
	begin.Version = receiptVersionV1
	if _, err := marshalReceipt(begin); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("closed event vocabulary")) {
		t.Fatalf("format 1 activation-event error=%v", err)
	}
}

func TestActivationMarkersRejectConflictsWithoutGrowingTheLog(t *testing.T) {
	log, path, _ := newLog(t)
	defer log.Close()

	begin := activationMarkerEvent(ActivationBegin)
	if _, err := log.AppendActivationBegin(begin); err != nil {
		t.Fatal(err)
	}
	beforeBeginConflict := readEvidenceBytes(t, path)
	beginNext := log.NextSequence()

	for name, mutate := range map[string]func(*Event){
		"activation identity": func(value *Event) {
			value.GrantID = "activation-b"
		},
		"begin digest": func(value *Event) {
			value.MetadataHash = "sha256:other-begin"
		},
		"capsule": func(value *Event) {
			value.CapsuleDigest = "sha256:other-capsule"
		},
		"policy": func(value *Event) {
			value.PolicyDigest = "sha256:other-policy"
		},
	} {
		t.Run("begin "+name, func(t *testing.T) {
			conflicting := begin
			mutate(&conflicting)
			if _, err := log.AppendActivationBegin(conflicting); !errors.Is(
				err, ErrActivationMarkerConflict,
			) {
				t.Fatalf("conflicting begin error=%v", err)
			}
			if log.NextSequence() != beginNext ||
				!bytes.Equal(readEvidenceBytes(t, path), beforeBeginConflict) {
				t.Fatal("conflicting activation begin grew or changed the evidence log")
			}
		})
	}

	checkpoint := activationMarkerEvent(ActivationCheckpoint)
	if _, err := log.AppendActivationCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	beforeCheckpointConflict := readEvidenceBytes(t, path)
	checkpointNext := log.NextSequence()

	for name, mutate := range map[string]func(*Event){
		"activation identity": func(value *Event) {
			value.GrantID = "activation-b"
		},
		"checkpoint digest": func(value *Event) {
			value.MetadataHash = "sha256:other-checkpoint"
		},
		"capsule": func(value *Event) {
			value.CapsuleDigest = "sha256:other-capsule"
		},
		"policy": func(value *Event) {
			value.PolicyDigest = "sha256:other-policy"
		},
	} {
		t.Run("checkpoint "+name, func(t *testing.T) {
			conflicting := checkpoint
			mutate(&conflicting)
			if _, err := log.AppendActivationCheckpoint(conflicting); !errors.Is(
				err, ErrActivationMarkerConflict,
			) {
				t.Fatalf("conflicting checkpoint error=%v", err)
			}
			if log.NextSequence() != checkpointNext ||
				!bytes.Equal(readEvidenceBytes(t, path), beforeCheckpointConflict) {
				t.Fatal("conflicting activation checkpoint grew or changed the evidence log")
			}
		})
	}
}

func TestActivationCheckpointRequiresMatchingBegin(t *testing.T) {
	log, path, _ := newLog(t)
	defer log.Close()

	before := readEvidenceBytes(t, path)
	checkpoint := activationMarkerEvent(ActivationCheckpoint)
	if _, err := log.AppendActivationCheckpoint(checkpoint); !errors.Is(
		err, ErrActivationMarkerConflict,
	) {
		t.Fatalf("checkpoint-before-begin error=%v", err)
	}
	if log.NextSequence() != 1 ||
		!bytes.Equal(readEvidenceBytes(t, path), before) {
		t.Fatal("checkpoint without a begin marker grew or changed the evidence log")
	}
}

func TestActivationMarkerIndexesSurviveReopen(t *testing.T) {
	log, path, _ := newLog(t)
	private := append(ed25519.PrivateKey(nil), log.private...)
	begin := activationMarkerEvent(ActivationBegin)
	checkpoint := activationMarkerEvent(ActivationCheckpoint)

	firstBegin, err := log.AppendActivationBegin(begin)
	if err != nil {
		t.Fatal(err)
	}
	firstCheckpoint, err := log.AppendActivationCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, private, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	before := readEvidenceBytes(t, path)
	next := reopened.NextSequence()

	replayedBegin, err := reopened.AppendActivationBegin(begin)
	if err != nil {
		t.Fatal(err)
	}
	replayedCheckpoint, err := reopened.AppendActivationCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if replayedBegin != firstBegin || replayedCheckpoint != firstCheckpoint {
		t.Fatalf(
			"reopened marker receipts changed: begin=%#v checkpoint=%#v",
			replayedBegin, replayedCheckpoint,
		)
	}
	if reopened.NextSequence() != next ||
		!bytes.Equal(readEvidenceBytes(t, path), before) {
		t.Fatal("exact marker retries after reopen grew or changed the evidence log")
	}

	conflicting := checkpoint
	conflicting.MetadataHash = "sha256:other-checkpoint"
	if _, err := reopened.AppendActivationCheckpoint(conflicting); !errors.Is(
		err, ErrActivationMarkerConflict,
	) {
		t.Fatalf("reopened conflicting checkpoint error=%v", err)
	}
}

func TestActivationMarkerIndexRejectsDuplicateSignedMarkers(t *testing.T) {
	for _, test := range []struct {
		name       string
		markerType EventType
	}{
		{name: "begin", markerType: ActivationBegin},
		{name: "checkpoint", markerType: ActivationCheckpoint},
	} {
		t.Run(test.name, func(t *testing.T) {
			log, path, _ := newLog(t)
			private := append(ed25519.PrivateKey(nil), log.private...)
			begin := activationMarkerEvent(ActivationBegin)
			if _, err := log.appendLocked(begin); err != nil {
				t.Fatal(err)
			}
			marker := begin
			if test.markerType == ActivationCheckpoint {
				marker = activationMarkerEvent(ActivationCheckpoint)
			}
			if _, err := log.appendLocked(marker); err != nil {
				t.Fatal(err)
			}
			if test.markerType == ActivationCheckpoint {
				if _, err := log.appendLocked(marker); err != nil {
					t.Fatal(err)
				}
			}
			if err := log.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(
				path, private, "node-a", 1,
			); err == nil {
				_ = reopened.Close()
				t.Fatal("duplicate signed activation marker was accepted")
			}
		})
	}
}

func TestActivationMarkerRetriesFailClosedAfterOutOfBandCorruption(t *testing.T) {
	t.Run("tail tamper", func(t *testing.T) {
		log, path, _ := newLog(t)
		begin := activationMarkerEvent(ActivationBegin)
		if _, err := log.AppendActivationBegin(begin); err != nil {
			t.Fatal(err)
		}
		tamperEvidenceTailPreservingMetadata(t, path)

		if _, err := log.AppendActivationBegin(begin); err == nil {
			t.Fatal("exact activation begin retry accepted a tampered evidence tail")
		}
		if _, err := log.AppendActivationBegin(begin); err == nil ||
			!bytes.Contains([]byte(err.Error()), []byte("closed")) {
			t.Fatalf("second begin retry after tamper error=%v", err)
		}
	})

	t.Run("truncation", func(t *testing.T) {
		log, path, _ := newLog(t)
		begin := activationMarkerEvent(ActivationBegin)
		if _, err := log.AppendActivationBegin(begin); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, info.Size()-1); err != nil {
			t.Fatal(err)
		}

		if _, err := log.AppendActivationBegin(begin); err == nil {
			t.Fatal("exact activation begin retry accepted a truncated evidence log")
		}
		if _, err := log.AppendActivationBegin(begin); err == nil ||
			!bytes.Contains([]byte(err.Error()), []byte("closed")) {
			t.Fatalf("second begin retry after truncation error=%v", err)
		}
	})
}

func TestActivationMarkerScopesAreIndependent(t *testing.T) {
	log, _, _ := newLog(t)
	defer log.Close()

	scopes := []Event{
		activationMarkerEvent(ActivationBegin),
		activationMarkerEvent(ActivationBegin),
		activationMarkerEvent(ActivationBegin),
		activationMarkerEvent(ActivationBegin),
	}
	scopes[1].TenantID = "tenant-b"
	scopes[2].RuntimeRef = "runtime-b"
	scopes[3].Generation = 2

	for index, begin := range scopes {
		begin.GrantID += string(rune('a' + index))
		begin.MetadataHash += string(rune('a' + index))
		scopes[index] = begin
		if _, err := log.AppendActivationBegin(begin); err != nil {
			t.Fatalf("append independent begin %d: %v", index, err)
		}
	}
	for index, begin := range scopes {
		checkpoint := begin
		checkpoint.Type = ActivationCheckpoint
		checkpoint.Outcome = Committed
		checkpoint.MetadataHash = "sha256:checkpoint-" + string(rune('a'+index))
		if _, err := log.AppendActivationCheckpoint(checkpoint); err != nil {
			t.Fatalf("append independent checkpoint %d: %v", index, err)
		}
	}
	if log.NextSequence() != uint64(2*len(scopes)+1) {
		t.Fatalf(
			"next sequence=%d want %d",
			log.NextSequence(), 2*len(scopes)+1,
		)
	}
}

func activationMarkerEvent(kind EventType) Event {
	value := event(kind)
	value.GrantID = "activation-a"
	value.ErrorCode = ""
	if kind == ActivationBegin {
		value.Outcome = Allowed
		value.MetadataHash = "sha256:begin"
	} else {
		value.Outcome = Committed
		value.MetadataHash = "sha256:checkpoint"
	}
	return value
}

func readEvidenceBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
