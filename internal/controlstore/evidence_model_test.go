package controlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

func TestEvidenceWitnessStateRoundTripAndLegacyMigration(t *testing.T) {
	current, limits := populatedControlState(t)
	node := firstNode(current)
	witness := testEvidenceWitness(t, node)
	node.Evidence = &witness
	current.nodes[node.ID] = node

	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeState(raw, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.nodes[node.ID].Evidence, &witness) {
		t.Fatalf("witness round trip = %#v", decoded.nodes[node.ID].Evidence)
	}

	legacy := current.clone()
	legacyNode := legacy.nodes[node.ID]
	legacyNode.Evidence = nil
	legacy.nodes[node.ID] = legacyNode
	legacyRaw, err := encodeState(legacy, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(legacyRaw, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Version = stateFormatMinReadVersion
	snapshot.Captures = nil
	snapshot.Deployments = nil
	for index := range snapshot.Commands {
		snapshot.Commands[index].DeliveryProtocol = 0
	}
	legacyRaw, err = json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := decodeState(legacyRaw, limits.MaxStateBytes)
	if err != nil || migrated.nodes[node.ID].Evidence != nil {
		t.Fatalf("legacy migration evidence=%#v err=%v", migrated.nodes[node.ID].Evidence, err)
	}

	snapshot.Nodes[0].Evidence = &witness
	legacyWithWitness, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(legacyWithWitness, limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot smuggled in witness state")
	}
	legacyNode.Evidence = &witness
	if _, err := applyTransaction(legacy, transaction{Version: transactionFormatMinReadVersion, Mutations: []mutation{{Kind: mutationNode, Node: &legacyNode}}}); err == nil {
		t.Fatal("legacy WAL transaction smuggled in witness state")
	}
}

func TestEvidenceWitnessValidationRejectsIdentityCoordinateAndKeyReuse(t *testing.T) {
	baseline, limits := populatedControlState(t)
	node := firstNode(baseline)
	valid := testEvidenceWitness(t, node)

	mutations := []func(*EvidenceWitness){
		func(value *EvidenceWitness) {
			value.IdentityProof.SignatureBase64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
		func(value *EvidenceWitness) { value.ReceiptNodeID = "node-other" },
		func(value *EvidenceWitness) { value.Epoch = 0 },
		func(value *EvidenceWitness) { value.PublicKeyBase64 += "=" },
		func(value *EvidenceWitness) { value.KeyID = "wrong" },
		func(value *EvidenceWitness) { value.PublicKeyDigest = digestBytes([]byte("wrong")) },
		func(value *EvidenceWitness) { value.ChainHash = digestBytes([]byte("not-genesis")) },
		func(value *EvidenceWitness) { value.AdvancedAt = node.CreatedAt },
		func(value *EvidenceWitness) { value.RecordsAccepted = 1 },
		func(value *EvidenceWitness) { value.Finding = &EvidenceFinding{Count: 1} },
	}
	for index, mutate := range mutations {
		candidate := baseline.clone()
		changedNode := candidate.nodes[node.ID]
		changed := valid
		mutate(&changed)
		changedNode.Evidence = &changed
		candidate.nodes[node.ID] = changedNode
		if err := validateState(candidate, limits); err == nil {
			t.Fatalf("invalid witness mutation %d was accepted: %#v", index, changed)
		}
	}

	sharedPublic, sharedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	candidate := baseline.clone()
	first := candidate.nodes[node.ID]
	firstWitness := testEvidenceWitnessWithKey(t, first, sharedPublic, sharedPrivate)
	first.Evidence = &firstWitness
	candidate.nodes[first.ID] = first
	second := cloneNode(first)
	second.ID = "node-second"
	secondWitness := testEvidenceWitnessWithKey(t, second, sharedPublic, sharedPrivate)
	second.Evidence = &secondWitness
	candidate.nodes[second.ID] = second
	if err := validateState(candidate, limits); err == nil {
		t.Fatal("one evidence public key was accepted for two historical nodes")
	}
}

func TestAdvancedEvidenceWitnessAndBoundedFindingValidate(t *testing.T) {
	current, limits := populatedControlState(t)
	node := firstNode(current)
	witness := testEvidenceWitness(t, node)
	pinned, err := parseTimestamp(witness.PinnedAt)
	if err != nil {
		t.Fatal(err)
	}
	witness.Sequence = 2
	witness.ChainHash = digestBytes([]byte("derived evidence head"))
	witness.AdvancedAt = canonicalTimestamp(pinned.Add(time.Minute))
	witness.RecordsAccepted = 2
	witness.LastBatchStart = 1
	witness.LastBatchEnd = 2
	witness.LastBatchDigest = digestBytes([]byte("exact signed batch"))
	witness.Finding = &EvidenceFinding{
		FirstReason: EvidenceRollback, FirstComparedSequence: 2, FirstComparedChainHash: witness.ChainHash,
		FirstSequence: 0, FirstChainHash: zeroEvidenceHash(),
		FirstObservedAt: canonicalTimestamp(pinned.Add(2 * time.Minute)),
		LastReason:      EvidenceFork, LastComparedSequence: 1, LastComparedChainHash: digestBytes([]byte("compared")),
		LastSequence: 1, LastChainHash: digestBytes([]byte("fork")),
		LastObservedAt: canonicalTimestamp(pinned.Add(3 * time.Minute)), Count: 2,
	}
	node.Evidence = &witness
	current.nodes[node.ID] = node
	if err := validateState(current, limits); err != nil {
		t.Fatalf("valid advanced witness: %v", err)
	}
	for name, mutate := range map[string]func(*EvidenceFinding){
		"missing comparison": func(value *EvidenceFinding) {
			value.FirstComparedSequence = 0
			value.FirstComparedChainHash = ""
		},
		"rollback not below comparison": func(value *EvidenceFinding) {
			value.FirstSequence = value.FirstComparedSequence
			value.FirstChainHash = value.FirstComparedChainHash
		},
		"fork identical to comparison": func(value *EvidenceFinding) {
			value.LastSequence = value.LastComparedSequence
			value.LastChainHash = value.LastComparedChainHash
		},
		"comparison beyond current": func(value *EvidenceFinding) {
			value.LastComparedSequence = witness.Sequence + 1
			value.LastComparedChainHash = digestBytes([]byte("future comparison"))
			value.LastSequence = value.LastComparedSequence
			value.LastChainHash = digestBytes([]byte("future fork"))
		},
		"equal-sequence comparison conflicts with current": func(value *EvidenceFinding) {
			value.FirstComparedSequence = witness.Sequence
			value.FirstComparedChainHash = digestBytes([]byte("foreign current"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := current.clone()
			changed := candidate.nodes[node.ID]
			mutate(changed.Evidence.Finding)
			candidate.nodes[node.ID] = changed
			if err := validateState(candidate, limits); err == nil {
				t.Fatal("invalid historical evidence finding was accepted")
			}
		})
	}
}

func testEvidenceWitness(t *testing.T, node Node) EvidenceWitness {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testEvidenceWitnessWithKey(t, node, public, private)
}

func testEvidenceWitnessWithKey(t *testing.T, node Node, public ed25519.PublicKey, private ed25519.PrivateKey) EvidenceWitness {
	t.Helper()
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		"control-test", "enrollment-test", node.ID, node.ID, 1, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, private)
	if err != nil {
		t.Fatal(err)
	}
	return EvidenceWitness{
		IdentityProof: proof,
		ReceiptNodeID: node.ID, Epoch: 1,
		PublicKeyBase64: base64.StdEncoding.EncodeToString(public), KeyID: evidence.KeyID(public),
		PublicKeyDigest: digestBytes(public), PinnedAt: node.CreatedAt,
		ChainHash: zeroEvidenceHash(),
	}
}

func zeroEvidenceHash() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
