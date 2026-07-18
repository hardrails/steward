package influence

import (
	"errors"
	"strings"
	"testing"
)

func TestContextHeadIsGrantScopedAndDeterministic(t *testing.T) {
	grant := "grant-" + strings.Repeat("a", 64)
	genesis, err := Genesis("tenant-a", grant, 3)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Genesis("tenant-a", grant, 3)
	if err != nil || again != genesis || genesis.Sequence != 0 {
		t.Fatalf("genesis=%#v again=%#v err=%v", genesis, again, err)
	}
	receipt := "sha256:" + strings.Repeat("b", 64)
	advanced, err := Advance(genesis, receipt)
	if err != nil || advanced.Sequence != 1 || advanced.ChainHash == genesis.ChainHash {
		t.Fatalf("advanced=%#v err=%v", advanced, err)
	}
	if other, _ := Genesis("tenant-b", grant, 3); other.ChainHash == genesis.ChainHash {
		t.Fatal("tenant identity did not scope the context genesis")
	}
	if other, _ := Genesis("tenant-a", grant, 4); other.ChainHash == genesis.ChainHash {
		t.Fatal("generation did not scope the context genesis")
	}
}

func TestContextHeadRejectsMalformedAndExhaustedInputs(t *testing.T) {
	grant := "grant-" + strings.Repeat("a", 64)
	for _, test := range []struct {
		tenant     string
		grant      string
		generation uint64
	}{
		{"", grant, 1}, {"tenant", "grant-short", 1}, {"tenant", grant, 0},
	} {
		if _, err := Genesis(test.tenant, test.grant, test.generation); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Genesis(%q,%q,%d) err=%v", test.tenant, test.grant, test.generation, err)
		}
	}
	valid, _ := Genesis("tenant", grant, 1)
	mutations := []Head{
		{},
		{SchemaVersion: "steward.effect-context.v2", TenantID: valid.TenantID, GrantID: valid.GrantID, Generation: 1, ChainHash: valid.ChainHash},
		{SchemaVersion: SchemaV1, TenantID: valid.TenantID, GrantID: valid.GrantID, Generation: 1, ChainHash: "sha256:nope"},
	}
	for _, mutation := range mutations {
		if err := mutation.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Validate(%#v) err=%v", mutation, err)
		}
	}
	if _, err := Advance(valid, "sha256:bad"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid receipt err=%v", err)
	}
	valid.Sequence = ^uint64(0)
	if _, err := Advance(valid, "sha256:"+strings.Repeat("b", 64)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("exhausted sequence err=%v", err)
	}
}
