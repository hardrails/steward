package controlprotocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeExecutorPollResponseV3KeepsMalformedDeliveryIsolated(t *testing.T) {
	raw := []byte(`{"protocol_version":3,"deliveries":[{"delivery_id":"bad","unexpected":true},{"delivery_id":"good","delivery_generation":1,"command_id":"command","command_digest":"sha256:` + strings.Repeat("a", 64) + `","command_dsse_base64":"e30="}]}`)
	response, err := DecodeExecutorPollResponseV3(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Deliveries) != 2 {
		t.Fatalf("deliveries=%d", len(response.Deliveries))
	}
	if _, err := DecodeExecutorDeliveryV3(response.Deliveries[0]); err == nil {
		t.Fatal("malformed delivery was accepted")
	}
	if delivery, err := DecodeExecutorDeliveryV3(response.Deliveries[1]); err != nil || delivery.DeliveryID != "good" {
		t.Fatalf("valid sibling=%#v err=%v", delivery, err)
	}
}

func TestDecodeExecutorPollResponseV3RejectsContainerAmbiguity(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate protocol": `{"protocol_version":3,"protocol_version":3,"deliveries":[]}`,
		"unknown field":      `{"protocol_version":3,"deliveries":[],"commands":[]}`,
		"null deliveries":    `{"protocol_version":3,"deliveries":null}`,
		"trailing JSON":      `{"protocol_version":3,"deliveries":[]} {}`,
		"wrong protocol":     `{"protocol_version":2,"deliveries":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExecutorPollResponseV3([]byte(raw), len(raw)); err == nil {
				t.Fatal("ambiguous poll response was accepted")
			}
		})
	}
}

func TestExecutorDeliveryAndReportValidation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	delivery := ExecutorDeliveryV3{
		DeliveryID: "delivery", DeliveryGeneration: 1, CommandID: "command",
		CommandDigest: digest, CommandDSSEBase64: "e30=",
	}
	if err := delivery.Validate(); err != nil {
		t.Fatal(err)
	}
	report := ExecutorReportV3{
		ProtocolVersion: ExecutorProtocolV3, DeliveryID: delivery.DeliveryID,
		DeliveryGeneration: delivery.DeliveryGeneration, CommandID: delivery.CommandID,
		CommandDigest: digest, Status: ExecutorStatusRejected, ReportedStatus: "failed",
		Result: ExecutorReportResultV3{Error: "rejected"},
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(report)
	if err != nil || !json.Valid(encoded) {
		t.Fatalf("marshal report: %s %v", encoded, err)
	}
	for _, invalid := range []string{
		"SHA256:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("g", 64),
	} {
		if ValidSHA256Digest(invalid) {
			t.Fatalf("invalid digest accepted: %q", invalid)
		}
	}
}

func TestExecutorDeliveryIDIsCanonicalAndIdentityBound(t *testing.T) {
	got, err := ExecutorDeliveryID("tenant-a", "node-1", "command-1")
	if err != nil {
		t.Fatal(err)
	}
	const want = "delivery-02519f7270ebb1adc5355b772ed5c5f26411e856735e8bd4076ca7094196f8c0"
	if got != want {
		t.Fatalf("delivery ID = %q, want %q", got, want)
	}
	for _, identity := range [][3]string{
		{"tenant-b", "node-1", "command-1"},
		{"tenant-a", "node-2", "command-1"},
		{"tenant-a", "node-1", "command-2"},
	} {
		candidate, err := ExecutorDeliveryID(identity[0], identity[1], identity[2])
		if err != nil || candidate == got {
			t.Fatalf("identity %#v produced delivery ID %q, err=%v", identity, candidate, err)
		}
	}
	if _, err := ExecutorDeliveryID("", "node-1", "command-1"); err == nil {
		t.Fatal("empty tenant identity produced a delivery ID")
	}
}
