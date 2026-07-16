package controlprotocol

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/dsse"
)

func TestDecodeExecutorPollResponseV4KeepsMalformedDeliveryIsolated(t *testing.T) {
	raw := []byte(`{"protocol_version":4,"deliveries":[{"delivery_id":"bad","unexpected":true},{"delivery_id":"good","delivery_generation":1,"command_id":"command","command_digest":"sha256:` + strings.Repeat("a", 64) + `","command_dsse_base64":"e30="}]}`)
	response, err := DecodeExecutorPollResponseV4(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Deliveries) != 2 {
		t.Fatalf("deliveries=%d", len(response.Deliveries))
	}
	if _, err := DecodeExecutorDeliveryV4(response.Deliveries[0]); err == nil {
		t.Fatal("malformed delivery was accepted")
	}
	if delivery, err := DecodeExecutorDeliveryV4(response.Deliveries[1]); err != nil || delivery.DeliveryID != "good" {
		t.Fatalf("valid sibling=%#v err=%v", delivery, err)
	}
}

func TestDecodeExecutorPollResponseV4RejectsContainerAmbiguity(t *testing.T) {
	tooMany := make([]json.RawMessage, MaxExecutorDeliveries+1)
	for index := range tooMany {
		tooMany[index] = json.RawMessage(`{}`)
	}
	tooManyRaw, err := json.Marshal(ExecutorPollResponseV4{
		ProtocolVersion: ExecutorProtocolV4,
		Deliveries:      tooMany,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"empty":              nil,
		"duplicate protocol": []byte(`{"protocol_version":4,"protocol_version":4,"deliveries":[]}`),
		"unknown field":      []byte(`{"protocol_version":4,"deliveries":[],"commands":[]}`),
		"null deliveries":    []byte(`{"protocol_version":4,"deliveries":null}`),
		"trailing JSON":      []byte(`{"protocol_version":4,"deliveries":[]} {}`),
		"wrong protocol":     []byte(`{"protocol_version":3,"deliveries":[]}`),
		"too many":           tooManyRaw,
	} {
		t.Run(name, func(t *testing.T) {
			limit := len(raw)
			if limit == 0 {
				limit = 1
			}
			if _, err := DecodeExecutorPollResponseV4(raw, limit); err == nil {
				t.Fatal("ambiguous poll response was accepted")
			}
		})
	}
	if _, err := DecodeExecutorPollResponseV4(
		[]byte(`{"protocol_version":4,"deliveries":[]}`),
		1,
	); err == nil {
		t.Fatal("response above the caller's byte limit was accepted")
	}
}

func TestExecutorAdmissionProjectionV1AcceptsMinimalAndFullShapes(t *testing.T) {
	minimal := minimalAdmissionProjection()
	if err := minimal.Validate(); err != nil {
		t.Fatalf("minimal projection: %v", err)
	}

	full := fullAdmissionProjection()
	if err := full.Validate(); err != nil {
		t.Fatalf("full projection: %v", err)
	}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ExecutorAdmissionProjectionV1
	if err := dsse.DecodeStrictInto(raw, MaxExecutorReportBytes, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("round-tripped projection: %v", err)
	}
}

func TestExecutorAdmissionProjectionV1RejectsInvalidIdentity(t *testing.T) {
	for name, mutate := range map[string]func(*ExecutorAdmissionProjectionV1){
		"schema":          func(value *ExecutorAdmissionProjectionV1) { value.SchemaVersion = "other" },
		"runtime prefix":  func(value *ExecutorAdmissionProjectionV1) { value.RuntimeRef = "runtime-" + strings.Repeat("a", 64) },
		"runtime length":  func(value *ExecutorAdmissionProjectionV1) { value.RuntimeRef += "a" },
		"runtime hex":     func(value *ExecutorAdmissionProjectionV1) { value.RuntimeRef = "executor-" + strings.Repeat("A", 64) },
		"status":          func(value *ExecutorAdmissionProjectionV1) { value.Status = "paused" },
		"capsule digest":  func(value *ExecutorAdmissionProjectionV1) { value.CapsuleDigest = "sha256:" + strings.Repeat("A", 64) },
		"policy digest":   func(value *ExecutorAdmissionProjectionV1) { value.PolicyDigest = "" },
		"generation":      func(value *ExecutorAdmissionProjectionV1) { value.Generation = 0 },
		"evidence length": func(value *ExecutorAdmissionProjectionV1) { value.EvidenceKeyID = strings.Repeat("d", 31) },
		"evidence hex":    func(value *ExecutorAdmissionProjectionV1) { value.EvidenceKeyID = strings.Repeat("D", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			value := minimalAdmissionProjection()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatalf("invalid projection was accepted: %#v", value)
			}
		})
	}
}

func TestExecutorAdmissionProjectionV1RejectsInvalidTopology(t *testing.T) {
	for name, mutate := range map[string]func(*ExecutorAdmissionProjectionV1){
		"invalid grant": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = "grant-" + strings.Repeat("A", 64)
		},
		"topology without grant": func(value *ExecutorAdmissionProjectionV1) {
			value.ServicePath = "/v1/services/grant-" + strings.Repeat("e", 64) + "/"
		},
		"route digest without grant": func(value *ExecutorAdmissionProjectionV1) {
			value.RoutePolicyDigest = digest("f")
		},
		"invalid route digest": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.RoutePolicyDigest = "sha256:" + strings.Repeat("F", 64)
		},
		"service path mismatch": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ServicePath = "/v1/services/grant-" + strings.Repeat("f", 64) + "/"
		},
		"service ID without path": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ServiceID = "agent-api"
			value.TaskAuthorities = []ExecutorTaskAuthorityV1{taskAuthority("approver-a", "a")}
			value.RoutePolicyDigest = digest("f")
		},
		"service ID without authorities": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ServicePath = servicePath()
			value.ServiceID = "agent-api"
		},
		"authorities without service ID": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ServicePath = servicePath()
			value.TaskAuthorities = []ExecutorTaskAuthorityV1{taskAuthority("approver-a", "a")}
			value.RoutePolicyDigest = digest("f")
		},
		"empty authorities": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ServicePath = servicePath()
			value.TaskAuthorities = []ExecutorTaskAuthorityV1{}
		},
		"invalid service ID": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ServicePath = servicePath()
			value.ServiceID = "-agent"
			value.TaskAuthorities = []ExecutorTaskAuthorityV1{taskAuthority("approver-a", "a")}
			value.RoutePolicyDigest = digest("f")
		},
		"egress endpoint without IDs": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.EgressProxy = executorEgressProxyV1
		},
		"egress IDs without endpoint": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.EgressRouteIDs = []string{"public-web"}
			value.RoutePolicyDigest = digest("f")
		},
		"invalid egress endpoint": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.EgressProxy = "http://127.0.0.1:8082"
			value.EgressRouteIDs = []string{"public-web"}
			value.RoutePolicyDigest = digest("f")
		},
		"connector endpoint without IDs": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ConnectorURL = executorConnectorURLV1
		},
		"connector IDs without endpoint": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ConnectorIDs = []string{"issues.create"}
			value.RoutePolicyDigest = digest("f")
		},
		"invalid connector endpoint": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ConnectorURL = "https://connector.example"
			value.ConnectorIDs = []string{"issues.create"}
			value.RoutePolicyDigest = digest("f")
		},
		"policy-bearing grant without digest": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.EgressProxy = executorEgressProxyV1
			value.EgressRouteIDs = []string{"public-web"}
		},
		"activation ID without digest": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ActivationID = "activation-1"
		},
		"activation digest without ID": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ActivationBeginDigest = digest("f")
		},
		"activation without grant": func(value *ExecutorAdmissionProjectionV1) {
			value.ActivationID = "activation-1"
			value.ActivationBeginDigest = digest("f")
		},
		"invalid activation ID": func(value *ExecutorAdmissionProjectionV1) {
			value.GrantID = grantID()
			value.ActivationID = "-activation"
			value.ActivationBeginDigest = digest("f")
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := minimalAdmissionProjection()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatalf("invalid projection was accepted: %#v", value)
			}
		})
	}
}

func TestExecutorAdmissionProjectionV1RejectsNonCanonicalBoundedCollections(t *testing.T) {
	tooManyAuthorities := make([]ExecutorTaskAuthorityV1, maxExecutorTaskAuthorities+1)
	for index := range tooManyAuthorities {
		tooManyAuthorities[index] = taskAuthority(
			"approver-"+string(rune('a'+index)),
			string(rune('a'+index)),
		)
	}
	tooManyRoutes := make([]string, maxExecutorAdmissionRouteOrConnectorIDs+1)
	for index := range tooManyRoutes {
		tooManyRoutes[index] = "route-" + string(rune('a'+index))
	}
	for name, mutate := range map[string]func(*ExecutorAdmissionProjectionV1){
		"too many authorities": func(value *ExecutorAdmissionProjectionV1) {
			value.TaskAuthorities = tooManyAuthorities
		},
		"unsorted authority IDs": func(value *ExecutorAdmissionProjectionV1) {
			value.TaskAuthorities = []ExecutorTaskAuthorityV1{
				taskAuthority("approver-b", "b"),
				taskAuthority("approver-a", "a"),
			}
		},
		"duplicate authority ID": func(value *ExecutorAdmissionProjectionV1) {
			value.TaskAuthorities = []ExecutorTaskAuthorityV1{
				taskAuthority("approver-a", "a"),
				taskAuthority("approver-a", "b"),
			}
		},
		"duplicate authority key": func(value *ExecutorAdmissionProjectionV1) {
			value.TaskAuthorities = []ExecutorTaskAuthorityV1{
				taskAuthority("approver-a", "a"),
				taskAuthority("approver-b", "a"),
			}
		},
		"invalid authority ID": func(value *ExecutorAdmissionProjectionV1) {
			value.TaskAuthorities = []ExecutorTaskAuthorityV1{taskAuthority("-approver", "a")}
		},
		"invalid authority base64": func(value *ExecutorAdmissionProjectionV1) {
			value.TaskAuthorities = []ExecutorTaskAuthorityV1{{
				KeyID:     "approver-a",
				PublicKey: "not-base64",
			}}
		},
		"noncanonical authority base64": func(value *ExecutorAdmissionProjectionV1) {
			value.TaskAuthorities = []ExecutorTaskAuthorityV1{{
				KeyID:     "approver-a",
				PublicKey: base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))),
			}}
		},
		"too many routes": func(value *ExecutorAdmissionProjectionV1) {
			value.EgressRouteIDs = tooManyRoutes
		},
		"empty routes": func(value *ExecutorAdmissionProjectionV1) {
			value.EgressRouteIDs = []string{}
		},
		"unsorted routes": func(value *ExecutorAdmissionProjectionV1) {
			value.EgressRouteIDs = []string{"route-b", "route-a"}
		},
		"duplicate routes": func(value *ExecutorAdmissionProjectionV1) {
			value.EgressRouteIDs = []string{"route-a", "route-a"}
		},
		"invalid route": func(value *ExecutorAdmissionProjectionV1) {
			value.EgressRouteIDs = []string{"-route"}
		},
		"empty connectors": func(value *ExecutorAdmissionProjectionV1) {
			value.ConnectorIDs = []string{}
		},
		"unsorted connectors": func(value *ExecutorAdmissionProjectionV1) {
			value.ConnectorIDs = []string{"issues.update", "issues.create"}
		},
		"duplicate connectors": func(value *ExecutorAdmissionProjectionV1) {
			value.ConnectorIDs = []string{"issues.create", "issues.create"}
		},
		"invalid connector": func(value *ExecutorAdmissionProjectionV1) {
			value.ConnectorIDs = []string{"issues/create"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := fullAdmissionProjection()
			mutate(&value)
			if value.EgressRouteIDs != nil {
				value.EgressProxy = executorEgressProxyV1
			}
			if value.ConnectorIDs != nil {
				value.ConnectorURL = executorConnectorURLV1
			}
			if err := value.Validate(); err == nil {
				t.Fatalf("invalid projection was accepted: %#v", value)
			}
		})
	}
}

func TestExecutorReportV4ValidationAndV3Separation(t *testing.T) {
	report := validExecutorReportV4()
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeExecutorReportV4(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Result.Admission == nil ||
		decoded.Result.Admission.RuntimeRef != report.Result.RuntimeRef {
		t.Fatalf("decoded report lost admission: %#v", decoded)
	}

	v3Raw := []byte(strings.Replace(
		string(raw),
		`"protocol_version":4`,
		`"protocol_version":3`,
		1,
	))
	var v3 ExecutorReportV3
	if err := dsse.DecodeStrictInto(v3Raw, MaxExecutorReportBytes, &v3); err == nil {
		t.Fatal("protocol-3 strict decoder accepted an admission projection")
	}

	v3 = ExecutorReportV3{
		ProtocolVersion:    ExecutorProtocolV3,
		DeliveryID:         report.DeliveryID,
		DeliveryGeneration: report.DeliveryGeneration,
		CommandID:          report.CommandID,
		CommandDigest:      report.CommandDigest,
		Status:             ExecutorStatusDone,
		ReportedStatus:     "stopped",
		ClaimGeneration:    report.ClaimGeneration,
		Result: ExecutorReportResultV3{
			RuntimeRef: report.Result.RuntimeRef,
		},
	}
	if err := v3.Validate(); err != nil {
		t.Fatalf("valid v3 report regressed: %v", err)
	}
	v3.ProtocolVersion = ExecutorProtocolV4
	if err := v3.Validate(); err == nil {
		t.Fatal("protocol-3 validator accepted a protocol-4 report")
	}
}

func TestExecutorReportV4RejectsInvalidAdmissionCorrelation(t *testing.T) {
	for name, mutate := range map[string]func(*ExecutorReportV4){
		"protocol": func(value *ExecutorReportV4) {
			value.ProtocolVersion = ExecutorProtocolV3
		},
		"claim generation": func(value *ExecutorReportV4) {
			value.ClaimGeneration = 0
		},
		"failed": func(value *ExecutorReportV4) {
			value.Status = ExecutorStatusFailed
		},
		"error code": func(value *ExecutorReportV4) {
			value.ErrorCode = "unexpected"
		},
		"error": func(value *ExecutorReportV4) {
			value.Result.Error = "unexpected"
		},
		"replayed": func(value *ExecutorReportV4) {
			value.Result.Replayed = true
		},
		"absent": func(value *ExecutorReportV4) {
			value.Result.Absent = true
		},
		"runtime mismatch": func(value *ExecutorReportV4) {
			value.Result.RuntimeRef = "executor-" + strings.Repeat("b", 64)
		},
		"created reported running": func(value *ExecutorReportV4) {
			value.ReportedStatus = "running"
		},
		"running reported stopped": func(value *ExecutorReportV4) {
			value.Result.Admission.Status = "running"
		},
		"invalid projection": func(value *ExecutorReportV4) {
			value.Result.Admission.PolicyDigest = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := validExecutorReportV4()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatalf("invalid report was accepted: %#v", value)
			}
		})
	}
}

func TestExecutorReportV4RejectsStrictJSONAmbiguityAndEncodedOverflow(t *testing.T) {
	validRaw, err := json.Marshal(validExecutorReportV4())
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), validRaw[:len(validRaw)-1]...), []byte(`,"unexpected":true}`)...)
	duplicate := []byte(strings.Replace(
		string(validRaw),
		`"protocol_version":4`,
		`"protocol_version":4,"protocol_version":4`,
		1,
	))
	for name, raw := range map[string][]byte{
		"unknown":   unknown,
		"duplicate": duplicate,
		"trailing":  append(append([]byte(nil), validRaw...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExecutorReportV4(raw); err == nil {
				t.Fatal("ambiguous report was accepted")
			}
		})
	}

	overflow := validExecutorReportV4()
	overflow.Result.Admission = nil
	overflow.Result.RuntimeRef = strings.Repeat("\x00", 1024)
	overflow.Result.Error = strings.Repeat("\x00", 4096)
	overflow.ErrorCode = strings.Repeat("\x00", 128)
	if err := overflow.Validate(); err == nil {
		t.Fatal("encoded report above the protocol byte cap was accepted")
	}
	raw, err := json.Marshal(overflow)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= MaxExecutorReportBytes {
		t.Fatalf("overflow fixture contains %d bytes, want more than %d", len(raw), MaxExecutorReportBytes)
	}
	if _, err := DecodeExecutorReportV4(raw); err == nil {
		t.Fatal("oversized encoded report was decoded")
	}
}

func TestExecutorReportV4WithoutAdmissionRetainsTerminalCompatibility(t *testing.T) {
	report := validExecutorReportV4()
	report.Status = ExecutorStatusRejected
	report.ReportedStatus = "failed"
	report.ClaimGeneration = 0
	report.ErrorCode = "executor_command_rejected"
	report.Result = ExecutorReportResultV4{Error: "rejected before the handler"}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
}

func minimalAdmissionProjection() ExecutorAdmissionProjectionV1 {
	return ExecutorAdmissionProjectionV1{
		SchemaVersion: ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    "executor-" + strings.Repeat("a", 64),
		Status:        "created",
		CapsuleDigest: digest("b"),
		PolicyDigest:  digest("c"),
		Generation:    1,
		EvidenceKeyID: strings.Repeat("d", 32),
	}
}

func fullAdmissionProjection() ExecutorAdmissionProjectionV1 {
	value := minimalAdmissionProjection()
	value.GrantID = grantID()
	value.ServicePath = servicePath()
	value.ServiceID = "agent-api"
	value.TaskAuthorities = []ExecutorTaskAuthorityV1{
		taskAuthority("approver-a", "a"),
		taskAuthority("approver-b", "b"),
	}
	value.EgressProxy = executorEgressProxyV1
	value.EgressRouteIDs = []string{"public-web", "vendor-api"}
	value.ConnectorURL = executorConnectorURLV1
	value.ConnectorIDs = []string{"git.read", "issues.create"}
	value.RoutePolicyDigest = digest("f")
	value.ActivationID = "activation-1"
	value.ActivationBeginDigest = digest("0")
	return value
}

func validExecutorReportV4() ExecutorReportV4 {
	projection := fullAdmissionProjection()
	return ExecutorReportV4{
		ProtocolVersion:    ExecutorProtocolV4,
		DeliveryID:         "delivery-1",
		DeliveryGeneration: 1,
		CommandID:          "command-1",
		CommandDigest:      digest("a"),
		Status:             ExecutorStatusDone,
		ReportedStatus:     "stopped",
		ClaimGeneration:    1,
		Result: ExecutorReportResultV4{
			RuntimeRef: projection.RuntimeRef,
			Admission:  &projection,
		},
	}
}

func taskAuthority(keyID, fill string) ExecutorTaskAuthorityV1 {
	return ExecutorTaskAuthorityV1{
		KeyID:     keyID,
		PublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat(fill, 32))),
	}
}

func digest(fill string) string {
	return "sha256:" + strings.Repeat(fill, 64)
}

func grantID() string {
	return "grant-" + strings.Repeat("e", 64)
}

func servicePath() string {
	return "/v1/services/" + grantID() + "/"
}
