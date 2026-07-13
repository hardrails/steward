package taskprotocol

import "testing"

func TestParseReportAcceptsBoundedLifecycleVocabulary(t *testing.T) {
	for _, status := range []Status{StatusQueued, StatusRunning, StatusCompleted, StatusFailed, StatusCancelled} {
		raw := []byte(`{"run_id":"run_0123456789abcdef","status":"` + string(status) + `","result":{"ok":true}}`)
		report, err := ParseReport(raw, len(raw), "run_0123456789abcdef")
		if err != nil || report.RunID != "run_0123456789abcdef" || report.Status != status || report.Status.Terminal() !=
			(status == StatusCompleted || status == StatusFailed || status == StatusCancelled) {
			t.Fatalf("status=%q report=%#v terminal=%t err=%v", status, report, report.Status.Terminal(), err)
		}
	}
}

func TestParseReportRejectsAmbiguousOrMismatchedInput(t *testing.T) {
	tests := []string{
		`{"run_id":"run_other","status":"running"}`,
		`{"run_id":"run_expected","status":"succeeded"}`,
		`{"run_id":"run_expected"}`,
		`{"run_id":"run_expected","status":"queued","status":"running"}`,
		`{"run_id":"run_expected","status":"running","result":{"x":1,"x":2}}`,
		`[{"run_id":"run_expected","status":"running"}]`,
		`{"run_id":"run_expected","status":"running"} {}`,
	}
	for _, raw := range tests {
		if _, err := ParseReport([]byte(raw), len(raw), "run_expected"); err == nil {
			t.Fatalf("invalid report accepted: %s", raw)
		}
	}
	if _, err := ParseReport([]byte(`{"run_id":"run_expected","status":"running"}`), MaxReportBytes+1, "run_expected"); err == nil {
		t.Fatal("oversized policy accepted")
	}
}
