package audit

import "testing"

func TestCVSSV3BaseScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
		ok     bool
	}{
		{"critical 9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"high 7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, true},
		{"moderate 6.1 scope changed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, true},
		{"low 2.6", "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.6, true},
		{"v3.0 supported", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"not v3 vector", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", 0, false},
		{"garbage", "nonsense", 0, false},
		{"missing metric", "CVSS:3.1/AV:N/AC:L", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cvssV3BaseScore(tt.vector)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("score = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverityFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0, ""},
		{2.6, "low"},
		{6.1, "moderate"},
		{7.5, "high"},
		{9.8, "critical"},
	}
	for _, tt := range tests {
		if got := severityFromScore(tt.score); got != tt.want {
			t.Errorf("severityFromScore(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestSeverityFromLabel(t *testing.T) {
	tests := map[string]string{
		"CRITICAL": "critical",
		"High":     "high",
		"moderate": "moderate",
		"MEDIUM":   "moderate",
		"low":      "low",
		"":         "",
		"bogus":    "",
	}
	for in, want := range tests {
		if got := severityFromLabel(in); got != want {
			t.Errorf("severityFromLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
