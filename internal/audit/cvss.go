package audit

import (
	"math"
	"strings"
)

// severity buckets, sharing npm's vocabulary ("moderate" for CVSS medium).
// CVSS sources only ever give us a score or a textual label; both map here.

// severityFromLabel maps a textual severity (OSV database_specific.severity,
// GitHub advisory severity) onto our vocabulary. Returns "" if unrecognised.
func severityFromLabel(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "moderate"
	case "low":
		return "low"
	default:
		return ""
	}
}

// severityFromScore buckets a CVSS base score per the FIRST qualitative scale.
func severityFromScore(score float64) string {
	switch {
	case score <= 0:
		return ""
	case score < 4.0:
		return "low"
	case score < 7.0:
		return "moderate"
	case score < 9.0:
		return "high"
	default:
		return "critical"
	}
}

// cvssV3BaseScore computes the CVSS v3.0/3.1 base score from a vector string
// (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"). Returns ok=false if the
// vector is malformed or not a v3 vector. v2/v4 vectors fall through to ok=false
// and the caller relies on the textual label instead.
func cvssV3BaseScore(vector string) (score float64, ok bool) {
	m := parseCVSSVector(vector)
	if m == nil {
		return 0, false
	}

	av, ok1 := cvssWeight(metricAV, m["AV"], "")
	ac, ok2 := cvssWeight(metricAC, m["AC"], "")
	ui, ok3 := cvssWeight(metricUI, m["UI"], "")
	c, ok4 := cvssWeight(metricCIA, m["C"], "")
	i, ok5 := cvssWeight(metricCIA, m["I"], "")
	a, ok6 := cvssWeight(metricCIA, m["A"], "")
	scope := m["S"]
	pr, ok7 := cvssWeight(metricPR, m["PR"], scope)
	valid := ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && (scope == "U" || scope == "C")
	if !valid {
		return 0, false
	}

	isc := 1 - (1-c)*(1-i)*(1-a)
	changed := scope == "C"

	var impact float64
	if changed {
		impact = 7.52*(isc-0.029) - 3.25*math.Pow(isc-0.02, 15)
	} else {
		impact = 6.42 * isc
	}
	if impact <= 0 {
		return 0, true
	}

	exploit := 8.22 * av * ac * pr * ui
	if changed {
		return cvssRoundUp(math.Min(1.08*(impact+exploit), 10)), true
	}
	return cvssRoundUp(math.Min(impact+exploit, 10)), true
}

// parseCVSSVector parses a "CVSS:3.x/Metric:Value/..." string into a metric map.
// Returns nil if the prefix isn't a v3 vector.
func parseCVSSVector(vector string) map[string]string {
	parts := strings.Split(vector, "/")
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return nil
	}
	m := make(map[string]string, len(parts))
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if ok {
			m[k] = v
		}
	}
	return m
}

type cvssMetric int

const (
	metricAV cvssMetric = iota
	metricAC
	metricUI
	metricPR
	metricCIA
)

// cvssWeight returns the numeric weight for a metric value. PR depends on scope.
func cvssWeight(metric cvssMetric, value, scope string) (float64, bool) {
	switch metric {
	case metricAV:
		return lookup(value, map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	case metricAC:
		return lookup(value, map[string]float64{"L": 0.77, "H": 0.44})
	case metricUI:
		return lookup(value, map[string]float64{"N": 0.85, "R": 0.62})
	case metricCIA:
		return lookup(value, map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	case metricPR:
		if scope == "C" {
			return lookup(value, map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5})
		}
		return lookup(value, map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27})
	default:
		return 0, false
	}
}

func lookup(value string, table map[string]float64) (float64, bool) {
	w, ok := table[value]
	return w, ok
}

// cvssRoundUp implements the CVSS v3.1 roundup function (round to one decimal,
// always up), guarding against binary floating-point representation error.
func cvssRoundUp(x float64) float64 {
	scaled := int(math.Round(x * 100000))
	if scaled%10000 == 0 {
		return float64(scaled) / 100000
	}
	return (math.Floor(float64(scaled)/10000) + 1) / 10
}
