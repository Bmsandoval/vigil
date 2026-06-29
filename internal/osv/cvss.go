package osv

import (
	"math"
	"strings"
)

// CVSSBaseScore computes the CVSS v3.0/3.1 base score from a vector string.
// It returns 0 for vectors it cannot parse (including CVSS v4, which uses a
// different formula); callers fall back to the qualitative label in that case.
func CVSSBaseScore(vector string) float64 {
	if !strings.HasPrefix(vector, "CVSS:3") {
		return 0
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			m[k] = v
		}
	}

	av := pick(map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, m["AV"])
	ac := pick(map[string]float64{"L": 0.77, "H": 0.44}, m["AC"])
	ui := pick(map[string]float64{"N": 0.85, "R": 0.62}, m["UI"])
	scopeChanged := m["S"] == "C"

	var pr float64
	if scopeChanged {
		pr = pick(map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}, m["PR"])
	} else {
		pr = pick(map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}, m["PR"])
	}

	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c := pick(cia, m["C"])
	i := pick(cia, m["I"])
	a := pick(cia, m["A"])
	if av == 0 || ac == 0 || ui == 0 || pr == 0 {
		return 0 // missing required metric
	}

	iscBase := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if scopeChanged {
		base = math.Min(1.08*(impact+exploitability), 10)
	} else {
		base = math.Min(impact+exploitability, 10)
	}
	return roundUp1(base)
}

// LabelFromScore maps a CVSS base score to the qualitative severity rating.
func LabelFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}

func pick(table map[string]float64, key string) float64 {
	return table[key] // 0 when absent → treated as parse failure upstream
}

// roundUp1 rounds up to one decimal place, per the CVSS spec.
func roundUp1(x float64) float64 {
	return math.Ceil(x*10) / 10
}
