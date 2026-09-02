package web

import (
	"encoding/json"
	"testing"
)

func TestNvdCpeRange(t *testing.T) {
	tests := []struct {
		name string
		m    nvdCpeMatch
		want cveRange
		ok   bool
	}{
		{
			name: "exclusive end",
			m:    nvdCpeMatch{VersionStartIncluding: "7.4.0", VersionEndExcluding: "7.4.3"},
			want: cveRange{major: 7, minor: 4, fixedPatch: 3},
			ok:   true,
		},
		{
			name: "inclusive end bumps to the next patch",
			m:    nvdCpeMatch{VersionStartIncluding: "7.0.0", VersionEndIncluding: "7.0.13"},
			want: cveRange{major: 7, minor: 0, fixedPatch: 14},
			ok:   true,
		},
		{
			name: "end-only range derives its train from the end",
			m:    nvdCpeMatch{VersionEndExcluding: "7.4.3"},
			want: cveRange{major: 7, minor: 4, fixedPatch: 3},
			ok:   true,
		},
		{
			name: "missing fixed version marks the train never fixed",
			m:    nvdCpeMatch{VersionStartIncluding: "7.4.0"},
			want: cveRange{major: 7, minor: 4, fixedPatch: neverFixed},
			ok:   true,
		},
		{
			name: "cross-train bounds are rejected rather than guessed",
			m:    nvdCpeMatch{VersionStartIncluding: "7.4.0", VersionEndExcluding: "7.6.1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := nvdCpeRange(tt.m)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNvdSeverity(t *testing.T) {
	crit := []nvdCvssMetric{{}}
	crit[0].CvssData.BaseSeverity = "CRITICAL"
	if got := nvdSeverity(crit); got != "critical" {
		t.Errorf("CRITICAL -> %q, want critical", got)
	}
	medV2 := []nvdCvssMetric{{}}
	medV2[0].BaseSeverity = "MEDIUM" // CVSSv2 carries severity at this level, not under CvssData
	if got := nvdSeverity(nil, nil, medV2); got != "warning" {
		t.Errorf("MEDIUM (v2 fallback) -> %q, want warning", got)
	}
	if got := nvdSeverity(); got != "warning" {
		t.Errorf("no metrics -> %q, want the warning default", got)
	}
}

func TestNvdEntryToDef(t *testing.T) {
	const sample = `{
		"vulnerabilities": [{
			"cve": {
				"id": "CVE-2099-9999",
				"descriptions": [{"lang": "en", "value": "a test vulnerability"}],
				"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
				"configurations": [{"nodes": [{"cpeMatch": [
					{"vulnerable": true, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
					 "versionStartIncluding": "7.4.0", "versionEndExcluding": "7.4.3"}
				]}]}]
			}
		}]
	}`
	var parsed nvdResponse
	if err := json.Unmarshal([]byte(sample), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(parsed.Vulnerabilities))
	}
	def, ok := nvdEntryToDef(parsed.Vulnerabilities[0])
	if !ok {
		t.Fatal("expected a valid def")
	}
	if def.id != "CVE-2099-9999" || def.severity != "critical" {
		t.Errorf("got %+v", def)
	}
	if len(def.ranges) != 1 || def.ranges[0] != (cveRange{major: 7, minor: 4, fixedPatch: 3}) {
		t.Errorf("ranges = %+v", def.ranges)
	}

	const noMatch = `{"vulnerabilities":[{"cve":{"id":"CVE-2099-0000","descriptions":[{"lang":"en","value":"x"}]}}]}`
	var parsed2 nvdResponse
	if err := json.Unmarshal([]byte(noMatch), &parsed2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := nvdEntryToDef(parsed2.Vulnerabilities[0]); ok {
		t.Error("entry with no FortiOS-matching range should be rejected")
	}
}

func TestNvdEntryToDefKeepsEndOnlyAndNeverFixedRanges(t *testing.T) {
	const sample = `{
		"vulnerabilities": [{
			"cve": {
				"id": "CVE-2099-9998",
				"descriptions": [{"lang": "en", "value": "range edge cases"}],
				"configurations": [{"nodes": [{"cpeMatch": [
					{"vulnerable": true, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "versionEndExcluding": "7.4.3"},
					{"vulnerable": true, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "versionStartIncluding": "6.0.0"}
				]}]}]
			}
		}]
	}`
	var parsed nvdResponse
	if err := json.Unmarshal([]byte(sample), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	def, ok := nvdEntryToDef(parsed.Vulnerabilities[0])
	if !ok {
		t.Fatal("entry with valid end-only and never-fixed ranges was discarded")
	}
	want := []cveRange{{major: 7, minor: 4, fixedPatch: 3}, {major: 6, minor: 0, fixedPatch: neverFixed}}
	if len(def.ranges) != len(want) {
		t.Fatalf("ranges = %+v, want %+v", def.ranges, want)
	}
	for i := range want {
		if def.ranges[i] != want[i] {
			t.Errorf("range %d = %+v, want %+v", i, def.ranges[i], want[i])
		}
	}
}

func TestEncodeDecodeRanges(t *testing.T) {
	in := []cveRange{{major: 7, minor: 4, fixedPatch: 3}, {major: 7, minor: 0, fixedPatch: neverFixed}}
	out := decodeRanges(encodeRanges(in))
	if len(out) != len(in) {
		t.Fatalf("got %d ranges, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("range %d: got %+v, want %+v", i, out[i], in[i])
		}
	}
}

func TestCVEFingerprint(t *testing.T) {
	a := []cveDef{{id: "CVE-2024-1", severity: "critical", remediation: "upgrade", ranges: []cveRange{{7, 4, 3}}}}
	b := []cveDef{{id: "CVE-2024-1", severity: "critical", remediation: "upgrade", ranges: []cveRange{{7, 4, 3}}}}
	c := []cveDef{{id: "CVE-2024-1", severity: "critical", remediation: "upgrade", ranges: []cveRange{{7, 4, 4}}}}
	if cveFingerprint(a) != cveFingerprint(b) {
		t.Error("identical defs should fingerprint the same")
	}
	if cveFingerprint(a) == cveFingerprint(c) {
		t.Error("different ranges should change the fingerprint")
	}
}
