package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/undont/supplyscan/internal/types"
)

// osvTestServer stands up mock querybatch + vulns endpoints. vulnsByPackage maps
// a normalised package name to the vuln ids querybatch should report; details
// maps a vuln id to the record the hydration endpoint returns.
func osvTestServer(t *testing.T, vulnsByPackage map[string][]string, details map[string]osvVulnDetail) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := osvBatchResponse{Results: make([]osvBatchResult, len(req.Queries))}
		for i, q := range req.Queries {
			for _, id := range vulnsByPackage[q.Package.Name] {
				resp.Results[i].Vulns = append(resp.Results[i].Vulns, osvVulnRef{ID: id})
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/v1/vulns/"):]
		detail, ok := details[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(detail)
	})

	return httptest.NewServer(mux)
}

func newTestOSVClient(srv *httptest.Server) *OSVClient {
	return NewOSVClient(
		withOSVURLs(srv.URL+"/v1/querybatch", srv.URL+"/v1/vulns/"),
		withOSVHTTPClient(srv.Client()),
	)
}

func TestOSVClient_AuditDependencies_PyPI(t *testing.T) {
	srv := osvTestServer(t,
		map[string][]string{"litellm": {"GHSA-test-litellm"}},
		map[string]osvVulnDetail{
			"GHSA-test-litellm": {
				ID:               "GHSA-test-litellm",
				Summary:          "SSRF in litellm proxy",
				DatabaseSpecific: map[string]json.RawMessage{"severity": json.RawMessage(`"HIGH"`)},
				Affected: []osvAffectedEntry{{
					Package: osvQueryPackage{Ecosystem: "PyPI", Name: "litellm"},
					Ranges: []osvAffectedRange{{Events: []osvRangeEvent{
						{Fixed: "1.82.9"},
					}}},
				}},
			},
		},
	)
	defer srv.Close()

	client := newTestOSVClient(srv)
	deps := []types.Dependency{
		{Name: "litellm", Version: "1.82.7", Ecosystem: types.EcosystemPyPI},
		{Name: "safe-pkg", Version: "1.0.0", Ecosystem: types.EcosystemPyPI},
	}

	findings, err := client.AuditDependencies(deps)
	if err != nil {
		t.Fatalf("AuditDependencies() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (%+v)", len(findings), findings)
	}

	f := findings[0]
	if f.Package != "litellm" || f.InstalledVersion != "1.82.7" {
		t.Errorf("got package %s@%s, want litellm@1.82.7", f.Package, f.InstalledVersion)
	}
	if f.Severity != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.ID != "GHSA-test-litellm" {
		t.Errorf("id = %q, want GHSA-test-litellm", f.ID)
	}
	if f.Title != "SSRF in litellm proxy" {
		t.Errorf("title = %q", f.Title)
	}
	if f.PatchedIn != "1.82.9" {
		t.Errorf("patched_in = %q, want 1.82.9", f.PatchedIn)
	}
}

func TestOSVClient_AuditDependencies_CVSSFallback(t *testing.T) {
	srv := osvTestServer(t,
		map[string][]string{"requests": {"PYSEC-test"}},
		map[string]osvVulnDetail{
			"PYSEC-test": {
				ID:      "PYSEC-test",
				Summary: "RCE in requests",
				// no database_specific.severity; severity must come from the CVSS vector
				Severity: []osvSeverityEntry{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
				Affected: []osvAffectedEntry{{
					Package: osvQueryPackage{Ecosystem: "PyPI", Name: "requests"},
				}},
			},
		},
	)
	defer srv.Close()

	client := newTestOSVClient(srv)
	deps := []types.Dependency{{Name: "requests", Version: "2.0.0", Ecosystem: types.EcosystemPyPI}}

	findings, err := client.AuditDependencies(deps)
	if err != nil {
		t.Fatalf("AuditDependencies() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical (from CVSS 9.8)", findings[0].Severity)
	}
}

func TestOSVClient_AuditDependencies_PyPINameNormalisation(t *testing.T) {
	// OSV stores normalised names; the client must normalise the query and the
	// affected-entry match for a lockfile name like "PyTorch_Lightning".
	srv := osvTestServer(t,
		map[string][]string{"pytorch-lightning": {"GHSA-pl"}},
		map[string]osvVulnDetail{
			"GHSA-pl": {
				ID:               "GHSA-pl",
				Summary:          "issue",
				DatabaseSpecific: map[string]json.RawMessage{"severity": json.RawMessage(`"MODERATE"`)},
				Affected: []osvAffectedEntry{{
					Package: osvQueryPackage{Ecosystem: "PyPI", Name: "pytorch-lightning"},
					Ranges:  []osvAffectedRange{{Events: []osvRangeEvent{{Fixed: "2.0.0"}}}},
				}},
			},
		},
	)
	defer srv.Close()

	client := newTestOSVClient(srv)
	deps := []types.Dependency{{Name: "PyTorch_Lightning", Version: "1.9.0", Ecosystem: types.EcosystemPyPI}}

	findings, err := client.AuditDependencies(deps)
	if err != nil {
		t.Fatalf("AuditDependencies() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Severity != "moderate" || findings[0].PatchedIn != "2.0.0" {
		t.Errorf("got severity=%q patched=%q, want moderate/2.0.0", findings[0].Severity, findings[0].PatchedIn)
	}
}

func TestOSVClient_AuditDependencies_Empty(t *testing.T) {
	client := NewOSVClient()
	findings, err := client.AuditDependencies(nil)
	if err != nil || findings != nil {
		t.Errorf("AuditDependencies(nil) = %v, %v; want nil, nil", findings, err)
	}
}
