package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDataDogTeamPCPSource_Name(t *testing.T) {
	src := NewDataDogTeamPCPSource()
	if got := src.Name(); got != "datadog-teampcp" {
		t.Errorf("Name() = %q, want %q", got, "datadog-teampcp")
	}
}

func TestDataDogTeamPCPSource_CacheTTL(t *testing.T) {
	src := NewDataDogTeamPCPSource()
	if got := src.CacheTTL(); got != dataDogTeamPCPCacheTTL {
		t.Errorf("CacheTTL() = %v, want %v", got, dataDogTeamPCPCacheTTL)
	}
}

func TestDataDogTeamPCPSource_WithOptions(t *testing.T) {
	customURL := "https://example.com/teampcp.csv"
	src := NewDataDogTeamPCPSource(WithDataDogTeamPCPURL(customURL))
	if src.url != customURL {
		t.Errorf("url = %q, want %q", src.url, customURL)
	}
}

func TestDataDogTeamPCPSource_Fetch_RetainsNpmAndPyPI(t *testing.T) {
	// Mixed-ecosystem CSV — npm and PyPI rows survive (tagged + ecosystem-scoped
	// keys); docker and other artefact types are dropped.
	csvData := `artifact_type,name,affected_versions` + "\n" + //nolint:misspell // upstream CSV column name
		`npm package,@antv/g6,5.0.50
npm package,@cap-js/sqlite,2.2.2
npm package,@tanstack/query-core,"5.59.1, 5.59.2"
pypi package,LiteLLM,"1.82.7, 1.82.8"
docker image,aquasec/trivy,"0.69.4, 0.69.5"
NPM PACKAGE,case-insensitive-pkg,1.0.0
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(csvData))
	}))
	defer server.Close()

	src := NewDataDogTeamPCPSource(WithDataDogTeamPCPURL(server.URL))
	data, err := src.Fetch(context.Background(), server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if data == nil {
		t.Fatal("Fetch() returned nil data")
	}
	if data.Source != "datadog-teampcp" {
		t.Errorf("Source = %q, want datadog-teampcp", data.Source)
	}
	if data.Campaign != dataDogTeamPCPCampaign {
		t.Errorf("Campaign = %q, want %q", data.Campaign, dataDogTeamPCPCampaign)
	}
	if len(data.Packages) != 5 {
		t.Fatalf("len(Packages) = %d, want 5 (4 npm + 1 pypi)", len(data.Packages))
	}
	if _, ok := data.Packages["docker|aquasec/trivy"]; ok {
		t.Error("docker row should have been filtered out")
	}
	if pkg, ok := data.Packages["pypi|litellm"]; !ok {
		t.Error("missing pypi|litellm (PyPI row should be retained, name PEP 503 normalised)")
	} else {
		if pkg.Ecosystem != "pypi" {
			t.Errorf("litellm ecosystem = %q, want pypi", pkg.Ecosystem)
		}
		if pkg.Name != "litellm" {
			t.Errorf("litellm name = %q, want normalised litellm", pkg.Name)
		}
		if len(pkg.Versions) != 2 {
			t.Errorf("litellm versions = %v, want 2", pkg.Versions)
		}
	}
	if pkg, ok := data.Packages["npm|@tanstack/query-core"]; !ok {
		t.Error("missing npm|@tanstack/query-core")
	} else {
		if pkg.Ecosystem != "npm" {
			t.Errorf("@tanstack/query-core ecosystem = %q, want npm", pkg.Ecosystem)
		}
		if len(pkg.Versions) != 2 {
			t.Errorf("@tanstack/query-core versions = %v, want 2", pkg.Versions)
		}
	}
	if _, ok := data.Packages["npm|case-insensitive-pkg"]; !ok {
		t.Error("artefact_type match should be case-insensitive")
	}
}

func TestDataDogTeamPCPSource_Fetch_MissingColumns(t *testing.T) {
	csvData := `name,affected_versions
@antv/g6,5.0.50
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(csvData))
	}))
	defer server.Close()

	src := NewDataDogTeamPCPSource(WithDataDogTeamPCPURL(server.URL))
	if _, err := src.Fetch(context.Background(), server.Client()); err == nil {
		t.Error("Fetch() expected error when artefact_type column is missing")
	}
}

func TestDataDogTeamPCPSource_Fetch_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	src := NewDataDogTeamPCPSource(WithDataDogTeamPCPURL(server.URL))
	if _, err := src.Fetch(context.Background(), server.Client()); err == nil {
		t.Error("Fetch() expected error for 500 response")
	}
}
