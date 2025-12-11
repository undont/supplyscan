package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDataDogSource_Name(t *testing.T) {
	src := NewDataDogSource()
	if got := src.Name(); got != "datadog" {
		t.Errorf("Name() = %q, want %q", got, "datadog")
	}
}

func TestDataDogSource_CacheTTL(t *testing.T) {
	src := NewDataDogSource()
	if got := src.CacheTTL(); got != dataDogCacheTTL {
		t.Errorf("CacheTTL() = %v, want %v", got, dataDogCacheTTL)
	}
}

func TestDataDogSource_WithOptions(t *testing.T) {
	customURL := "https://example.com/iocs.csv"
	src := NewDataDogSource(WithDataDogURL(customURL))

	if src.url != customURL {
		t.Errorf("url = %q, want %q", src.url, customURL)
	}
}

func TestDataDogSource_Fetch_Success(t *testing.T) {
	csvData := `package_name,package_versions,sources
malicious-pkg,"1.0.0,1.0.1",datadog
@evil/scoped,2.0.0,datadog
another-bad,3.0.0,socketdev
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(csvData))
	}))
	defer server.Close()

	src := NewDataDogSource(WithDataDogURL(server.URL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if data == nil {
		t.Fatal("Fetch() returned nil data")
	}

	if data.Source != "datadog" {
		t.Errorf("Source = %q, want %q", data.Source, "datadog")
	}

	if data.Campaign != dataDogCampaign {
		t.Errorf("Campaign = %q, want %q", data.Campaign, dataDogCampaign)
	}

	if len(data.Packages) != 3 {
		t.Errorf("len(Packages) = %d, want 3", len(data.Packages))
	}

	// Check malicious-pkg
	if pkg, ok := data.Packages["malicious-pkg"]; !ok {
		t.Error("Packages missing 'malicious-pkg'")
	} else if len(pkg.Versions) != 2 {
		t.Errorf("malicious-pkg versions = %v, want 2 versions", pkg.Versions)

	}

	// Check scoped package
	if _, ok := data.Packages["@evil/scoped"]; !ok {
		t.Error("Packages missing '@evil/scoped'")
	}

	// Verify FetchedAt is set
	if data.FetchedAt == "" {
		t.Error("FetchedAt is empty")
	}
}

func TestDataDogSource_Fetch_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	src := NewDataDogSource(WithDataDogURL(server.URL))
	ctx := context.Background()

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for server error")
	}
}

func TestDataDogSource_Fetch_InvalidCSV(t *testing.T) {
	// Missing required headers
	csvData := `wrong_column,other_column
value1,value2
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(csvData))
	}))
	defer server.Close()

	src := NewDataDogSource(WithDataDogURL(server.URL))
	ctx := context.Background()

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for invalid CSV headers")
	}
}

func TestDataDogSource_Fetch_EmptyCSV(t *testing.T) {
	csvData := `package_name,package_versions,sources
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(csvData))
	}))
	defer server.Close()

	src := NewDataDogSource(WithDataDogURL(server.URL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(data.Packages) != 0 {
		t.Errorf("len(Packages) = %d, want 0", len(data.Packages))
	}
}

func TestDataDogSource_Fetch_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	src := NewDataDogSource(WithDataDogURL(server.URL))
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := src.Fetch(ctx, server.Client())
	if err == nil {
		t.Error("Fetch() expected error for cancelled context")
	}
}

func TestDataDogSource_Fetch_AlternativeHeaders(t *testing.T) {
	// Test alternative column names
	csvData := `name,compromised_version,reporter
pkg1,1.0.0,test
pkg2,"2.0.0,2.0.1",test
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(csvData))
	}))
	defer server.Close()

	src := NewDataDogSource(WithDataDogURL(server.URL))
	ctx := context.Background()

	data, err := src.Fetch(ctx, server.Client())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(data.Packages) != 2 {
		t.Errorf("len(Packages) = %d, want 2", len(data.Packages))
	}
}
