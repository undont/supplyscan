.PHONY: build build-all test lint lint-fix clean docker install fmt tidy vet check

BINARY := supplyscan-mcp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags="-s -w -X github.com/seanhalberthal/supplyscan-mcp/internal/types.Version=$(VERSION)"

# Build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd

# Cross-compile for all platforms
build-all: clean
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64 ./cmd
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64 ./cmd
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64 ./cmd
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64 ./cmd
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe ./cmd

# Run tests
test:
	@set -o pipefail; go test -v -race -cover ./... 2>&1 | grep -vE "^\s*(---|PASS: Test|RUN|^coverage: )" | grep -E "(^ok|^FAIL|^\?\?\?|^=== FAIL)"

# Run linter
lint:
	golangci-lint run

# Run linter with auto-fix
lint-fix:
	golangci-lint run --fix

# Clean build artefacts
clean:
	rm -f $(BINARY)
	rm -rf dist/

# Build Docker image
docker:
	docker build -t $(BINARY):$(VERSION) -t $(BINARY):latest .

# Install to $GOPATH/bin
install:
	go install $(LDFLAGS) ./cmd

# Format Go code
fmt:
	go fmt ./...

# Tidy Go modules
tidy:
	go mod tidy

# Run go vet
vet:
	go vet ./...

# Run all checks (format, tidy, vet, lint, test)
check: fmt tidy vet lint test
