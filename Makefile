.PHONY: build build-all test lint clean docker install

BINARY := supplyscan-mcp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags="-s -w -X github.com/seanhalberthal/supplyscan-mcp/internal/types.Version=$(VERSION)"

# Build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/supplyscan-mcp

# Cross-compile for all platforms
build-all: clean
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64 ./cmd/supplyscan-mcp
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64 ./cmd/supplyscan-mcp
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64 ./cmd/supplyscan-mcp
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64 ./cmd/supplyscan-mcp
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe ./cmd/supplyscan-mcp

# Run tests
test:
	go test -v -race -cover ./...

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
	go install $(LDFLAGS) ./cmd/supplyscan-mcp

# Run all checks (test + lint)
check: lint test
