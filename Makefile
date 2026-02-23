.PHONY: build build-all test lint lint-fix clean docker install fmt tidy vet check help

BINARY := supplyscan
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags="-s -w -X github.com/seanhalberthal/supplyscan/internal/types.Version=$(VERSION)"
GOLANGCI_LINT_VERSION := v2.10.1
GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

# Build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/supplyscan

# Cross-compile for all platforms
build-all: clean
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64 ./cmd/supplyscan
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64 ./cmd/supplyscan
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64 ./cmd/supplyscan
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64 ./cmd/supplyscan
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe ./cmd/supplyscan

# Run tests
test:
	go test -race ./...

# Run linter (pinned version via go run)
lint:
	$(GOLANGCI_LINT) run

# Run linter with auto-fix
lint-fix:
	$(GOLANGCI_LINT) run --fix

# Clean build artefacts
clean:
	rm -f $(BINARY)
	rm -rf dist/

# Build Docker image
docker:
	docker build -t $(BINARY):$(VERSION) -t $(BINARY):latest .

# Install to $GOPATH/bin
install:
	go install $(LDFLAGS) ./cmd/supplyscan

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

# Show available targets
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build       Build for current platform"
	@echo "  build-all   Cross-compile for all platforms"
	@echo "  test        Run tests"
	@echo "  lint        Run linter"
	@echo "  lint-fix    Run linter with auto-fix"
	@echo "  clean       Clean build artefacts"
	@echo "  docker      Build Docker image"
	@echo "  install     Install to \$$GOPATH/bin"
	@echo "  fmt         Format Go code"
	@echo "  tidy        Tidy Go modules"
	@echo "  vet         Run go vet"
	@echo "  check       Run all checks (fmt, tidy, vet, lint, test)"
	@echo "  help        Show this help message"
