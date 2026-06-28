# girth — build & test
#
# Common targets:
#   make            build the CLI into bin/girth
#   make test       unit + in-process e2e tests
#   make race       tests under the race detector
#   make check      fmt-check + vet + test (CI-style gate)
#   make linux      static linux/amd64 build (the deploy artifact)
#   make clean      remove build artifacts

GO       ?= go
PKG      := ./...
CMD      := ./cmd/girth
BIN_DIR  := bin
BIN      := $(BIN_DIR)/girth

# Static, dependency-free linux/amd64 binary for scp-ing to test hosts.
LINUX_BIN   := $(BIN_DIR)/girth-linux-amd64
LINUX_ARM   := $(BIN_DIR)/girth-linux-arm64

.PHONY: all build run-help test race vet fmt fmt-check check linux linux-arm tidy clean

all: build

build: $(BIN)

$(BIN): $(wildcard *.go) $(wildcard cmd/girth/*.go) go.mod
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN) $(CMD)

run-help: build
	$(BIN) help

test:
	$(GO) test $(PKG)

race:
	$(GO) test -race $(PKG)

vet:
	$(GO) vet $(PKG)

fmt:
	gofmt -w .

# Fail if any file is not gofmt-clean (prints offenders).
fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# CI-style gate.
check: fmt-check vet test

linux: $(LINUX_BIN)

$(LINUX_BIN): $(wildcard *.go) $(wildcard cmd/girth/*.go) go.mod
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o $(LINUX_BIN) $(CMD)

linux-arm: $(wildcard *.go) $(wildcard cmd/girth/*.go) go.mod
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -o $(LINUX_ARM) $(CMD)

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN_DIR)
