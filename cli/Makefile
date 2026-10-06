# claim-check build. Works with GNU make on Linux and macOS.
GO        ?= go
VERSION   ?= 2.0.0-dev
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
LDFLAGS   := -s -w -X main.version=$(VERSION)
GOFMT     := $(shell $(GO) env GOROOT)/bin/gofmt

.PHONY: test fmt-check vet release clean

## test: gofmt check, go vet, go test
test: fmt-check vet
	$(GO) test ./...

fmt-check:
	@out="$$($(GOFMT) -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

## release: static binaries for every platform in dist/, plus dist/SHA256SUMS
release:
	@mkdir -p dist
	rm -f dist/claim-check* dist/SHA256SUMS
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "build dist/claim-check_$${os}_$${arch}"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/claim-check_$${os}_$${arch} . ; \
	done
	@cd dist && if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum claim-check_* > SHA256SUMS; \
	else \
		shasum -a 256 claim-check_* > SHA256SUMS; \
	fi
	@cat dist/SHA256SUMS

clean:
	rm -rf dist
