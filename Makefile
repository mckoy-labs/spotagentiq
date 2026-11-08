VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X main.version=$(VERSION)

.PHONY: build test vet fmt demo release docker clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/spotagentiq ./cmd/spotagentiq

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

demo: build
	./bin/spotagentiq demo

# Cross-compile release binaries into dist/.
release:
	@mkdir -p dist
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS)" \
			-o dist/spotagentiq_$(VERSION)_$${os}_$${arch}$$ext ./cmd/spotagentiq; \
	done
	@cd dist && sha256sum spotagentiq_* > SHA256SUMS

docker:
	docker build --build-arg VERSION=$(VERSION) -t spotagentiq:$(VERSION) -t spotagentiq:latest .

clean:
	rm -rf bin dist
