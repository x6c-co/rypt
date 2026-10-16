GO ?= go

.PHONY: all test race vet cover fuzz integration

all: vet test

test:
	$(GO) test ./...

# race needs cgo.
race:
	CGO_ENABLED=1 $(GO) test -race ./...

# vet also covers the integration tests, which ./... skips because of their
# build tag. gofmt's errors count as output.
vet:
	$(GO) vet ./...
	$(GO) vet -tags integration ./...
	@out="$$("$$($(GO) env GOROOT)/bin/gofmt" -l . 2>&1)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

# fuzz runs each fuzz target for FUZZTIME.
FUZZTIME ?= 30s
fuzz:
	$(GO) test -run '^$$' -fuzz '^FuzzAPIError$$' -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz '^FuzzDecode$$' -fuzztime $(FUZZTIME) .

# integration runs against the live API. It needs RYPT_TOKEN and RYPT_KEY_ID
# in the environment and spends about ten operations on that key.
integration:
	$(GO) test -tags integration -count=1 -run Integration -v ./...
