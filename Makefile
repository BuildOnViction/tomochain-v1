.PHONY: caelum caelum-cross evm all test clean
.PHONY: caelum-linux caelum-linux-386 caelum-linux-amd64 caelum-linux-mips64 caelum-linux-mips64le
.PHONY: caelum-darwin caelum-darwin-386 caelum-darwin-amd64

GOBIN = $(shell pwd)/build/bin
GOFMT = gofmt
GO ?= latest
GO_PACKAGES = .
GO_FILES := $(shell find $(shell go list -f '{{.Dir}}' $(GO_PACKAGES)) -name \*.go)

GIT = git

caelum:
	build/env.sh go run build/ci.go install ./cmd/caelum
	@echo "Done building."
	@echo "Run \"$(GOBIN)/caelum\" to launch caelum."

bootnode:
	build/env.sh go run build/ci.go install ./cmd/bootnode
	@echo "Done building."
	@echo "Run \"$(GOBIN)/bootnode\" to launch a bootnode."

puppeth:
	build/env.sh go run build/ci.go install ./cmd/puppeth
	@echo "Done building."
	@echo "Run \"$(GOBIN)/puppeth\" to launch puppeth."

all:
	build/env.sh go run build/ci.go install

test: all
	build/env.sh go run build/ci.go test

clean:
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# Cross Compilation Targets (xgo)

caelum-cross: caelum-linux caelum-darwin
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/caelum-*

caelum-linux: caelum-linux-386 caelum-linux-amd64 caelum-linux-mips64 caelum-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/caelum-linux-*

caelum-linux-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/caelum
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/caelum-linux-* | grep 386

caelum-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/caelum
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/caelum-linux-* | grep amd64

caelum-linux-mips:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/caelum
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/caelum-linux-* | grep mips

caelum-linux-mipsle:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/caelum
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/caelum-linux-* | grep mipsle

caelum-linux-mips64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/caelum
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/caelum-linux-* | grep mips64

caelum-linux-mips64le:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/caelum
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/caelum-linux-* | grep mips64le

caelum-darwin: caelum-darwin-386 caelum-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/caelum-darwin-*

caelum-darwin-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/caelum
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/caelum-darwin-* | grep 386

caelum-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/caelum
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/caelum-darwin-* | grep amd64

gofmt:
	$(GOFMT) -s -w $(GO_FILES)
	$(GIT) checkout vendor
