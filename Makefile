VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

.PHONY: build
build:
	go build $(LDFLAGS) -o helmscan ./cmd/app

.PHONY: build-all
build-all:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/helmscan_Darwin_x86_64/helmscan ./cmd/app
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/helmscan_Darwin_arm64/helmscan ./cmd/app
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/helmscan_Linux_x86_64/helmscan ./cmd/app
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/helmscan_Windows_x86_64/helmscan.exe ./cmd/app

.PHONY: release
release:
	goreleaser release --clean

.PHONY: snapshot
snapshot:
	goreleaser release --snapshot --clean --skip=publish

.PHONY: clean
clean:
	rm -rf dist/ helmscan
