VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

.PHONY: build
build:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/helmscan_Darwin_x86_64/helmscan
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/helmscan_Darwin_arm64/helmscan
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/helmscan_Linux_x86_64/helmscan

.PHONY: release
release: build
	cd dist/helmscan_Darwin_x86_64 && tar czf ../helmscan_Darwin_x86_64.tar.gz helmscan
	cd dist/helmscan_Darwin_arm64 && tar czf ../helmscan_Darwin_arm64.tar.gz helmscan
	cd dist/helmscan_Linux_x86_64 && tar czf ../helmscan_Linux_x86_64.tar.gz helmscan
