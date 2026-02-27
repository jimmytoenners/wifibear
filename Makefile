BINARY=wifibear
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build build-all test lint clean install

build:
	CGO_ENABLED=1 go build $(LDFLAGS) -o $(BINARY) .

build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 .

build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 .

build-all: build-linux-amd64 build-linux-arm64

test:
	go test ./...

lint:
	golangci-lint run

clean:
	rm -f $(BINARY) $(BINARY)-linux-*

install: build
	sudo cp $(BINARY) /usr/local/bin/
