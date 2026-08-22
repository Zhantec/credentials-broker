.PHONY: build run test lint format clean

build:
	go build -o bin/broker ./cmd/broker

run:
	CONFIG_PATH=config.example.yaml go run ./cmd/broker

test:
	go test ./...

lint:
	golangci-lint run

format:
	gofmt -w .
	goimports -w .

clean:
	rm -rf bin
