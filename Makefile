IMAGE ?= credentials-broker:dev

.PHONY: build run test lint format clean docker-build docker-run

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

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm -p 8080:8080 \
		-v "$(PWD)/config.example.yaml:/etc/credentials-broker/config.yaml:ro" \
		-e INFISICAL_BASE_URL=$(INFISICAL_BASE_URL) \
		-e INFISICAL_CLIENT_ID=$(INFISICAL_CLIENT_ID) \
		-e INFISICAL_CLIENT_SECRET=$(INFISICAL_CLIENT_SECRET) \
		$(IMAGE)
