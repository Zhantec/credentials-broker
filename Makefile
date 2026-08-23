IMAGE ?= credentials-broker:dev

.PHONY: build run test lint format fmt-check clean docker-build docker-run

build:
	go build -o bin/broker ./cmd/broker

run:
	go run ./cmd/broker

test:
	go test ./...

lint:
	golangci-lint run

format:
	gofmt -w .
	goimports -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	@test -z "$$(goimports -l .)" || (goimports -l . && exit 1)

clean:
	rm -rf bin

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm -p 8080:8080 \
		-v "$(PWD)/data:/data" \
		-e DB_PATH=/data/credentials-broker.db \
		-e ADMIN_API_KEY=$(ADMIN_API_KEY) \
		-e INFISICAL_BASE_URL=$(INFISICAL_BASE_URL) \
		-e INFISICAL_CLIENT_ID=$(INFISICAL_CLIENT_ID) \
		-e INFISICAL_CLIENT_SECRET=$(INFISICAL_CLIENT_SECRET) \
		$(IMAGE)
