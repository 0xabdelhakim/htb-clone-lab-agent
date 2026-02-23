.PHONY: test run build fmt dev

test:
	go test ./...

run:
	go run ./cmd/lab-agent

build:
	go build -o bin/lab-agent ./cmd/lab-agent

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

dev:
	docker compose up --build
