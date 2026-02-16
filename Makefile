.PHONY: run build test vet tidy

run:
	docker compose up --build

build:
	go build -o charon main.go

vet:
	go vet ./...

tidy:
	go mod tidy

test:
	go mod tidy
	go vet ./...
	docker compose -f compose.test.yml up -d
	@echo "Waiting for Postgres..." && sleep 2
	go test -race ./... ; docker compose -f compose.test.yml down
