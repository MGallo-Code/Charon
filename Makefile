.PHONY: run build test

run:
	go run main.go

build:
	go build -o charon main.go

test:
	docker compose -f compose.test.yml up -d
	@echo "Waiting for Postgres..." && sleep 2
	go test ./... ; docker compose -f compose.test.yml down
