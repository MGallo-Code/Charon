.PHONY: run build test vet tidy migration-check

run:
	docker compose up --build

build:
	go build -o charon main.go

vet:
	go vet ./...

# Static, DB-free guard for the migration-ordering invariant (INVARIANTS.md INV-1).
migration-check:
	go run ./cmd/migration-check

tidy:
	go mod tidy

test:
	go mod tidy
	go vet ./...
	docker compose -f compose.test.yml up -d
	@echo "Waiting for Postgres..." && sleep 2
	go test -race ./... ; docker compose -f compose.test.yml down
