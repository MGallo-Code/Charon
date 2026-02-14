package store

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/gofrs/uuid/v5"
)

// Shared test connections for the store package
var testStore *PostgresStore
var testRedis *RedisStore

// TestMain sets up Postgres + Redis, runs all store tests, tears down
func TestMain(m *testing.M) {
	ctx := context.Background()

	// Attempts to connect to db, log err
	ps, err := NewPostgresStore(ctx, "postgres://test_user:test_pass@localhost:5433/charon_test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to test database: %v\n", err)
		os.Exit(1)
	}
	testStore = ps

	// Attempt to run migrations against db, log err
	if err := testStore.Migrate(ctx, os.DirFS("../../migrations")); err != nil {
		fmt.Fprintf(os.Stderr, "failed to run migrations: %v\n", err)
		testStore.Close()
		os.Exit(1)
	}

	// Attempts to connect to redis, log err
	rs, err := NewRedisStore(ctx, "redis://localhost:6380")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to test redis: %v\n", err)
		testStore.Close()
		os.Exit(1)
	}
	testRedis = rs

	// Run tests :))
	code := m.Run()
	// Couldn't defer close bc Exit() :(, call here to close connections
	testRedis.Close()
	testStore.Close()
	os.Exit(code)
}

// --- Helpers ---

// Create user in db with given email/pwd, generates UUID, returns id
func mustCreateUser(t *testing.T, ctx context.Context, email, hash string) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("failed to generate UUID: %v", err)
	}
	if err := testStore.CreateUserByEmail(ctx, id, email, hash); err != nil {
		t.Fatalf("CreateUserByEmail(%q): %v", email, err)
	}
	return id
}

// Delete users w/ given email(s), for cleanup, self-explanatory...
func cleanupUsersByEmail(t *testing.T, ctx context.Context, emails ...string) {
	t.Helper()
	for _, email := range emails {
		testStore.pool.Exec(ctx, "DELETE FROM users WHERE email = $1", email)
	}
}
