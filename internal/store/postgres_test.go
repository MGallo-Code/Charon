package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
)

// Shared db pool conn for testing
var testStore *PostgresStore

// Main test func
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

	// Run tests :))
	code := m.Run()
	// Couldn't defer close bc Exit() :(, call here to close db pool connection
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

// --- CreateUserByEmail ---

func TestCreateUserByEmail(t *testing.T) {
	ctx := context.Background()

	// Speaks for itself...
	t.Run("stores correct values and defaults", func(t *testing.T) {
		// Set user vars
		email := "store_test@example.com"
		hash := "argon2id$v=19$m=65536,t=3,p=2$fakesalt$fakehash"
		// Remove previous users w/ same email (just in case! :) )
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		// Create user
		id := mustCreateUser(t, ctx, email, hash)

		// Create user vars, nullable fields as pointers
		var (
			dbID               uuid.UUID
			dbEmail            string
			dbPasswordHash     string
			dbCreatedAt        time.Time
			dbUpdatedAt        time.Time
			dbEmailConfirmedAt *time.Time
			dbPhone            *string
			dbPhoneConfirmedAt *time.Time
			dbFirstName        *string
			dbLastName         *string
			dbOAuthProvider    *string
			dbOAuthProviderID  *string
			dbAvatarURL        *string
		)
		// Attempt to get values of inserted user, and validate them
		err := testStore.pool.QueryRow(ctx, `
			SELECT id, email, password_hash, created_at, updated_at,
				email_confirmed_at, phone, phone_confirmed_at,
				first_name, last_name, oauth_provider, oauth_provider_id, avatar_url
			FROM users WHERE id = $1
		`, id).Scan(
			&dbID, &dbEmail, &dbPasswordHash, &dbCreatedAt, &dbUpdatedAt,
			&dbEmailConfirmedAt, &dbPhone, &dbPhoneConfirmedAt,
			&dbFirstName, &dbLastName, &dbOAuthProvider, &dbOAuthProviderID, &dbAvatarURL,
		)
		if err != nil {
			t.Fatalf("failed to query inserted user: %v", err)
		}

		// Validate values we passed in match what was saved
		if dbID != id {
			t.Errorf("id: expected %v, got %v", id, dbID)
		}
		if dbEmail != email {
			t.Errorf("email: expected %q, got %q", email, dbEmail)
		}
		if dbPasswordHash != hash {
			t.Errorf("password_hash: expected %q, got %q", hash, dbPasswordHash)
		}

		// Verify schema defaults fired
		if dbCreatedAt.IsZero() {
			t.Error("created_at was not set")
		}
		if dbUpdatedAt.IsZero() {
			t.Error("updated_at was not set")
		}

		// Verify unset fields are NULL, not empty or zeroish vals
		if dbEmailConfirmedAt != nil {
			t.Error("email_confirmed_at should be NULL for email registration")
		}
		if dbPhone != nil {
			t.Error("phone should be NULL for email registration")
		}
		if dbPhoneConfirmedAt != nil {
			t.Error("phone_confirmed_at should be NULL for email registration")
		}
		if dbFirstName != nil {
			t.Error("first_name should be NULL for email registration")
		}
		if dbLastName != nil {
			t.Error("last_name should be NULL for email registration")
		}
		if dbOAuthProvider != nil {
			t.Error("oauth_provider should be NULL for email registration")
		}
		if dbOAuthProviderID != nil {
			t.Error("oauth_provider_id should be NULL for email registration")
		}
		if dbAvatarURL != nil {
			t.Error("avatar_url should be NULL for email registration")
		}
	})

	// Less abt testing UNIQUE constraint, more just making sure errors are returned by func
	t.Run("returns error on duplicate email", func(t *testing.T) {
		// Set vars, cleanup emails under same value
		email := "dup_test@example.com"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		// Create user w/ email
		mustCreateUser(t, ctx, email, "hash1")

		// Attempt to create another user w/ same email
		id2, _ := uuid.NewV7()
		err := testStore.CreateUserByEmail(ctx, id2, email, "hash2")
		// Report if no err
		if err == nil {
			t.Fatal("expected error for duplicate email, got nil")
		}
	})
}
