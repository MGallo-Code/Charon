package store

import (
	"context"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
)

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

// --- GetUserByEmail ---

func TestGetUserByEmail(t *testing.T) {
	ctx := context.Background()

	t.Run("returns correct user", func(t *testing.T) {
		email := "get_by_email@example.com"
		hash := "argon2id$fakehash"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		// Create user
		id := mustCreateUser(t, ctx, email, hash)

		// Attempt to get user by email
		user, err := testStore.GetUserByEmail(ctx, email)
		if err != nil {
			t.Fatalf("GetUserByEmail failed: %v", err)
		}

		// If user fetched, validate their fields
		if user.ID != id {
			t.Errorf("id: expected %v, got %v", id, user.ID)
		}
		if user.Email == nil || *user.Email != email {
			t.Errorf("email: expected %q, got %v", email, user.Email)
		}
		if user.PasswordHash != hash {
			t.Errorf("password_hash: expected %q, got %q", hash, user.PasswordHash)
		}
	})

	t.Run("returns error for nonexistent email", func(t *testing.T) {
		_, err := testStore.GetUserByEmail(ctx, "nobody@example.com")
		if err == nil {
			t.Fatal("expected error for nonexistent email, got nil")
		}
	})
}

// --- GetUserByID ---

func TestGetUserByID(t *testing.T) {
	ctx := context.Background()

	t.Run("returns correct user", func(t *testing.T) {
		email := "get_by_id@example.com"
		hash := "argon2id$fakehash"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		// Create user w/ email
		id := mustCreateUser(t, ctx, email, hash)

		// Attempt to get user by ID
		user, err := testStore.GetUserByID(ctx, id)
		if err != nil {
			t.Fatalf("GetUserByID failed: %v", err)
		}

		// Validate returned user vals
		if user.ID != id {
			t.Errorf("id: expected %v, got %v", id, user.ID)
		}
		if user.Email == nil || *user.Email != email {
			t.Errorf("email: expected %q, got %v", email, user.Email)
		}
		if user.PasswordHash != hash {
			t.Errorf("password_hash: expected %q, got %q", hash, user.PasswordHash)
		}
	})

	t.Run("returns error for nonexistent ID", func(t *testing.T) {
		fakeID, _ := uuid.NewV7()
		_, err := testStore.GetUserByID(ctx, fakeID)
		if err == nil {
			t.Fatal("expected error for nonexistent ID, got nil")
		}
	})
}
