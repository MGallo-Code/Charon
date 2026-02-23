package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
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

// --- GetPwdHashByUserID ---

func TestGetPwdHashByUserID(t *testing.T) {
	ctx := context.Background()

	t.Run("returns correct password hash", func(t *testing.T) {
		email := "get_pwd_hash@example.com"
		hash := "argon2id$fakehash"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		id := mustCreateUser(t, ctx, email, hash)

		got, err := testStore.GetPwdHashByUserID(ctx, id)
		if err != nil {
			t.Fatalf("GetPwdHashByUserID failed: %v", err)
		}
		if got != hash {
			t.Errorf("password_hash: expected %q, got %q", hash, got)
		}
	})

	t.Run("returns error for nonexistent ID", func(t *testing.T) {
		fakeID, _ := uuid.NewV7()
		_, err := testStore.GetPwdHashByUserID(ctx, fakeID)
		if err == nil {
			t.Fatal("expected error for nonexistent ID, got nil")
		}
	})
}

// --- CreateSession ---

func TestCreateSession(t *testing.T) {
	ctx := context.Background()

	t.Run("stores session with correct values", func(t *testing.T) {
		email := "session_create@example.com"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		// Need a real user (foreign key constraint)
		userID := mustCreateUser(t, ctx, email, "fakehash")
		tokenHash := sha256.Sum256([]byte("test-token-create"))
		csrfToken := sha256.Sum256([]byte("test-csrf-create"))
		expiresAt := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)
		ip := "192.168.1.1"
		ua := "Mozilla/5.0"

		sessionID, _ := uuid.NewV7()
		err := testStore.CreateSession(ctx, sessionID, userID, tokenHash[:], csrfToken[:], expiresAt, &ip, &ua)
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}

		// Verify session was stored correctly via direct query, as usual log errors...
		var (
			dbID        uuid.UUID
			dbUserID    uuid.UUID
			dbTokenHash []byte
			dbCSRFToken []byte
			dbExpiresAt time.Time
			dbIP        *string
			dbUA        *string
			dbCreatedAt time.Time
		)
		err = testStore.pool.QueryRow(ctx, `
			SELECT
				id, user_id, token_hash, csrf_token, expires_at, ip_address::TEXT, user_agent, created_at
			FROM sessions
			WHERE id = $1
		`, sessionID).Scan(&dbID, &dbUserID, &dbTokenHash, &dbCSRFToken, &dbExpiresAt, &dbIP, &dbUA, &dbCreatedAt)
		if err != nil {
			t.Fatalf("querying session: %v", err)
		}

		if dbID != sessionID {
			t.Errorf("id: expected %v, got %v", sessionID, dbID)
		}
		if dbUserID != userID {
			t.Errorf("user_id: expected %v, got %v", userID, dbUserID)
		}
		if string(dbTokenHash) != string(tokenHash[:]) {
			t.Error("token_hash does not match")
		}
		if string(dbCSRFToken) != string(csrfToken[:]) {
			t.Error("csrf_token does not match")
		}
		if !dbExpiresAt.Equal(expiresAt) {
			t.Errorf("expires_at: expected %v, got %v", expiresAt, dbExpiresAt)
		}
		if dbIP == nil || *dbIP != "192.168.1.1/32" {
			t.Errorf("ip_address: expected 192.168.1.1/32, got %v", dbIP)
		}
		if dbUA == nil || *dbUA != "Mozilla/5.0" {
			t.Errorf("user_agent: expected Mozilla/5.0, got %v", dbUA)
		}
		if dbCreatedAt.IsZero() {
			t.Error("created_at was not set")
		}
	})

	t.Run("stores session with nil optional fields", func(t *testing.T) {
		email := "session_create_nil@example.com"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		userID := mustCreateUser(t, ctx, email, "fakehash")
		tokenHash := sha256.Sum256([]byte("test-token-nil"))
		csrfToken := sha256.Sum256([]byte("test-csrf-nil"))
		expiresAt := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)

		sessionID, _ := uuid.NewV7()
		err := testStore.CreateSession(ctx, sessionID, userID, tokenHash[:], csrfToken[:], expiresAt, nil, nil)
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}

		// Verify nullable fields are NULL
		var dbIP *string
		var dbUA *string
		err = testStore.pool.QueryRow(ctx,
			"SELECT ip_address, user_agent FROM sessions WHERE id = $1",
			sessionID,
		).Scan(&dbIP, &dbUA)
		if err != nil {
			t.Fatalf("querying session: %v", err)
		}
		if dbIP != nil {
			t.Errorf("ip_address should be NULL, got %v", dbIP)
		}
		if dbUA != nil {
			t.Errorf("user_agent should be NULL, got %v", dbUA)
		}
	})

	t.Run("returns error for duplicate token hash", func(t *testing.T) {
		email := "session_dup_hash@example.com"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		userID := mustCreateUser(t, ctx, email, "fakehash")
		tokenHash := sha256.Sum256([]byte("test-token-dup"))
		expiresAt := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)

		csrfToken := sha256.Sum256([]byte("test-csrf-dup"))
		mustCreateSession(t, ctx, userID, tokenHash[:], csrfToken[:], expiresAt)

		// Attempt to create another session with same token hash
		id2, _ := uuid.NewV7()
		csrfToken2 := sha256.Sum256([]byte("test-csrf-dup-2"))
		err := testStore.CreateSession(ctx, id2, userID, tokenHash[:], csrfToken2[:], expiresAt, nil, nil)
		if err == nil {
			t.Fatal("expected error for duplicate token_hash, got nil")
		}
	})
}

// --- GetSessionByTokenHash ---

func TestGetSessionByTokenHash(t *testing.T) {
	ctx := context.Background()

	t.Run("returns valid session", func(t *testing.T) {
		email := "session_get@example.com"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		userID := mustCreateUser(t, ctx, email, "fakehash")
		tokenHash := sha256.Sum256([]byte("test-token-get"))
		csrfToken := sha256.Sum256([]byte("test-csrf-get"))
		expiresAt := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)
		sessionID := mustCreateSession(t, ctx, userID, tokenHash[:], csrfToken[:], expiresAt)

		session, err := testStore.GetSessionByTokenHash(ctx, tokenHash[:])
		if err != nil {
			t.Fatalf("GetSessionByTokenHash failed: %v", err)
		}

		if session.ID != sessionID {
			t.Errorf("id: expected %v, got %v", sessionID, session.ID)
		}
		if session.UserID != userID {
			t.Errorf("user_id: expected %v, got %v", userID, session.UserID)
		}
		if string(session.CSRFToken) != string(csrfToken[:]) {
			t.Error("csrf_token does not match")
		}
		if !session.ExpiresAt.Equal(expiresAt) {
			t.Errorf("expires_at: expected %v, got %v", expiresAt, session.ExpiresAt)
		}
	})

	t.Run("does not return expired session", func(t *testing.T) {
		email := "session_expired@example.com"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		userID := mustCreateUser(t, ctx, email, "fakehash")
		tokenHash := sha256.Sum256([]byte("test-token-expired"))
		csrfToken := sha256.Sum256([]byte("test-csrf-expired"))
		// Expired 1 hour ago
		expiresAt := time.Now().Add(-1 * time.Hour).Truncate(time.Microsecond)
		mustCreateSession(t, ctx, userID, tokenHash[:], csrfToken[:], expiresAt)

		_, err := testStore.GetSessionByTokenHash(ctx, tokenHash[:])
		if err == nil {
			t.Fatal("expected error for expired session, got nil")
		}
	})

	t.Run("returns error for nonexistent token hash", func(t *testing.T) {
		fakeHash := sha256.Sum256([]byte("nonexistent"))
		_, err := testStore.GetSessionByTokenHash(ctx, fakeHash[:])
		if err == nil {
			t.Fatal("expected error for nonexistent token hash, got nil")
		}
	})
}

// --- DeleteSession (Postgres) ---

func TestDeleteSessionPG(t *testing.T) {
	ctx := context.Background()

	t.Run("removes session by token hash", func(t *testing.T) {
		email := "session_delete@example.com"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		userID := mustCreateUser(t, ctx, email, "fakehash")
		tokenHash := sha256.Sum256([]byte("test-token-delete"))
		csrfToken := sha256.Sum256([]byte("test-csrf-delete"))
		expiresAt := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)
		mustCreateSession(t, ctx, userID, tokenHash[:], csrfToken[:], expiresAt)

		err := testStore.DeleteSession(ctx, tokenHash[:])
		if err != nil {
			t.Fatalf("DeleteSession failed: %v", err)
		}

		// Verify it's gone
		_, err = testStore.GetSessionByTokenHash(ctx, tokenHash[:])
		if err == nil {
			t.Error("expected error after deleting session, got nil")
		}
	})
}

// --- CleanupExpiredSessions ---

func TestCleanupExpiredSessions(t *testing.T) {
	ctx := context.Background()

	// sessionExists queries the DB directly, ignoring expires_at, to confirm a row is present.
	sessionExists := func(t *testing.T, tokenHash []byte) bool {
		t.Helper()
		var count int
		err := testStore.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM sessions WHERE token_hash = $1`, tokenHash,
		).Scan(&count)
		if err != nil {
			t.Fatalf("sessionExists query failed: %v", err)
		}
		return count > 0
	}

	t.Run("deletes only sessions beyond retention window", func(t *testing.T) {
		email := "cleanup_test@example.com"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })
		userID := mustCreateUser(t, ctx, email, "fakehash")

		// Three sessions with different expiry times
		hashAncient := sha256.Sum256([]byte("token-ancient")) // expired 10 days ago → should be deleted
		hashRecent := sha256.Sum256([]byte("token-recent"))   // expired 3 days ago  → inside 7d window, keep
		hashActive := sha256.Sum256([]byte("token-active"))   // expires tomorrow     → active, keep
		csrf := sha256.Sum256([]byte("csrf"))

		mustCreateSession(t, ctx, userID, hashAncient[:], csrf[:], time.Now().Add(-10*24*time.Hour))
		mustCreateSession(t, ctx, userID, hashRecent[:], csrf[:], time.Now().Add(-3*24*time.Hour))
		mustCreateSession(t, ctx, userID, hashActive[:], csrf[:], time.Now().Add(24*time.Hour))

		n, err := testStore.CleanupExpiredSessions(ctx, 7*24*time.Hour)
		if err != nil {
			t.Fatalf("CleanupExpiredSessions failed: %v", err)
		}
		if n < 1 {
			t.Errorf("expected at least 1 deleted row, got %d", n)
		}

		if sessionExists(t, hashAncient[:]) {
			t.Error("ancient session (10d expired) should have been deleted")
		}
		if !sessionExists(t, hashRecent[:]) {
			t.Error("recent session (3d expired, inside 7d window) should be retained")
		}
		if !sessionExists(t, hashActive[:]) {
			t.Error("active session should not be touched")
		}
	})

	t.Run("returns zero when nothing to delete", func(t *testing.T) {
		n, err := testStore.CleanupExpiredSessions(ctx, 7*24*time.Hour)
		if err != nil {
			t.Fatalf("CleanupExpiredSessions failed: %v", err)
		}
		// Can't assert exactly 0 (other tests may have left rows), just assert no error
		_ = n
	})
}

// --- UpdateUserPassword ---

func TestUpdateUserPassword(t *testing.T) {
	ctx := context.Background()

	t.Run("updates password hash and updated_at", func(t *testing.T) {
		email := "update_pwd@example.com"
		oldHash := "argon2id$old"
		newHash := "argon2id$new"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email) })

		id := mustCreateUser(t, ctx, email, oldHash)

		// Capture created_at before update
		var createdAt time.Time
		if err := testStore.pool.QueryRow(ctx,
			"SELECT created_at FROM users WHERE id = $1", id,
		).Scan(&createdAt); err != nil {
			t.Fatalf("querying created_at: %v", err)
		}

		// Small pause ensures updated_at > created_at
		time.Sleep(2 * time.Millisecond)

		if err := testStore.UpdateUserPassword(ctx, id, newHash); err != nil {
			t.Fatalf("UpdateUserPassword failed: %v", err)
		}

		var dbHash string
		var updatedAt time.Time
		if err := testStore.pool.QueryRow(ctx,
			"SELECT password_hash, updated_at FROM users WHERE id = $1", id,
		).Scan(&dbHash, &updatedAt); err != nil {
			t.Fatalf("querying updated user: %v", err)
		}

		if dbHash != newHash {
			t.Errorf("password_hash: expected %q, got %q", newHash, dbHash)
		}
		if !updatedAt.After(createdAt) {
			t.Errorf("updated_at (%v) should be after created_at (%v)", updatedAt, createdAt)
		}
	})

	t.Run("returns pgx.ErrNoRows for nonexistent user", func(t *testing.T) {
		fakeID, _ := uuid.NewV7()
		err := testStore.UpdateUserPassword(ctx, fakeID, "argon2id$hash")
		if err == nil {
			t.Fatal("expected error for nonexistent user, got nil")
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("expected pgx.ErrNoRows, got %v", err)
		}
	})
}

// --- DeleteAllUserSessions (Postgres) ---

func TestDeleteAllUserSessionsPG(t *testing.T) {
	ctx := context.Background()

	t.Run("removes all sessions for a user", func(t *testing.T) {
		email1 := "session_delall_a@example.com"
		email2 := "session_delall_b@example.com"
		t.Cleanup(func() { cleanupUsersByEmail(t, ctx, email1, email2) })

		userA := mustCreateUser(t, ctx, email1, "fakehash")
		userB := mustCreateUser(t, ctx, email2, "fakehash")

		hashA1 := sha256.Sum256([]byte("token-a1"))
		hashA2 := sha256.Sum256([]byte("token-a2"))
		hashB1 := sha256.Sum256([]byte("token-b1"))
		csrfA1 := sha256.Sum256([]byte("csrf-a1"))
		csrfA2 := sha256.Sum256([]byte("csrf-a2"))
		csrfB1 := sha256.Sum256([]byte("csrf-b1"))
		expiresAt := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)

		mustCreateSession(t, ctx, userA, hashA1[:], csrfA1[:], expiresAt)
		mustCreateSession(t, ctx, userA, hashA2[:], csrfA2[:], expiresAt)
		mustCreateSession(t, ctx, userB, hashB1[:], csrfB1[:], expiresAt)

		// Delete all of userA's sessions
		err := testStore.DeleteAllUserSessions(ctx, userA)
		if err != nil {
			t.Fatalf("DeleteAllUserSessions failed: %v", err)
		}

		// Both of userA's sessions should be gone
		if _, err := testStore.GetSessionByTokenHash(ctx, hashA1[:]); err == nil {
			t.Error("expected session hashA1 to be deleted")
		}
		if _, err := testStore.GetSessionByTokenHash(ctx, hashA2[:]); err == nil {
			t.Error("expected session hashA2 to be deleted")
		}

		// UserB's session should still exist
		_, err = testStore.GetSessionByTokenHash(ctx, hashB1[:])
		if err != nil {
			t.Errorf("userB's session should not be deleted: %v", err)
		}
	})
}
