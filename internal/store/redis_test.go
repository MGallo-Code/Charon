package store

import (
	"context"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
)

// --- SetSession + GetSession ---

func TestSetAndGetSession(t *testing.T) {
	ctx := context.Background()

	t.Run("round-trip stores and retrieves session", func(t *testing.T) {
		// Set example vars
		tokenHash := "testhash_set_get"
		userID, _ := uuid.NewV7()
		csrfToken := []byte("test-csrf-redis-roundtrip-32byte")
		session := Session{
			UserID:    userID,
			CSRFToken: csrfToken,
			ExpiresAt: time.Now().Add(1 * time.Hour).Truncate(time.Second),
		}
		t.Cleanup(func() {
			testRedis.DeleteSession(ctx, tokenHash, userID)
		})

		// Store session
		err := testRedis.SetSession(ctx, tokenHash, session, 3600)
		if err != nil {
			t.Fatalf("SetSession failed: %v", err)
		}

		// Retrieve session
		got, err := testRedis.GetSession(ctx, tokenHash)
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}

		// Verify fields match
		if got.UserID != userID {
			t.Errorf("UserID: expected %v, got %v", userID, got.UserID)
		}
		if string(got.CSRFToken) != string(csrfToken) {
			t.Error("CSRFToken does not match")
		}
		if !got.ExpiresAt.Equal(session.ExpiresAt) {
			t.Errorf("ExpiresAt: expected %v, got %v", session.ExpiresAt, got.ExpiresAt)
		}
	})
}

// --- GetSession (miss) ---

func TestGetSessionMiss(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		got, err := testRedis.GetSession(ctx, "nonexistent_token_hash")
		if err == nil {
			t.Fatal("expected error for nonexistent session, got nil")
		}
		if got != nil {
			t.Error("expected nil session on miss")
		}
	})
}

// --- DeleteSession ---

func TestDeleteSession(t *testing.T) {
	ctx := context.Background()

	t.Run("removes session from cache", func(t *testing.T) {
		tokenHash := "testhash_delete"
		userID, _ := uuid.NewV7()
		session := Session{
			UserID:    userID,
			CSRFToken: []byte("test-csrf-redis-delete-32bytes!"),
			ExpiresAt: time.Now().Add(1 * time.Hour).Truncate(time.Second),
		}

		// Store session, then delete it
		if err := testRedis.SetSession(ctx, tokenHash, session, 3600); err != nil {
			t.Fatalf("SetSession failed: %v", err)
		}
		if err := testRedis.DeleteSession(ctx, tokenHash, userID); err != nil {
			t.Fatalf("DeleteSession failed: %v", err)
		}

		// Verify it's gone
		_, err := testRedis.GetSession(ctx, tokenHash)
		if err == nil {
			t.Error("expected error after deleting session, got nil")
		}
	})
}

// --- DeleteAllUserSessions ---

func TestDeleteAllUserSessions(t *testing.T) {
	ctx := context.Background()

	t.Run("removes all sessions for a user", func(t *testing.T) {
		userID, _ := uuid.NewV7()
		otherUserID, _ := uuid.NewV7()

		hash1 := "testhash_user_a1"
		hash2 := "testhash_user_a2"
		hashOther := "testhash_user_b"

		t.Cleanup(func() {
			testRedis.DeleteSession(ctx, hash1, userID)
			testRedis.DeleteSession(ctx, hash2, userID)
			testRedis.DeleteSession(ctx, hashOther, otherUserID)
		})

		// Create two sessions for userID, one for otherUserID
		testRedis.SetSession(ctx, hash1, Session{UserID: userID, CSRFToken: []byte("csrf-a1-padding-to-32-bytes!!!!"), ExpiresAt: time.Now().Add(1 * time.Hour)}, 3600)
		testRedis.SetSession(ctx, hash2, Session{UserID: userID, CSRFToken: []byte("csrf-a2-padding-to-32-bytes!!!!"), ExpiresAt: time.Now().Add(1 * time.Hour)}, 3600)
		testRedis.SetSession(ctx, hashOther, Session{UserID: otherUserID, CSRFToken: []byte("csrf-b1-padding-to-32-bytes!!!!"), ExpiresAt: time.Now().Add(1 * time.Hour)}, 3600)

		// Delete all sessions for userID
		err := testRedis.DeleteAllUserSessions(ctx, userID)
		if err != nil {
			t.Fatalf("DeleteAllUserSessions failed: %v", err)
		}

		// Both of userID's sessions should be gone
		if _, err := testRedis.GetSession(ctx, hash1); err == nil {
			t.Error("expected session hash1 to be deleted")
		}
		if _, err := testRedis.GetSession(ctx, hash2); err == nil {
			t.Error("expected session hash2 to be deleted")
		}

		// Other user's session should still exist
		_, err = testRedis.GetSession(ctx, hashOther)
		if err != nil {
			t.Errorf("other user's session should not be deleted: %v", err)
		}
	})
}
