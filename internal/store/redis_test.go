package store

import (
	"context"
	"errors"
	"fmt"
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

// --- SetSession TTL ---

func TestSetSessionTTL(t *testing.T) {
	ctx := context.Background()

	// Generally trusting redis to auto-remove expired , but just in case...
	t.Run("session expires after TTL", func(t *testing.T) {
		tokenHash := "testhash_ttl"
		userID, _ := uuid.NewV7()
		session := Session{
			UserID:    userID,
			CSRFToken: []byte("csrf-ttl-padding-to-32-bytes!!!"),
			ExpiresAt: time.Now().Add(2 * time.Second).Truncate(time.Second),
		}
		t.Cleanup(func() {
			testRedis.DeleteSession(ctx, tokenHash, userID)
		})

		// Store with 2-second TTL
		err := testRedis.SetSession(ctx, tokenHash, session, 2)
		if err != nil {
			t.Fatalf("SetSession failed: %v", err)
		}

		// Immediately retrievable
		_, err = testRedis.GetSession(ctx, tokenHash)
		if err != nil {
			t.Fatalf("session should exist immediately: %v", err)
		}

		// Wait for TTL to expire
		time.Sleep(3 * time.Second)

		// Should be gone now
		_, err = testRedis.GetSession(ctx, tokenHash)
		if err == nil {
			t.Error("session should be expired after TTL")
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

// --- Allow ---

// cleanupRateLimit deletes counter and lockout keys for the given rate limit key.
func cleanupRateLimit(t *testing.T, ctx context.Context, key string) {
	t.Helper()
	testRedis.rdb.Del(ctx,
		fmt.Sprintf("rl:counter:%s", key),
		fmt.Sprintf("rl:lockout:%s", key),
	)
}

func TestAllow(t *testing.T) {
	ctx := context.Background()

	t.Run("allows first attempt", func(t *testing.T) {
		key := "test:allow:first_attempt"
		policy := RateLimit{MaxAttempts: 3, Window: time.Minute, LockoutTTL: 5 * time.Minute}
		t.Cleanup(func() { cleanupRateLimit(t, ctx, key) })

		if err := testRateLimiter.Allow(ctx, key, policy); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})

	t.Run("allows attempts under threshold", func(t *testing.T) {
		key := "test:allow:under_threshold"
		policy := RateLimit{MaxAttempts: 3, Window: time.Minute, LockoutTTL: 5 * time.Minute}
		t.Cleanup(func() { cleanupRateLimit(t, ctx, key) })

		// Two attempts (below MaxAttempts=3) should all pass
		for i := 0; i < 2; i++ {
			if err := testRateLimiter.Allow(ctx, key, policy); err != nil {
				t.Fatalf("attempt %d: expected nil, got %v", i+1, err)
			}
		}
	})

	t.Run("threshold attempt is allowed but sets lockout", func(t *testing.T) {
		key := "test:allow:threshold"
		policy := RateLimit{MaxAttempts: 3, Window: time.Minute, LockoutTTL: 5 * time.Minute}
		t.Cleanup(func() { cleanupRateLimit(t, ctx, key) })

		// Hit MaxAttempts -- all should return nil
		for i := 0; i < 3; i++ {
			if err := testRateLimiter.Allow(ctx, key, policy); err != nil {
				t.Fatalf("attempt %d: expected nil, got %v", i+1, err)
			}
		}

		// Lockout key must exist after the final allowed attempt
		if err := testRedis.rdb.Get(ctx, fmt.Sprintf("rl:lockout:%s", key)).Err(); err != nil {
			t.Errorf("expected lockout key after threshold: %v", err)
		}
	})

	t.Run("blocks after threshold", func(t *testing.T) {
		key := "test:allow:blocked"
		policy := RateLimit{MaxAttempts: 3, Window: time.Minute, LockoutTTL: 5 * time.Minute}
		t.Cleanup(func() { cleanupRateLimit(t, ctx, key) })

		// Reach threshold (3 allowed attempts sets lockout)
		for i := 0; i < 3; i++ {
			testRateLimiter.Allow(ctx, key, policy)
		}

		// Next attempt must be rejected
		if err := testRateLimiter.Allow(ctx, key, policy); !errors.Is(err, ErrRateLimitExceeded) {
			t.Errorf("expected ErrRateLimitExceeded, got %v", err)
		}
	})

	t.Run("counter resets after window expires", func(t *testing.T) {
		key := "test:allow:window_reset"
		policy := RateLimit{MaxAttempts: 3, Window: 2 * time.Second, LockoutTTL: 5 * time.Minute}
		t.Cleanup(func() { cleanupRateLimit(t, ctx, key) })

		// One attempt -- counter=1, below threshold, no lockout written
		if err := testRateLimiter.Allow(ctx, key, policy); err != nil {
			t.Fatalf("initial attempt: expected nil, got %v", err)
		}

		// Wait for window to expire
		time.Sleep(3 * time.Second)

		// Counter gone; fresh window, first attempt allowed
		if err := testRateLimiter.Allow(ctx, key, policy); err != nil {
			t.Errorf("after window reset: expected nil, got %v", err)
		}
	})

	t.Run("lockout expires after LockoutTTL", func(t *testing.T) {
		key := "test:allow:lockout_expiry"
		// Short window + lockout so both expire before the second phase, giving a clean reset
		policy := RateLimit{MaxAttempts: 2, Window: 2 * time.Second, LockoutTTL: 2 * time.Second}
		t.Cleanup(func() { cleanupRateLimit(t, ctx, key) })

		// Hit threshold -- triggers lockout
		testRateLimiter.Allow(ctx, key, policy)
		testRateLimiter.Allow(ctx, key, policy)

		// Confirm blocked
		if err := testRateLimiter.Allow(ctx, key, policy); !errors.Is(err, ErrRateLimitExceeded) {
			t.Fatalf("expected ErrRateLimitExceeded immediately after threshold, got %v", err)
		}

		// Wait for both lockout and counter window to expire
		time.Sleep(3 * time.Second)

		// First attempt after full expiry should be allowed
		if err := testRateLimiter.Allow(ctx, key, policy); err != nil {
			t.Errorf("after lockout expiry: expected nil, got %v", err)
		}
	})

	t.Run("independent keys don't share state", func(t *testing.T) {
		keyA := "test:allow:independent_a"
		keyB := "test:allow:independent_b"
		policy := RateLimit{MaxAttempts: 2, Window: time.Minute, LockoutTTL: 5 * time.Minute}
		t.Cleanup(func() {
			cleanupRateLimit(t, ctx, keyA)
			cleanupRateLimit(t, ctx, keyB)
		})

		// Lock out keyA
		testRateLimiter.Allow(ctx, keyA, policy)
		testRateLimiter.Allow(ctx, keyA, policy)

		// keyA is locked
		if err := testRateLimiter.Allow(ctx, keyA, policy); !errors.Is(err, ErrRateLimitExceeded) {
			t.Errorf("keyA: expected ErrRateLimitExceeded, got %v", err)
		}

		// keyB is unaffected
		if err := testRateLimiter.Allow(ctx, keyB, policy); err != nil {
			t.Errorf("keyB: expected nil, got %v", err)
		}
	})
}
