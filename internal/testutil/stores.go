// stores.go
//
// Shared mock implementations of auth.Store and auth.SessionCache.
// Imported by test files across packages to avoid duplicate mock definitions.
package testutil

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
)

// MockStore implements auth.Store for tests....

// Always stateful...Users and Sessions are maps, like a real store.
// Use *Err fields to inject errors for specific operations.
// Use NewMockStore to seed users; or construct directly and set *Err fields for error-path tests.
type MockStore struct {
	// Error injection...zero value means no error
	CreateUserErr      error
	GetUserByEmailErr  error
	CreateSessionErr   error
	GetSessionErr      error
	DeleteSessionErr   error
	DeleteAllSessionsErr error

	Users    map[string]*store.User    // keyed by email
	Sessions map[string]*store.Session // keyed by string(tokenHash)

	mu sync.Mutex
}

// NewMockStore returns a MockStore seeded with the given users, indexed by email.
func NewMockStore(users ...*store.User) *MockStore {
	ms := &MockStore{
		Users:    make(map[string]*store.User),
		Sessions: make(map[string]*store.Session),
	}
	for _, u := range users {
		if u.Email != nil {
			ms.Users[*u.Email] = u
		}
	}
	return ms
}

func (m *MockStore) CreateUserByEmail(_ context.Context, id uuid.UUID, email, passwordHash string) error {
	return m.CreateUserErr
}

func (m *MockStore) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	if m.GetUserByEmailErr != nil {
		return nil, m.GetUserByEmailErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[email]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (m *MockStore) CreateSession(_ context.Context, id uuid.UUID, userID uuid.UUID, tokenHash []byte, csrfToken []byte, expiresAt time.Time, ip *string, userAgent *string) error {
	if m.CreateSessionErr != nil {
		return m.CreateSessionErr
	}
	m.mu.Lock()
	if m.Sessions == nil {
		m.Sessions = make(map[string]*store.Session)
	}
	m.Sessions[string(tokenHash)] = &store.Session{
		ID:        id,
		UserID:    userID,
		TokenHash: tokenHash,
		CSRFToken: csrfToken,
		ExpiresAt: expiresAt,
	}
	m.mu.Unlock()
	return nil
}

func (m *MockStore) GetSessionByTokenHash(_ context.Context, tokenHash []byte) (*store.Session, error) {
	if m.GetSessionErr != nil {
		return nil, m.GetSessionErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Sessions[string(tokenHash)]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (m *MockStore) DeleteSession(_ context.Context, tokenHash []byte) error {
	if m.DeleteSessionErr != nil {
		return m.DeleteSessionErr
	}
	m.mu.Lock()
	delete(m.Sessions, string(tokenHash))
	m.mu.Unlock()
	return nil
}

func (m *MockStore) DeleteAllUserSessions(_ context.Context, userID uuid.UUID) error {
	if m.DeleteAllSessionsErr != nil {
		return m.DeleteAllSessionsErr
	}
	m.mu.Lock()
	for key, s := range m.Sessions {
		if s.UserID == userID {
			delete(m.Sessions, key)
		}
	}
	m.mu.Unlock()
	return nil
}

// MockCache implements auth.SessionCache for tests.
// Always stateful...Sessions is a map, like a real cache.
// Use *Err fields to inject errors for specific operations.
type MockCache struct {
	// Error injection...zero value means no error
	SetSessionErr        error
	DeleteSessionErr     error
	DeleteAllSessionsErr error

	Sessions map[string]*store.CachedSession // keyed by base64 token hash

	mu sync.Mutex
}

// NewMockCache returns an empty MockCache ready for use.
func NewMockCache() *MockCache {
	return &MockCache{
		Sessions: make(map[string]*store.CachedSession),
	}
}

func (m *MockCache) GetSession(_ context.Context, tokenHash string) (*store.CachedSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Sessions[tokenHash]
	if !ok {
		return nil, errors.New("cache miss")
	}
	return s, nil
}

func (m *MockCache) SetSession(_ context.Context, tokenHash string, sessionData store.Session, ttl int) error {
	if m.SetSessionErr != nil {
		return m.SetSessionErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Sessions == nil {
		m.Sessions = make(map[string]*store.CachedSession)
	}
	m.Sessions[tokenHash] = &store.CachedSession{
		UserID:    sessionData.UserID,
		CSRFToken: sessionData.CSRFToken,
		ExpiresAt: sessionData.ExpiresAt,
	}
	return nil
}

func (m *MockCache) DeleteSession(_ context.Context, tokenHash string, userID uuid.UUID) error {
	if m.DeleteSessionErr != nil {
		return m.DeleteSessionErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Sessions, tokenHash)
	return nil
}

func (m *MockCache) DeleteAllUserSessions(_ context.Context, userID uuid.UUID) error {
	if m.DeleteAllSessionsErr != nil {
		return m.DeleteAllSessionsErr
	}
	m.mu.Lock()
	for key, s := range m.Sessions {
		if s.UserID == userID {
			delete(m.Sessions, key)
		}
	}
	m.mu.Unlock()
	return nil
}
