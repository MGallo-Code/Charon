// stores.go
//
// Shared mock implementations of auth.Store and auth.SessionCache.
// Imported by test files across packages to avoid duplicate mock definitions.
package testutil

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/MGallo-Code/charon/internal/store"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// MockStore implements auth.Store for tests....

// Always stateful...Users and Sessions are maps, like a real store.
// Use *Err fields to inject errors for specific operations.
// Use NewMockStore to seed users; or construct directly and set *Err fields for error-path tests.
type MockStore struct {
	// Error injection...zero value means no error
	CheckHealthErr         error
	CreateUserErr          error
	GetUserByEmailErr      error
	GetPwdHashByUserIDErr  error
	CreateSessionErr       error
	GetSessionErr          error
	UpdateUserPasswordErr  error
	DeleteSessionErr       error
	DeleteAllSessionsErr   error
	CreateTokenErr         error
	GetTokenByHashErr      error
	MarkTokenUsedErr       error
	ConsumeTokenErr        error
	SetEmailConfirmedAtErr error
	WriteAuditLogErr       error

	Users    map[string]*store.User    // keyed by email
	Sessions map[string]*store.Session // keyed by string(tokenHash)
	Tokens   map[string]*store.Token   // keyed by string(tokenHash)

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
		return nil, fmt.Errorf("fetching user by email: %w", pgx.ErrNoRows)
	}
	return u, nil
}

func (m *MockStore) GetPwdHashByUserID(_ context.Context, id uuid.UUID) (string, error) {
	if m.GetPwdHashByUserIDErr != nil {
		return "", m.GetPwdHashByUserIDErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.Users {
		if u.ID == id {
			return u.PasswordHash, nil
		}
	}
	return "", fmt.Errorf("fetching password hash by user id: %w", pgx.ErrNoRows)
}

func (m *MockStore) UpdateUserPassword(_ context.Context, id uuid.UUID, passwordHash string) error {
	if m.UpdateUserPasswordErr != nil {
		return m.UpdateUserPasswordErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Get user by id
	var u *store.User
	for _, user := range m.Users {
		if user.ID == id {
			u = user
			break
		}
	}
	// Check user find success
	if u == nil {
		return fmt.Errorf("updating user password: %w", pgx.ErrNoRows)
	}
	// Update pwd
	u.PasswordHash = passwordHash
	return nil
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
		return nil, fmt.Errorf("fetching session by token hash: %w", pgx.ErrNoRows)
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

func (m *MockStore) CreateToken(_ context.Context, id, userID uuid.UUID, tokenType string, tokenHash []byte, expiresAt time.Time) error {
	if m.CreateTokenErr != nil {
		return m.CreateTokenErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Tokens == nil {
		m.Tokens = make(map[string]*store.Token)
	}
	m.Tokens[string(tokenHash)] = &store.Token{
		ID:        id,
		UserID:    userID,
		TokenType: tokenType,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}
	return nil
}

func (m *MockStore) GetTokenByHash(_ context.Context, tokenHash []byte, tokenType string) (*store.Token, error) {
	if m.GetTokenByHashErr != nil {
		return nil, m.GetTokenByHashErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tokens[string(tokenHash)]
	if !ok {
		return nil, fmt.Errorf("fetching token by hash: %w", pgx.ErrNoRows)
	}
	return t, nil
}

func (m *MockStore) MarkTokenUsed(_ context.Context, tokenHash []byte) error {
	if m.MarkTokenUsedErr != nil {
		return m.MarkTokenUsedErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tokens[string(tokenHash)]
	if !ok {
		return fmt.Errorf("marking token as used: %w", pgx.ErrNoRows)
	}
	now := time.Now()
	t.UsedAt = &now
	return nil
}

func (m *MockStore) ConsumeToken(_ context.Context, tokenHash []byte, tokenType string) (uuid.UUID, error) {
	if m.ConsumeTokenErr != nil {
		return uuid.UUID{}, m.ConsumeTokenErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tokens[string(tokenHash)]
	if !ok || t.TokenType != tokenType {
		return uuid.UUID{}, fmt.Errorf("consuming token: %w", pgx.ErrNoRows)
	}
	now := time.Now()
	t.UsedAt = &now
	return t.UserID, nil
}

func (m *MockStore) SetEmailConfirmedAt(_ context.Context, userID uuid.UUID) error {
	return m.SetEmailConfirmedAtErr
}

func (m *MockStore) WriteAuditLog(_ context.Context, _ store.AuditEntry) error {
	return m.WriteAuditLogErr
}

func (m *MockStore) CheckHealth(_ context.Context) error {
	return m.CheckHealthErr
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
	CheckHealthErr       error
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

func (m *MockCache) CheckHealth(_ context.Context) error {
	return m.CheckHealthErr
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

// MockRateLimiter implements auth.RateLimiter for tests.
// Set AllowErr to inject a rate limit or unexpected error.
type MockRateLimiter struct {
	AllowErr error
}

func (m *MockRateLimiter) Allow(_ context.Context, _ string, _ store.RateLimit) error {
	return m.AllowErr
}

// MockMailer implements mail.Mailer for tests.
// Set *Err fields to inject send failures.
// Last* fields capture the most recent call's arguments for each method.
type MockMailer struct {
	SendPasswordResetErr     error
	SendEmailVerificationErr error

	// Password reset captures
	LastResetTo        string
	LastResetToken     string
	LastResetFirstName *string
	LastResetLastName  *string

	// Email verification captures
	LastVerifTo        string
	LastVerifToken     string
	LastVerifFirstName *string
	LastVerifLastName  *string
}

func (m *MockMailer) SendPasswordReset(_ context.Context, toEmail, token string, firstName, lastName *string) error {
	m.LastResetTo = toEmail
	m.LastResetToken = token
	m.LastResetFirstName = firstName
	m.LastResetLastName = lastName
	return m.SendPasswordResetErr
}

func (m *MockMailer) SendEmailVerification(_ context.Context, toEmail, token string, firstName, lastName *string) error {
	m.LastVerifTo = toEmail
	m.LastVerifToken = token
	m.LastVerifFirstName = firstName
	m.LastVerifLastName = lastName
	return m.SendEmailVerificationErr
}
