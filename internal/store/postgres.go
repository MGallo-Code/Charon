// Package store handles all database and cache interactions.
//
// postgres.go -- pgxpool connection setup and queries.
// Creates a connection pool at startup, shared across all handlers.
// All queries use parameterized statements (no string concatenation).
package store
