// migrate.go

// SQL migration runner using embedded filesystem.
package store

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
)

// Migrate applies pending SQL migrations from given filesystem.
// Each migration runs in its own transaction; failures roll back that migration only.
// Already-applied migrations are skipped.
func (s *PostgresStore) Migrate(ctx context.Context, migrationsFS fs.FS) error {
	// Create migration-tracking table if doesn't exist...
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	// Read .sql filenames from embedded filesystem
	entries, err := fs.Glob(migrationsFS, "*.sql")
	if err != nil {
		return fmt.Errorf("reading migration files: %w", err)
	}
	sort.Strings(entries)

	// Fetch all applied versions in one query -- avoids N round trips on startup.
	rows, err := s.pool.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("reading applied migrations: %w", err)
	}
	defer rows.Close()
	applied := make(map[string]bool)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return fmt.Errorf("scanning applied migration: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading applied migrations: %w", err)
	}

	for _, filename := range entries {
		if applied[filename] {
			slog.Info("migration already applied, skipping", "version", filename)
			continue
		}

		// Read SQL file
		sql, err := fs.ReadFile(migrationsFS, filename)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", filename, err)
		}

		// Run file's SQL in a transaction
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("beginning transaction for %s: %w", filename, err)
		}

		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("executing migration %s: %w", filename, err)
		}

		// Update migrations table to show migration applied
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", filename); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("recording migration %s: %w", filename, err)
		}

		// Commit transaction
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing migration %s: %w", filename, err)
		}

		slog.Info("migration applied", "version", filename)
	}

	return nil
}
