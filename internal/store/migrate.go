package store

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
)

// Migrate applies all pending SQL migrations from the given filesystem.
// Each migration runs in its own transaction — if any statement fails,
// that migration is rolled back entirely. Already-applied migrations are skipped.
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

	for _, filename := range entries {
		// Check if migration already applied
		var exists bool
		err := s.pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)",
			filename,
		).Scan(&exists)
		if err != nil {
			return fmt.Errorf("checking migration %s: %w", filename, err)
		}
		// If migration been applied, skip
		if exists {
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
