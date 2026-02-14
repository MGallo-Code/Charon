package store

import (
	"context"
	"testing"
	"testing/fstest"
)

// --- Migrate ---

func TestMigrate(t *testing.T) {
	ctx := context.Background()

	t.Run("applies migration and records version", func(t *testing.T) {
		// Map file for testing
		testFS := fstest.MapFS{
			"900_test_migrate.sql": &fstest.MapFile{
				Data: []byte("CREATE TABLE test_migrate_tbl (id INT);"),
			},
		}
		t.Cleanup(func() {
			testStore.pool.Exec(ctx, "DROP TABLE IF EXISTS test_migrate_tbl")
			testStore.pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version = $1", "900_test_migrate.sql")
		})

		// Attempt to migrate, if failed return err
		err := testStore.Migrate(ctx, testFS)
		if err != nil {
			t.Fatalf("Migrate failed: %v", err)
		}

		// Verify table was created
		var tableExists bool
		err = testStore.pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'test_migrate_tbl')",
		).Scan(&tableExists)
		if err != nil {
			t.Fatalf("checking table existence: %v", err)
		}
		if !tableExists {
			t.Error("expected test_migrate_tbl to exist after migration")
		}

		// Verify version recorded
		var recorded bool
		err = testStore.pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)",
			"900_test_migrate.sql",
		).Scan(&recorded)
		if err != nil {
			t.Fatalf("checking schema_migrations: %v", err)
		}
		if !recorded {
			t.Error("expected migration version to be recorded in schema_migrations")
		}
	})

	t.Run("skips already-applied migrations", func(t *testing.T) {
		// Map new file to test fs
		testFS := fstest.MapFS{
			"901_test_idempotent.sql": &fstest.MapFile{
				Data: []byte("CREATE TABLE test_idempotent_tbl (id INT);"),
			},
		}
		t.Cleanup(func() {
			testStore.pool.Exec(ctx, "DROP TABLE IF EXISTS test_idempotent_tbl")
			testStore.pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version = $1", "901_test_idempotent.sql")
		})

		// Run twice
		if err := testStore.Migrate(ctx, testFS); err != nil {
			t.Fatalf("first Migrate: %v", err)
		}
		if err := testStore.Migrate(ctx, testFS); err != nil {
			t.Fatalf("second Migrate: %v", err)
		}

		// Should still be exactly one record
		var count int
		err := testStore.pool.QueryRow(ctx,
			"SELECT COUNT(*) FROM schema_migrations WHERE version = $1",
			"901_test_idempotent.sql",
		).Scan(&count)
		if err != nil {
			t.Fatalf("counting migrations: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 migration record, got %d", count)
		}
	})

	t.Run("rolls back on bad SQL", func(t *testing.T) {
		testFS := fstest.MapFS{
			"902_test_bad.sql": &fstest.MapFile{
				Data: []byte("THIS IS NOT VALID SQL;"),
			},
		}
		t.Cleanup(func() {
			testStore.pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version = $1", "902_test_bad.sql")
		})

		err := testStore.Migrate(ctx, testFS)
		if err == nil {
			t.Fatal("expected error for bad SQL, got nil")
		}

		// Verify version NOT recorded (transaction rolled back)
		var recorded bool
		err = testStore.pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)",
			"902_test_bad.sql",
		).Scan(&recorded)
		if err != nil {
			t.Fatalf("checking schema_migrations: %v", err)
		}
		if recorded {
			t.Error("bad migration should not be recorded in schema_migrations")
		}
	})

	t.Run("applies migrations in sorted order", func(t *testing.T) {
		// Second migration depends on first, proves ordering works
		testFS := fstest.MapFS{
			"903_test_order_a.sql": &fstest.MapFile{
				Data: []byte("CREATE TABLE test_order_tbl (id INT);"),
			},
			"904_test_order_b.sql": &fstest.MapFile{
				Data: []byte("ALTER TABLE test_order_tbl ADD COLUMN name TEXT;"),
			},
		}
		t.Cleanup(func() {
			testStore.pool.Exec(ctx, "DROP TABLE IF EXISTS test_order_tbl")
			testStore.pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version LIKE '90%_test_order%'")
		})

		// If order is wrong, ALTER fails because table doesn't exist yet
		err := testStore.Migrate(ctx, testFS)
		if err != nil {
			t.Fatalf("Migrate failed: %v", err)
		}

		// Verify both were applied
		var count int
		err = testStore.pool.QueryRow(ctx,
			"SELECT COUNT(*) FROM schema_migrations WHERE version LIKE '90%_test_order%'",
		).Scan(&count)
		if err != nil {
			t.Fatalf("counting migrations: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2 migration records, got %d", count)
		}
	})

	// Straightforward!...
	t.Run("handles empty filesystem", func(t *testing.T) {
		testFS := fstest.MapFS{}

		err := testStore.Migrate(ctx, testFS)
		if err != nil {
			t.Fatalf("Migrate with empty FS should not error, got: %v", err)
		}
	})
}
