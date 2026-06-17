// migration-check is a DB-free static check that guards the migration-ordering
// invariant (see INVARIANTS.md, INV-1).
//
// WHY: store.Migrate applies migrations in sort.Strings(filename) order and records
// the full filename as the schema_migrations.version primary key. That ordering is
// only correct if every filename has a unique, zero-padded, fixed-width numeric
// prefix - otherwise lexical order diverges from intended order (e.g. "10_x.sql"
// sorts before "2_x.sql") or two migrations collide on a prefix and their relative
// order becomes an accident of the rest of the name. tsc/go vet cannot see this; it
// is a cross-cutting filename invariant, so it needs its own coverage check.
//
// This mirrors the SBIC platform's static .mjs checks: the same check PATTERN, a
// different runner (Go instead of Node). DB-free, no secrets - runnable in CI and
// locally: `go run ./cmd/migration-check`.
//
// Exit 0: every migration filename is NNN_name.sql with a unique 3-digit prefix.
// Exit 1: a collision or a malformed/zero-length set (fail-closed).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// 3-digit zero-padded prefix, underscore, a name, .sql. Fixed width keeps
// sort.Strings order equal to numeric order.
var nameRe = regexp.MustCompile(`^(\d{3})_[a-z0-9_]+\.sql$`)

func main() {
	dir := "migrations"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migration-check: cannot read %s: %v\n", dir, err)
		os.Exit(1)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".sql" {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	if len(files) == 0 {
		// Fail-closed: an empty set is almost certainly a wrong path, not a pass.
		fmt.Fprintf(os.Stderr, "migration-check: no .sql files in %s - refusing to pass vacuously\n", dir)
		os.Exit(1)
	}

	prefixes := map[string]string{} // prefix -> first filename that used it
	var malformed, collisions []string

	for _, f := range files {
		m := nameRe.FindStringSubmatch(f)
		if m == nil {
			malformed = append(malformed, f)
			continue
		}
		p := m[1]
		if prev, dup := prefixes[p]; dup {
			collisions = append(collisions, fmt.Sprintf("%s collides with %s on prefix %s", f, prev, p))
			continue
		}
		prefixes[p] = f
	}

	fmt.Printf("migration-check: %d migrations, %d distinct prefixes\n", len(files), len(prefixes))

	if len(malformed) == 0 && len(collisions) == 0 {
		fmt.Println("migration-check OK - every migration has a unique 3-digit prefix; lexical order equals intended order.")
		os.Exit(0)
	}

	fmt.Fprintln(os.Stderr, "\nMIGRATION-ORDERING INVARIANT VIOLATED:")
	for _, m := range malformed {
		fmt.Fprintf(os.Stderr, "  malformed (want NNN_name.sql, 3-digit prefix): %s\n", m)
	}
	for _, c := range collisions {
		fmt.Fprintf(os.Stderr, "  collision: %s\n", c)
	}
	fmt.Fprintln(os.Stderr, "\nFix: give each migration a unique zero-padded 3-digit prefix so")
	fmt.Fprintln(os.Stderr, "sort.Strings(filename) order in store.Migrate equals the intended order.")
	os.Exit(1)
}
