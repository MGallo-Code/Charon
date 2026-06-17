# INVARIANTS - Charon

The per-repo registry of cross-cutting invariants: rules that must hold across many
surfaces, the single point that enforces each, and the gate that guards it. Read it
before changing a file to see which invariants its surface is subject to.

Scaffolded by `coding-mastermind-init`. The check PATTERN is shared with the rest of
the kit; only the runner is Go (here) instead of Node (SBIC). See `cmd/migration-check`.

## How to read a row

- **Invariant**: the end-state that must hold, as an outcome, never a banned verb.
- **Enforcement point**: the single chokepoint that makes it hold.
- **Gate**: the mechanical check + tier (pre-commit -> local re-run -> CI). POINT guards
  one named site; COVERAGE guarantees no site can silently omit it.
- **Status**: `required-gate` / `advisory-gate` / `point-only` / `advisor-only` / `to-build`.
- **Recur**: times this invariant has regressed (seed estimate; keep current).
- **Detection signals**: a precise, low-false-positive trigger.
- **Escape hatch**: the audited override + named owner (default-with-audited-override).

## Index

| ID | Invariant (end-state) | Enforcement point | Gate (tier) | Status | Recur |
|----|-----------------------|-------------------|-------------|--------|-------|
| INV-1 | migration ordering integrity: every `migrations/*.sql` has a unique 3-digit zero-padded prefix, so `sort.Strings(filename)` order in `store.Migrate` equals intended order and no two collide | the `NNN_name.sql` naming convention applied by `store.Migrate` (filename = `schema_migrations.version` key) | `go run ./cmd/migration-check` (CI + local, COVERAGE, DB-free) | advisory-gate (wire to CI to promote) | 0 |

## Detail

### INV-1 - migration ordering integrity
- **Surfaces**: `migrations/*.sql`.
- **Detection signals**: a new migration whose 3-digit prefix duplicates an existing
  one, or whose name does not match `^\d{3}_[a-z0-9_]+\.sql$`.
- **Escape hatch**: a deliberate convention change is a one-line edit to the prefix
  width in `cmd/migration-check` + a note here; owner = whoever changes the migration
  runner. (`store.Migrate` sorts lexically and keys on the full filename, so the
  invariant is "unique fixed-width prefix," not "never reuse a number.")
- **Recurrence history**: none yet. The check exists so a colliding or mis-padded
  migration fails fast instead of silently reordering on startup.
- **Why a check, not just a rule**: `go vet`/`go build` cannot see filename ordering;
  it is a cross-cutting convention over a directory, so it needs its own coverage check
  (the Go analog of the SBIC platform's static `scripts/ci/*.mjs` checks).

<!-- Add a row when a rule recurs across surfaces. The SECOND recurrence is the trigger
     to promote it from prose to a mechanical gate, not the third. Candidate next
     invariants for an auth service: every handler runs RequireAuth before any store
     access; every audited mutation writes an audit_logs row. -->
