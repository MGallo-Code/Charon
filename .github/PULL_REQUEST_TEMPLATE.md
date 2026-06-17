<!-- coding-mastermind PR template. Keep it short; the goal is a real self-check, not theater. -->

## What and why

<one or two lines: the outcome this PR delivers, and the issue/spec it serves>

## Invariants touched

<which `INVARIANTS.md` rows the changed surfaces are subject to; for each, how this PR
keeps it (helper-routed / gate covers the new surface / pgTAP-pinned / logged override).
"none" is a valid answer if the surfaces match no registry row.>

## Definition of Done

- [ ] Does what the issue/spec said; scope did not silently grow.
- [ ] Required CI checks are GREEN on this PR (not "will be green").
- [ ] The relevant gate's green asserts a real outcome and FAILS if the implementation
      is reverted (no rotten green).
- [ ] Any NEW instance of a covered invariant's surface is seen by its gate.
- [ ] No secrets in the diff; imported packages all resolve.
- [ ] Visible output verified live (browser/screenshot + data cross-check), if any.
- [ ] Migration includes a rollback note, if any.

## Blast radius

<the files this PR was expected to touch; flag anything outside that set>
