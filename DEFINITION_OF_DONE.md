# Definition of Done

A change is done when each item holds, or a reason it does not is stated. "It runs and
looks right" is not done; "the gate is green AND the green asserts a real outcome" is.

## Correctness

- [ ] The change does what the spec/issue said; scope did not silently grow.
- [ ] Every cross-cutting invariant the touched surfaces are subject to (see
      `INVARIANTS.md`) still holds, and any NEW surface is covered by the same gate.
- [ ] No flat prohibition was added; every guardrail is default-with-audited-override
      with a named owner.

## The gate is real (no rotten green)

- [ ] The relevant checks were RUN and are green.
- [ ] Green means something: the test asserts a real outcome (a count, a value,
      non-emptiness), not just exit code 0. It FAILS if you revert the implementation
      (the revert-test).
- [ ] A missing or empty test suite FAILS, it does not pass vacuously.
- [ ] The check's own config was not edited in the same change it is supposed to guard.

## Evidence

- [ ] For anything with visible output (UI, a chart, a rendered doc), it was checked
      live (a browser/screenshot + a data cross-check), not only diff-reviewed - a diff
      cannot see a render bug.
- [ ] A required CI check is reported "fixed" only when it is GREEN on the PR, not on
      confidence.

## Hygiene

- [ ] No secrets/keys/tokens in the diff.
- [ ] Every imported package resolves in the lockfile/registry (no hallucinated deps).
- [ ] Docs/cross-references the change touches still resolve (no stale paths).
