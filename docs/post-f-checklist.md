# Post-F checklist (maintenance-grade)

This project is **feature-complete**. Treat every change as maintenance.

## Gate question (must be yes)

> Does this reduce overhead / bugs / ambiguity?

If not, do not merge.

## Local validation (required)

Run from repo root:

```bash
./build.sh check-all --verbose
```

Also run:

```bash
yamllint .github/workflows/*
actionlint .github/workflows/*
```

## Output contract

- Human output:
  - deterministic ordering
  - low noise
  - consistent headers/columns
- JSON output:
  - single JSON object
  - stable ordering of arrays
  - additive fields only (no renames/removals)

## Risk areas (re-test when touched)

- `/proc` scanning hot paths (`whoholds`, `whyopen`)
- permission-restricted environments (`hidepid`, unprivileged mode)
- races: PID exit / PID recycle
- parsing robustness for procfs lines

## Release discipline

- Patch releases only (`v1.0.x`)
- Changes must be small, reviewable, and strongly justified
