# Zenlixem: scope boundary (Phase F end)

Zenlixem is **feature-complete** after Phase F.

This is not a dead project; it is a **maintenance-grade** project.

## What Zenlixem does

- `zenlixem`: suite wrapper (metadata + `doctor` + completions)
- `whoholds`: who holds this file / device / port (procfs)
- `lasttouch`: who last modified this file (audit/journalctl when available)
- `envpath`: why this command resolves to this path (PATH resolution)
- `whyopen`: why this path / port is open (narrative reasons)

## Non-goals (explicitly out of scope)

Zenlixem will **not** become:

- a daemon / background service
- a configuration platform
- a plugin system
- a TUI/dashboard/observability stack
- an auto-fix tool

If a change pushes Zenlixem toward any of the above, it should be rejected.

## Post-F loop: allowed changes

All changes must pass this gate:

> Does this reduce overhead / bugs / ambiguity?

Allowed:

- bug fixes
- performance improvements (only with evidence)
- edge-case hardening (real Linux behavior)
- small UX polish (no contract breaks)
- documentation improvements

Not allowed:

- “just one more feature”
- new long-term modes / new configuration systems
- changes that break output contracts

## Output contract

- Human output stays clear and low-noise.
- `--json` stays a single JSON object with stable ordering.
- Backward compatibility matters:
  - Additive JSON fields are OK.
  - Removing/renaming fields is not.

## Release policy

- `v1.0.x` = maintenance releases only.
- If experimentation is needed, do it in a separate repo/project (e.g. `zenlixem-labs`).

## Maintenance docs

- `docs/post-f-checklist.md`
- `docs/perf.md`
