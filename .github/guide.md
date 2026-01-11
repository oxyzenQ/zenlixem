# GitHub Actions Guide (Zenlixem)

This repository uses GitHub Actions to keep `main` green and to publish release artifacts when you push a version tag.

## Workflows

### 1) CI (`.github/workflows/ci.yml`)

**Triggers**

- Push to `main`
- Pull requests

**Jobs**

- `lint_test`
  - `cargo build --all-targets` (debug)
  - `yamllint .github/workflows/*`
  - `actionlint .github/workflows/*`
  - `./build.sh check-all --verbose`

- `build` (matrix)
  - Builds release binaries for:
    - `linux-amd64` (`x86_64-unknown-linux-gnu`)
    - `linux-aarch64` (`aarch64-unknown-linux-gnu`)
  - Uses `cross` for consistent cross-compilation.

### 2) Release (`.github/workflows/release.yml`)

**Trigger**

- Push tags matching `v*`

**Gate (must be green before publishing)**

- `verify` job runs the same checks as CI:
  - `yamllint .github/workflows/*`
  - `actionlint .github/workflows/*`
  - `./build.sh check-all --verbose`

**Artifacts**

- For each target (matrix), the workflow builds and packages:
  - `zenlixem`
  - `whoholds`
  - `lasttouch`
  - `envpath`

Artifacts are uploaded as:

- `zenlixem-linux-amd64.tar.gz`
- `zenlixem-linux-aarch64.tar.gz`
- `*.sha512sum`

## Release tags and prerelease logic

The Release workflow automatically decides whether the GitHub Release is a **latest stable release** or a **pre-release** based on the tag name:

- Stable (latest):
  - `v1.0.0`

- Pre-release:
  - `v1.0.0-alpha.1`
  - `v1.0.0-beta.1`
  - `v1.0.0-rc.1`

**Rule:** if the tag contains `-` (dash), it is treated as a pre-release.

## How to publish a release

1. Make sure `main` is green.
2. Create a tag:

```bash
git tag v1.0.1
```

Or pre-release:

```bash
git tag v1.0.1-rc.1
```

3. Push the tag:

```bash
git push origin v1.0.1
```

The workflow will build, package, and publish the release assets automatically.

## Local checks (required before pushing core/workflow changes)

Run these from the repository root:

```bash
yamllint .github/workflows/*
actionlint .github/workflows/*
./build.sh check-all --verbose
```

## Local optimized builds

The repository provides `cargo` aliases (via `.cargo/config.toml`) and matching `build.sh` commands.

Examples:

```bash
cargo linux-amd64-universal
cargo linux-amd64-universal-tiny
cargo linux-aarch64-universal
cargo linux-aarch64-universal-tiny
```

These commands build using custom Cargo profiles and stage the resulting binaries into:

`target/<target-triple>/release/`
