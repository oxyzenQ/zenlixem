# zenlixem

zenlixem is a small, Linux-focused CLI suite for system introspection.

## Tools (v1.0.1)

- `zenlixem` — suite wrapper (includes `zenlixem doctor`)
- `whoholds` — who holds this file / device / port
- `lasttouch` — who last modified this file
- `envpath` — why this command resolves to this path
- `whyopen` — why this path / port is open (narrative reasons)

## Project status (maintenance-grade)

- Scope boundary: `FINAL.md`
- Post-F checklist: `docs/post-f-checklist.md`
- Performance notes: `docs/perf.md`

## Supported platforms

Linux only.

## Usage

### `zenlixem`

```bash
zenlixem doctor
```

```bash
zenlixem doctor --json
```

```bash
zenlixem completions bash > zenlixem.bash
```

Exit codes:

- `0` = OK
- `1` = warnings
- `2` = failures

### `whoholds`

```bash
whoholds <TARGET>
```

`TARGET` can be:

- a filesystem path (file, directory, or device node)
- a numeric TCP/UDP port (example: `8080`)

```bash
whoholds /dev/nvme0n1
whoholds /mnt/data
whoholds 8080
```

### `lasttouch`

```bash
lasttouch <PATH>
```

```bash
lasttouch /etc/sysctl.conf
```

### `envpath`

```bash
envpath <COMMAND>
```

`COMMAND` must be a bare command name (no `/` characters).

```bash
envpath gcc
```

### `whyopen`

```bash
whyopen /var/log/syslog
whyopen 8080
```

## Build from source

### Requirements

- Rust toolchain (via `rustup`)
- Linux `x86_64` (amd64) or Linux `aarch64` (arm64)

### Build using `build.sh` (recommended)

```bash
chmod +x ./build.sh

./build.sh check-all
./build.sh release
```

### Shell completions (optional)

```bash
./build.sh install-comp
```

### Manpages (optional)

```bash
sudo ./build.sh install-man
```

Or install both:

```bash
sudo ./build.sh install
```

### Optimized Linux targets

Linux amd64 (universal):

```bash
./build.sh pro-linux-amd64
```

Outputs:

- `target/x86_64-unknown-linux-gnu/release/zenlixem`
- `target/x86_64-unknown-linux-gnu/release/whoholds`
- `target/x86_64-unknown-linux-gnu/release/lasttouch`
- `target/x86_64-unknown-linux-gnu/release/envpath`
- `target/x86_64-unknown-linux-gnu/release/whyopen`

Linux arm64 (universal):

```bash
./build.sh pro-linux-arm64
```

Outputs:

- `target/aarch64-unknown-linux-gnu/release/zenlixem`
- `target/aarch64-unknown-linux-gnu/release/whoholds`
- `target/aarch64-unknown-linux-gnu/release/lasttouch`
- `target/aarch64-unknown-linux-gnu/release/envpath`
- `target/aarch64-unknown-linux-gnu/release/whyopen`

Note: building for `aarch64-unknown-linux-gnu` typically requires building on an arm64 machine, or configuring an aarch64 cross-toolchain + linker.

### Build using Cargo (no script)

```bash
cargo build --release -p zenlixem
cargo build --release -p whoholds
cargo build --release -p lasttouch
cargo build --release -p envpath
cargo build --release -p whyopen
```

### Static binaries (optional)

```bash
cross build --release --target x86_64-unknown-linux-musl -p zenlixem -p whoholds -p lasttouch -p envpath -p whyopen
```

### Run from source tree

```bash
cargo run -p zenlixem -- doctor
cargo run -p whoholds -- /mnt/data
cargo run -p lasttouch -- /etc/sysctl.conf
cargo run -p envpath -- gcc
cargo run -p whyopen -- /mnt/data
```

## Examples

```bash
whoholds /dev/nvme0n1
whoholds 8080
whoholds /mnt/data

lasttouch /etc/sysctl.conf

envpath gcc

whyopen /mnt/data
whyopen 8080
```

## Common Flags

All tools support:

- `-i` / `--info` — print build and version information
- `--json` — output result as JSON

`whoholds` additionally supports:

- `--ports` — scan all ports
- `--listening` — filter to listening sockets (use with `--ports`)
- `--established` — filter to established TCP sockets (use with `--ports`)

## Notes

- Some information sources may require elevated permissions. When a process cannot be inspected due to permissions, the tools will emit warnings.

## Limitations

- **lasttouch** cannot always determine the real actor who modified a file. When audit log and journalctl data are unavailable, it falls back to filesystem metadata (mtime), which provides a timestamp but no identity information. Metadata fallback is not proof of who made the change.
- **whoholds** and **whyopen** rely on procfs scanning. Results depend on the caller's permissions: unprivileged users will see partial results when `/proc/<pid>/fd` or `/proc/<pid>/maps` is inaccessible. Systems with `hidepid=2` mounted on `/proc` will restrict most PID information from unprivileged users.
- **Containers and namespaces**: when running inside a container, `/proc` shows only the container's PID namespace. whoholds/whyopen will not see host processes or sockets outside the container's network namespace.
- **Audit log parsing** only covers x86_64 and aarch64 syscall tables. On other Linux architectures, lasttouch will fall back to the x86_64 table with a warning, which may misclassify events.
- **Race conditions**: processes may exit or be recycled between the time their PID is enumerated and their fd/maps are read. The tools tolerate vanished PIDs gracefully but may miss short-lived processes.
