[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/oxyzenQ/zenlixem)

# zenlixem

zenlixem is a small, Linux-focused CLI suite for system introspection.

## Tools (v1.0.0)

- `zenlixem` — suite wrapper (includes `zenlixem doctor`)
- `whoholds` — who holds this file / device / port
- `lasttouch` — who last modified this file
- `envpath` — why this command resolves to this path
- `whyopen` — why this path / port is open (narrative reasons)

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
zenlixem completions bash > zenlixem.bash
```

### Manpages (optional)

```bash
sudo install -Dm644 man/*.1 /usr/local/share/man/man1/
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

## Notes

- Some information sources may require elevated permissions. When a process cannot be inspected due to permissions, the tools will emit warnings.
