# Performance notes (maintenance)

Zenlixem is feature-complete. Performance work is allowed only when it is **measured**.

## Principles

- Optimize the hot path:
  - procfs scanning (PIDs, fd links, maps)
  - string parsing and allocations
  - syscall count per PID
- Avoid speculative rewrites.
- Prefer small changes that reduce:
  - syscalls
  - allocations
  - repeated reads

## Baseline commands

### Build

```bash
./build.sh release
```

### Quick runtime sampling

Run a few times and compare:

```bash
/usr/bin/time -f "elapsed=%e user=%U sys=%S maxrss=%M" ./target/$(rustc -vV | sed -n 's/^host: //p')/release/whoholds --ports --listening >/dev/null
/usr/bin/time -f "elapsed=%e user=%U sys=%S maxrss=%M" ./target/$(rustc -vV | sed -n 's/^host: //p')/release/whyopen 8080 >/dev/null
```

### Under load (optional)

```bash
for i in $(seq 1 10); do /usr/bin/time -f "%e" ./target/$(rustc -vV | sed -n 's/^host: //p')/release/whoholds --ports --listening >/dev/null; done
```

## What to record

For each run, record:

- tool + arguments
- privileged vs unprivileged mode
- elapsed/user/sys time
- max RSS
- approximate PID count

## Common bottlenecks

- repeated reads of `/proc/<pid>/comm`
- iterating all fds for every pid when only a subset matters
- parsing `/proc/net/*` multiple times per command
- building large intermediate vectors before filtering

## Safety

Every performance change must preserve:

- deterministic ordering
- JSON output schema
- correct partial/permission behavior
