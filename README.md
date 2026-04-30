# copyfail-rs

Rust implementation of CVE-2026-31431 (Copy Fail) — a Linux kernel page-cache write primitive via AF_ALG splice.

[中文文档 / Chinese README](README_CN.md)

## CVE-2026-31431

The Linux kernel's `algif_aead` implementation allows an unprivileged user to write arbitrary data into the page cache of any readable file via the `splice()` syscall. The `authencesn` AEAD algorithm writes `seqno_lo` (user-controlled AAD bytes 4-7) into the destination scatterlist at offset `assoclen + cryptlen`, which — when chained to page-cache pages via `splice()` — results in an arbitrary 4-byte write. On-disk content remains unchanged, but all subsequent readers see corrupted page-cache data.

**Affected kernels:** Linux < 6.12.23, < 6.13.11, < 6.14.2

## Features

| Flag | Description |
|---|---|
| `--check` | Safe preflight: inspect the resolved `su` target and exit |
| `--escalate` | Patch `/etc/passwd` in page cache to remove root password, then `su root` |
| `--set-password` | Escalate first, then read a new root password from stdin and apply it via `chpasswd` |
| `--uid` | Flip current user's UID to 0 in `/etc/passwd`, then `su <username>` |
| `--backup <path>` | Backup the `su` binary before overwriting |
| `--exec <path>` | Run a specific command as root after overwrite |

### Escalation Modes

**1. `--uid`** — Flips the current user's UID field to `0000` in `/etc/passwd` via page-cache write. After patching, `su <username>` with your own password drops a root shell. The tool attempts to clear the page cache after authentication and before starting the shell, which reduces the chance of SSH continuing to see the account as UID 0. No root password modification needed. Works for any 4-digit UID (1000-9999).

**2. `--escalate`** — Patches the root line in `/etc/passwd` via page-cache write: `root:x:0:0:root:...` → `root::0:0:root :...`. The comment field is padded with spaces to keep line length identical. After patching, `su root` works without a password.

**3. `--set-password`** — First escalates (removes root password), then reads the new password from stdin and applies it with `chpasswd`.

**4. Default mode (no flags)** — Overwrites the page cache of the `su` binary with architecture-specific shellcode payloads (x86_64, x86, aarch64), then executes `su` to gain a root shell.

## Build

```bash
cargo build
cargo build --release
cargo test
cargo clippy
```

## Usage

```bash
./copyfail-rs --check
./copyfail-rs --uid
./copyfail-rs --escalate
printf '%s\n' 'mypassword' | ./copyfail-rs --set-password
./copyfail-rs --backup /tmp/su.bak
./copyfail-rs --exec /bin/bash
```

## Recovery

Page-cache modifications are volatile — clearing the cache restores the original on-disk content:

```bash
echo 3 > /proc/sys/vm/drop_caches
```

## Verified On

| OS | Kernel | Result |
|---|---|---|
| Ubuntu 22.04.2 LTS | 6.8.0-87-generic | `--escalate` pass, `--set-password` pass, `--uid` pass |
| Ubuntu 22.04.2 LTS | 6.8.0-107-generic | `--escalate` pass, `--uid` pass |
| Ubuntu 25.10 | 6.17.0-5-generic | splice EINVAL, kernel patched |
| Ubuntu 25.10 | 6.17.0-8-generic | `--uid` pass |
| Alpine Linux edge | 6.19.12 | Exploit runs, page-cache write blocked by kernel fix |

## Documentation

- [Quick Start](docs/quick-start.md)
- [Vulnerability Principle](docs/principle.md)
- [Demo](docs/demo.md)
- [Defense & Mitigation](docs/mitigation.md)

## License

This project is provided for authorized security testing and educational purposes only.
