# floria

**A programmable local filesystem for secrets and config on macOS.** floria exposes your credentials as plain local files, identifies the reading process at its first observable access, and applies your authorization policy before handing content over — with an audit trail and encrypted secret storage.

```
~/.floria/
├── env/…            # dynamic config files, generated on open
├── secrets/<id>     # encrypted store entries, decrypted per authorized read
└── surfaces/<id>    # composed outputs (.env, direnv, INI) built from managed resources
```

Your tools see ordinary files. `cat`, `ssh`, `psql`, GUI database clients, editors, `mmap` — nothing changes on their side. What changes is that every read is attributed, authorized, and audited.

> **Status: early development.** macOS 26 / Apple Silicon / [macFUSE](https://macfuse.github.io/). On-disk formats and the CLI are still moving; expect breaking changes between versions.

## Why

Secrets on developer machines today are either plaintext files (`.env`, `~/.aws/credentials`, `~/.pgpass` — readable by every process you run) or locked behind CLI wrappers (`op run`, `dotenvx run` — which can't cover GUI apps, IDEs, or system services, and force you to change habits). Named-pipe approaches (1Password Environments) avoid the wrapper, but a FIFO is not a regular file: no stable size, no seek/mmap, concurrent readers race each other — and the kernel never tells the writer *who* is reading.

A user-space filesystem is the only primitive that gives you both: **real files** for compatibility, and a **kernel-delivered caller identity** on every operation for control.

## Features

**Process-level authorization at first access**
- Each observable access boundary is attributed: executable path, arguments, cwd, parent process chain, and code-signing identity (Team ID / bundle ID via `SecCode`), where available. This normally happens at `open()`; if macFUSE reuses a file handle, a new process is authorized on its first read.
- Interactive prompts through a native menubar app — allow once, allow for a duration, or require Touch ID. Decisions cache per app (Team ID) or per repository for interpreters (node/python/… are keyed by their git checkout, not the shared interpreter binary).
- A pf-style rule engine (first-match by descending priority) for standing policy. Built-in rules prompt for secrets and managed outputs; a read-only catch-all allows other reads in monitor mode. Operations that match no rule are denied. Read approvals never silently cover writes — write access is a separate, explicit grant.

**Encrypted, versioned secret store**
- Secrets live as portable [age](https://age-encryption.org)-encrypted blobs. `protect` a file and the original becomes a symlink into the mount; plaintext exists only in memory, per authorized read.
- **Append-only versioning**: every save is a new immutable version behind a movable head pointer. `history` lists versions, `rollback` repoints, nothing is overwritten.
- **Writable through the mount**: editors save in place through the symlink (verified with vim); each save lands as a new version, and concurrent writers append instead of clobbering.
- New installations use a dedicated Floria ed25519 key in the macOS login Keychain. Development configurations can also use an existing SSH ed25519 key, or migrate it into the Keychain with `floria keys import`.

**Project discovery & composed surfaces**
- Point floria at a project directory: it statically scans `.env*`, `.envrc`, `mise.toml`, `~/.aws/credentials`, `~/.pgpass`, and SSH keys — **never executing project code**.
- Secret-shaped keys (`*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_DSN`, …) become reusable, individually-gated shared secrets; plain config (`DEBUG`, `*_ID`, feature flags) stays as ungated env values. Segment-based name matching, overridable per entry at review time.
- The original file is replaced by a link to a *composed surface* that renders shared secrets and plain values back into one `.env`/direnv/INI output. The same value reused across files is stored once, and every resource remembers where it was imported from.

**Audit everything, leak nothing**
- A JSONL audit log records path, decision, matched rule, full process chain, and a sha256 content version — **never plaintext**.
- Metadata-only operations such as `stat` and `readdir` do not generate content or trigger prompts. Dynamic content is generated when an authorized access session is created; applications that read file contents still pass through authorization.

**SSH agent surfaces**
- Filtered `ssh-agent` sockets scoped to an identity set. Each signature request is authorized like a file read, with verified host-key / session-bind context in the prompt and the audit trail.

**Built for parallel AI agents**
- Per-process identity makes "the IDE may read `dev.env`, the coding agent may not touch `prod.env`" an enforceable policy rather than a convention — with a per-agent audit trail.
- Git worktree aware: worktrees are discovered and tracked per project. Auto-provisioning for new worktrees (planned) removes the ".env is gitignored, so every fresh worktree is broken until someone copies files into it" ritual — with zero plaintext copies to leak, instead of one per worktree.

## How it works

```
            open("~/.floria/env/acme/dev.env")
                          │
                    macFUSE (kernel)
                          │  caller pid/uid/gid
                          ▼
   ┌────────────── floria daemon (Rust) ───────────────┐
   │  identity: pid → exe, cwd, parent chain, Team ID    │
   │  policy:   rule engine → allow / deny / prompt ─────┼──▶ menubar app (Swift)
   │  content:  store decrypt / handler / surface render │      prompt + Touch ID
   │  audit:    JSONL (sha256 version, never plaintext)  │
   └─────────────────────────────────────────────────────┘
```

- Rust crates on a strict dependency spine: `floria-core` (config, rule engine, authorization boundary — fully unit-testable, no FUSE dependency), `floria-platform` (process forensics), `floria-fs` (macFUSE backend), `floria-agent` (policy engine + IPC), `floria-store` (encrypted storage), `floria-catalog` / `-surface` / `-discover` / `-control` (workspace model), and the `floria` CLI.
- The Swift menubar app is **pure UI** — prompts, Touch ID, recent access, inventory. Every policy decision lives in the Rust daemon.
- Dynamic read snapshots are isolated by file handle and process lifetime. Repeated reads in that access session return consistent bytes. macFUSE can hide separate POSIX opens by reusing a handle, so multiple opens by the same process may share a snapshot. Opens and reads run off the FUSE event loop, and prompts time out fail-closed before the kernel's deadline.

## Quick start

```bash
# 1. Install macFUSE (one-time; requires approving the kext in System Settings)
brew install --cask macfuse

# 2. From the repository root, install the development toolchain with mise
mise install

# 3. Build and install a local development app in /Applications/Floria.app
# This replaces an existing Floria.app with an ad-hoc build without CloudKit.
mise run install-development-app

# 4. Protect a file through the running daemon
/Applications/Floria.app/Contents/Resources/floria protect ~/my-project/.env
cat ~/my-project/.env          # now served through the mount, gated by policy

# 5. Inspect
/Applications/Floria.app/Contents/Resources/floria list
/Applications/Floria.app/Contents/Resources/floria history '<path|id>'
/Applications/Floria.app/Contents/Resources/floria doctor
```

Install mise and the Xcode command-line tools before building. The installer starts the menubar app and manages the daemon through a LaunchAgent. The app provides authorization prompts, project discovery, and the inventory UI. Local development builds derive socket trust from the built executables; signed releases embed the signing identity. `mise run install-app` is the CloudKit-enabled installation path and requires signing credentials and a provisioning profile.

### Key management

```bash
# For an existing SSH-key-backed store: copy its key into the login Keychain
floria keys import --config ./floria.toml
# Add --remove-file to remove the on-disk key after import and verification.
```

The example config uses `store.key_source = "keychain"`, as do new installations. If the setting is omitted, `"auto"` prefers the configured on-disk SSH key and falls back to the Keychain when that file is absent. For an existing store, import the same key before switching sources so its encrypted blobs remain decryptable.

## Security model (short version)

- **The trust boundary is the local user session.** floria defends against *unauthorized programs* in your session reading credentials silently — not against root, the kernel, or an attacker who already owns your account.
- Authorization denies operations that match no rule. Built-in rules prompt for secrets and managed outputs; other reads have a monitor-mode allow fallback. When authorization requires the agent, an unreachable agent or a prompt timeout denies access before the kernel's deadline.
- Audit logs and catalog metadata never contain secret plaintext; decrypted bytes live in zeroized memory and are served via direct I/O, never written to disk.
- Local socket peers are checked against code-signing requirements. Signed releases embed the product identifiers and Team ID; development builds derive trust from local executable paths. Process-identity collection is best-effort, and PID-reuse race windows remain a known limitation.

## Development

```bash
# Without macFUSE installed (typecheck + unit tests):
cargo test -p floria-core -p floria-platform
cargo clippy --workspace --features floria/macos-no-mount

# Full test suite
cargo test --workspace --features floria/macos-no-mount

# Swift app
cd app && swift build && swift run floria-menubar
```

`floria-core` is deliberately backend-agnostic and fully unit-testable — config parsing, the rule engine, authorization, and snapshot logic all run without a mount. The `macos-no-mount` feature only skips the macFUSE probe for machines without the kext; never enable it for a real mount.

## Roadmap

- Dedicated age X25519 key with `rekey` and recovery recipients
- Worktree auto-provisioning (link new worktrees to their environment automatically)
- Redacted / schema views of secrets for AI agents
- Template renderers (TOML, ERB) for more managed file types

## License

[MIT](LICENSE)
