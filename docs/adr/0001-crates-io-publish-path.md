# ADR 0001: Crates.io publish path

- **Status**: Accepted
- **Date**: 2026-05-19
- **Closes**: ghidra-cli-7al (E8.6)
- **Supersedes**: —

## Context

The phall1/ghidra-cli fork is preparing v0.2.0 (multi-arch release pipeline,
MCP server, observability baseline). The original akiselev/ghidra-cli
shipped through v0.1.9 with no crates.io publish — but the upstream
maintainer *did* register the name and pushed `0.1.10` to crates.io
after the fork was created.

```
$ cargo search ghidra-cli
ghidra-cli = "0.1.10"    # Rust CLI to run Ghidra headless for reverse
                         #  engineering with Claude Code and other agents
```

The name is therefore not free. Anything we do has to plan around an
existing owner who shipped the same conceptual project. Distribution of
the 0.2.0 binaries themselves is already solved out-of-band: E8.1 builds
multi-arch tarballs in GitHub Releases and E8.2 wired `cargo-binstall`
metadata against those releases. So the question is narrowly about the
*source crate*, not about how end users install the tool.

## Options considered

### A. Take over the crates.io name

Ask the akiselev owner to transfer the crate, or invoke crates.io's
[Trademark Policy / inactive crate transfer process][1] if they decline
or don't respond.

Pros:
- Single canonical name; users searching crates.io land on the active fork.
- `cargo install ghidra-cli` does the obvious thing.
- Future contributors don't have to remember a renamed binary.

Cons:
- Requires upstream cooperation; transfer is not guaranteed.
- The crates.io team is conservative about transfers when the original
  crate is still maintained (and 0.1.10 was published *after* our fork
  diverged, which signals active maintenance).
- Even if we succeed, the version chain becomes confusing:
  `0.1.9` (akiselev) → `0.1.10` (akiselev) → `0.2.0` (phall1) creates a
  semver narrative where 0.1.10 is a "branch" off the trunk.
- Carries reputational risk: looks like a name grab if the optics aren't
  handled well.

### B. Publish under a new name

Use a distinct crate name (e.g. `ghidra-mcp`, `ghidra-cli-mcp`,
`ghidra-rcli`, or a namespaced `phall1-ghidra-cli`).

Pros:
- No cooperation needed from upstream.
- Clear separation: the fork is a different project with different
  goals (LLM-first / MCP / Phase 3 Java-elimination).
- `cargo install <name>` still works; only the source crate name differs
  from the installed binary, which is already true for many CLIs.

Cons:
- Discoverability hit: anyone searching "ghidra cli" on crates.io will
  find the older crate first.
- The README, badges, and shell completions all currently hardcode
  `ghidra-cli` and the binary is `ghidra`. Renaming the crate doesn't
  force renaming the binary, but the mismatch needs documenting.

### C. Don't publish to crates.io

Keep distributing exclusively via GitHub Releases + `cargo-binstall`
(already wired in E8.1/E8.2) and optionally a Homebrew tap (E8.3, P4).

Pros:
- Zero coordination cost.
- Binary distribution is already solved by E8.1/E8.2 — `cargo binstall
  ghidra-cli` pulls our release tarball today via the
  `[package.metadata.binstall]` block in `Cargo.toml`.
- We're a GPL-3.0 binary tool, not a library. Almost nobody builds it
  from a crates.io tarball; the audience installs prebuilts.
- Avoids the "fork stole a name" optics entirely.

Cons:
- No `cargo install ghidra-cli` for users who don't want to install
  `cargo-binstall`. Practical impact: ~one extra command (`cargo install
  cargo-binstall && cargo binstall ghidra-cli`) for the small slice of
  users who prefer building from source via cargo.
- We can't take a name on crates.io later without re-evaluating Option A.
- Less obvious "this is a real Rust project" signal in the Rust ecosystem.

## Decision

**Option C — do not publish to crates.io for v0.2.0.**

Rationale:

1. **The distribution problem is already solved.** E8.1 + E8.2 give us
   `cargo binstall ghidra-cli` against multi-arch GitHub release
   artifacts. That covers >95% of "I just want to run this" install
   flows without any crates.io involvement.

2. **We're a binary, not a library.** Crates.io is most valuable as a
   library index (`cargo add foo`). Binary crates use crates.io
   primarily for source-build distribution, which `cargo-binstall`
   already provides for us through the GitHub release path. There is
   no third-party crate that depends on `ghidra-cli` as a library, and
   we don't intend to publish one.

3. **The name belongs to the upstream maintainer.** akiselev published
   0.1.10 *after* the fork diverged — that's a clear "I am still
   maintaining this" signal. Pursuing a transfer would be adversarial
   and would invite a public dispute that is bad for both projects.

4. **Phase 3 changes the calculus.** Once the JVM is gone (E7), the
   project's shape may differ enough that a new name actually makes
   sense (e.g. `decompile-rs` or similar). Locking ourselves to a name
   today — whether `ghidra-cli` or `ghidra-mcp` — pre-commits to an
   identity that the future tool may not want.

## Consequences

- v0.2.0 ships exclusively via GitHub Releases. The README install
  section will lead with `cargo-binstall` and pre-built tarballs;
  building from source is documented but de-emphasized.
- We re-evaluate publishing to crates.io once *one* of these happens:
  - The fork takes on a stable identity (Phase 3 lands or definitively
    stalls per E7.12).
  - A library carve-out (e.g. an `mcp-ghidra` crate) becomes a
    candidate for crates.io publication independent of the binary.
  - The upstream `ghidra-cli` crate goes inactive for ≥12 months *and*
    we want the name.
- `[package.metadata.binstall]` in `Cargo.toml` stays the canonical
  installation contract. Breaking changes to that block require a new
  ADR.

## Notes

- Crates.io trademark/inactive-crate policy: see [the crates.io
  policies page][1].
- The binary inside the release tarball is named `ghidra-cli` (E8.1
  renamed from `[[bin]] ghidra` for distribution). The Cargo binary
  target keeps its short `ghidra` name for ergonomic developer use.

[1]: https://crates.io/policies
