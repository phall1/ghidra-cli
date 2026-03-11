# Claude Binary Reverse Engineering Plan (Bun Runtime)

## Goal

Produce a high-confidence design/spec for the Claude CLI binary at:

- symlink: `/Users/phall/.local/bin/claude`
- resolved binary: `/Users/phall/.local/share/claude/versions/2.1.58`
- SHA-256: `182c20c6080d042e4e08a6b2a2ce8258c1a50e53c01d36ddf20a82b4693395ea`

This plan is written so work can resume immediately with no extra context.

## Current Known State

- Repository: `ghidra-cli`
- Existing Ghidra projects: `claude-re.rep`, `openssl-re.rep`
- Prior issue encountered: long analysis looked like hangs due to weak observability and command timeout cuts.
- Important technical constraint: this target is Bun-embedded (`Mach-O arm64`), so static function decompilation is dominated by runtime internals.

## Immediate Start Checklist

Run this exact sequence first.

1. Confirm target identity:

```bash
ls -l /Users/phall/.local/bin/claude
readlink /Users/phall/.local/bin/claude
file /Users/phall/.local/share/claude/versions/2.1.58
shasum -a 256 /Users/phall/.local/share/claude/versions/2.1.58
```

2. Ensure local environment is valid:

```bash
just doctor
```

3. If project state is inconsistent, reset local analysis state (destructive local cache cleanup):

```bash
NUKE_CONFIRM=YES just nuke
just bootstrap
```

4. Use detached/observable import path to avoid false "hang" diagnosis:

```bash
./scripts/with-ghidra-env.sh target/debug/ghidra import \
  "/Users/phall/.local/bin/claude" \
  --project claude-re \
  --program claude_2_1_58 \
  --detach
```

5. Poll bridge/project status in short intervals:

```bash
./scripts/with-ghidra-env.sh target/debug/ghidra status --project claude-re
./scripts/with-ghidra-env.sh target/debug/ghidra program list --project claude-re
```

## Ideal Setup (Operational)

### Runtime + Tooling

- Use `just`/`mise` wrappers to keep Java/Ghidra env consistent.
- Prefer `target/debug/ghidra` via `./scripts/with-ghidra-env.sh` for repeatability.
- Keep one active project per target binary/version (`claude-re` for Claude 2.1.58).

### Observability Rules

- Avoid single giant blocking commands with fixed short timeout.
- Use `--detach` for import/analyze when binary is large.
- Use frequent status probes (`ghidra status`, `program list`) instead of waiting blindly.
- When needed, run in PTY session so output is visible continuously.

### Data Hygiene

- Always record exact binary hash at session start.
- Treat each binary version as a separate evidence set.
- Never mix findings across hashes/versions in final spec.

## Why Bun Needs Hybrid RE (Not Static-Only)

For Bun-packed binaries, static decompilation mostly surfaces runtime machinery. To isolate Claude-specific behavior, use hybrid analysis:

1. Static triage (imports, exports, strings, xrefs)
2. Embedded resource/module extraction
3. Dynamic runtime tracing (file/network/process/env)
4. Correlate runtime events back to static anchors

Static-only decomp for this target will over-index on Bun internals and under-deliver product-level architecture.

## Execution Plan

### Phase 1: Binary and Surface Mapping

Objective: build an evidence index for known anchors.

Commands:

```bash
./scripts/with-ghidra-env.sh target/debug/ghidra summary --project claude-re --program claude_2_1_58 --pretty
./scripts/with-ghidra-env.sh target/debug/ghidra stats --project claude-re --program claude_2_1_58 --pretty
./scripts/with-ghidra-env.sh target/debug/ghidra dump imports --project claude-re --program claude_2_1_58 --pretty
./scripts/with-ghidra-env.sh target/debug/ghidra dump exports --project claude-re --program claude_2_1_58 --pretty
./scripts/with-ghidra-env.sh target/debug/ghidra strings list --project claude-re --program claude_2_1_58 --limit 1000 --pretty
```

Deliverable:

- `docs/reports/claude-re/phase1-surface-map.md` with categorized symbol/string clusters.

### Phase 2: Claude-Specific Anchor Discovery

Objective: separate product anchors from Bun/runtime anchors.

Key string pivots:

- `anthropic`
- `claude`
- `CLAUDE.md`
- `api`
- `https://`
- `model`
- `auth`

Commands:

```bash
./scripts/with-ghidra-env.sh target/debug/ghidra find string "anthropic" --project claude-re --program claude_2_1_58 --pretty
./scripts/with-ghidra-env.sh target/debug/ghidra find string "claude" --project claude-re --program claude_2_1_58 --pretty
./scripts/with-ghidra-env.sh target/debug/ghidra find string "https://" --project claude-re --program claude_2_1_58 --limit 300 --pretty
```

Then xref each high-value hit to recover nearby functions/basic blocks.

Deliverable:

- `docs/reports/claude-re/phase2-anchor-map.md`

### Phase 3: Embedded Asset/Module Recovery

Objective: recover likely bundled JS/assets/config that carry app semantics.

Approach:

- identify long string blobs and known bundle markers
- detect compressed or packed regions in memory map
- extract candidate sections and decode/decompress where applicable

Deliverable:

- `docs/reports/claude-re/phase3-embedded-assets.md`
- extracted artifacts under `docs/reports/claude-re/artifacts/`

### Phase 4: Dynamic Behavior Correlation

Objective: map runtime behavior to static anchors.

Actions:

- run Claude with benign commands and capture file/network/process traces
- capture env var reads, config path access, and outbound host patterns
- correlate trace evidence with static addresses/strings from phases 1-3

Deliverable:

- `docs/reports/claude-re/phase4-dynamic-correlation.md`

### Phase 5: Final Design/Spec

Objective: produce architecture/spec with confidence ratings.

Required sections:

1. Binary profile and provenance
2. Startup sequence and lifecycle
3. Command parsing and dispatch model
4. Configuration and state paths
5. Network/API interaction model
6. File/FS behavior and workspace semantics
7. Security-relevant behavior
8. Known unknowns and confidence levels

Output path:

- `docs/reverse-engineering-claude-spec.md`

## Reporting Format (Per Session)

At end of each RE session, append:

- commands run
- hashes/version checked
- findings gained
- unresolved unknowns
- next exact command to run

Session log path:

- `docs/reports/claude-re/session-log.md`

## Fast Resume Procedure

If returning after interruption:

1. Re-verify hash/version (checklist step 1).
2. Open latest session log entry.
3. Run the recorded "next exact command."
4. Continue from first incomplete phase deliverable.

## Success Criteria

This effort is complete only when:

- Claude-specific architecture is separated from Bun runtime internals
- each major behavior claim has at least one static or dynamic evidence anchor
- unresolved unknowns are explicit and bounded
- `docs/reverse-engineering-claude-spec.md` is present and self-contained
