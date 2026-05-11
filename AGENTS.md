# Agent Instructions

## Critical Rules

1. **NEVER SKIP TESTS!** If Ghidra is not installed, the tests MUST fail. `require_ghidra!()` panics when `ghidra doctor` fails.
2. **DEFAULT OUTPUT FORMAT** should be human and agent readable, NOT JSON. Use `--json` and `--pretty` for JSON output. Exception: when stdout is not a TTY (piped/scripted), the default auto-detects to `JsonCompact` for machine consumption — this is standard Unix pipe convention.

## Architecture

ghidra-cli uses a **direct bridge architecture**:
- CLI connects directly to a Java bridge running inside Ghidra's JVM via TCP
- The bridge is a GhidraScript (`GhidraCliBridge.java`) started via `analyzeHeadless -postScript`
- Bridge binds `ServerSocket(0)` on localhost, writes port/PID files for discovery
- One bridge per project, identified by `~/.local/share/ghidra-cli/bridge-{md5}.port`
- Import/Analyze commands auto-start the bridge if not running
- No separate Rust daemon process — the Java bridge IS the persistent server

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
