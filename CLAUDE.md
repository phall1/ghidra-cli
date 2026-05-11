# ghidra-cli Navigation Index

See @AGENTS.md for agent-specific instructions.

## Key Files

| What | When |
|------|------|
| `src/main.rs` | Modifying CLI entry point, bridge lifecycle, or output format detection |
| `src/main.rs` `verify_bridge()` | Changing bridge ping verification after connecting to an existing bridge |
| `src/main.rs` `extract_program_from_command()` | Adding new command variants that support `--program` switching |
| `src/cli.rs` | Adding/modifying CLI arguments and subcommands |
| `src/format/mod.rs` | Implementing new output formats or changing format detection logic |
| `src/ghidra/bridge.rs` | Bridge process management (start/stop/status/connect via TCP) |
| `src/ghidra/scripts/GhidraCliBridge.java` | Java bridge server (TCP, command handlers, Ghidra API) |
| `src/ipc/client.rs` | BridgeClient (TCP connection, command methods) |
| `src/ipc/protocol.rs` | BridgeRequest/BridgeResponse wire format |
| `PLAN-java-plugin.md` | Architecture decisions and migration rationale |
| `README.md` | Understanding project architecture or user-facing command documentation |

## Modules

| What | When |
|------|------|
| `src/ghidra/` | Bridge management, Ghidra setup/installation, Java bridge script |
| `src/ipc/` | TCP client, protocol definitions, transport helpers |
| `src/format/` | Handling output format conversion (Table, Compact, JSON, CSV, etc.) |
| `tests/` | Writing integration or unit tests |

## Documentation

| What | When |
|------|------|
| `CHANGELOG.md` | Reviewing version history and release notes |
| `src/ghidra/README.md` | Understanding bridge lifecycle, PID file sequence, TOCTOU elimination, BridgeClient adoption |
| `src/ipc/README.md` | Understanding TCP wire format, BridgeClient API, single implementation rationale |
| `tests/README.md` | Understanding test structure and conventions |


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
