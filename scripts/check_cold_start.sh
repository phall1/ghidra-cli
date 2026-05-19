#!/usr/bin/env bash
#
# check_cold_start.sh - Cold-start regression gate for the Ghidra JVM bridge.
# Closes beads ghidra-cli-eqy (E2.7) and ghidra-cli-c0s (E3.6) as a shared
# implementation: both issues require asserting `cold_start_ms < threshold`
# off a clean-state import of a canonical binary.
#
# Workflow:
#   1. Resolve threshold from `.cold-start-threshold` at repo root
#      (single source of truth; ratchet down by editing this file).
#   2. Tear down any cached bridge + Ghidra project for the test name so
#      the measurement reflects a true cold start (JVM boot + Ghidra init
#      + bridge bind), not a warm-cache pop.
#   3. Import a fixed canonical binary, which spawns analyzeHeadless and
#      causes `start_bridge()` to emit a `jvm_cold_start` event into
#      `${XDG_DATA_HOME:-$HOME/.local/share}/ghidra-cli/cold-start.json`.
#   4. Stop the bridge (clean teardown, not a kill).
#   5. Read `cold_start_ms` from the snapshot and compare to threshold.
#
# Exit codes:
#   0  - cold start under threshold (pass)
#   1  - cold start at or over threshold (regression)
#   2  - usage / configuration error
#   77 - prerequisite missing (Ghidra not installed); skipped, not failed.
#        Treat as success in CI so the gate is non-blocking on dev laptops
#        without Ghidra.
#
# Env vars:
#   GHIDRA_CLI_BIN     - path to the ghidra-cli binary (default: cargo run --)
#   COLD_START_PROJECT - project name to use (default: ci-cold-start)
#   COLD_START_BINARY  - binary to import (default: tests/fixtures/sample_binary)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

THRESHOLD_FILE="${REPO_ROOT}/.cold-start-threshold"
if [[ ! -f "${THRESHOLD_FILE}" ]]; then
    echo "error: threshold file missing: ${THRESHOLD_FILE}" >&2
    exit 2
fi
THRESHOLD_MS="$(tr -d '[:space:]' < "${THRESHOLD_FILE}")"
if ! [[ "${THRESHOLD_MS}" =~ ^[0-9]+$ ]]; then
    echo "error: invalid threshold (${THRESHOLD_MS}); expected integer ms" >&2
    exit 2
fi

PROJECT="${COLD_START_PROJECT:-ci-cold-start}"
BINARY="${COLD_START_BINARY:-${REPO_ROOT}/tests/fixtures/sample_binary}"

if [[ ! -f "${BINARY}" ]]; then
    echo "error: canonical binary not found: ${BINARY}" >&2
    echo "hint: build it with: rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs" >&2
    exit 2
fi

# Resolve the data directory the same way bridge.rs::get_data_dir does
# (dirs::data_local_dir + "ghidra-cli"). Linux uses $XDG_DATA_HOME or
# $HOME/.local/share; macOS uses $HOME/Library/Application Support.
case "$(uname -s)" in
    Darwin) DATA_DIR="${HOME}/Library/Application Support/ghidra-cli" ;;
    *)      DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/ghidra-cli" ;;
esac

# Same convention as tests/common: caches live under dirs::cache_dir().
case "$(uname -s)" in
    Darwin) CACHE_DIR="${HOME}/Library/Caches/ghidra-cli" ;;
    *)      CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/ghidra-cli" ;;
esac
PROJECT_DIR="${CACHE_DIR}/projects"

# Resolve the CLI. We respect $GHIDRA_CLI_BIN so CI can point at the
# already-built debug binary and avoid a redundant `cargo run` rebuild.
if [[ -n "${GHIDRA_CLI_BIN:-}" ]]; then
    CLI=("${GHIDRA_CLI_BIN}")
elif [[ -x "${REPO_ROOT}/target/debug/ghidra" ]]; then
    CLI=("${REPO_ROOT}/target/debug/ghidra")
elif [[ -x "${REPO_ROOT}/target/release/ghidra" ]]; then
    CLI=("${REPO_ROOT}/target/release/ghidra")
else
    CLI=(cargo run --quiet --manifest-path "${REPO_ROOT}/Cargo.toml" --)
fi

# Prerequisite: Ghidra installed. If not, exit 77 (skipped) — matches the
# convention used by require_ghidra! in the Rust test suite and lets this
# script run on dev laptops without failing.
#
# We capture doctor's output into a variable before grep'ing it. Piping
# directly is brittle under `set -o pipefail`: grep -q closes its stdin on
# first match and the upstream command gets SIGPIPE, which pipefail then
# propagates as a pipeline failure even though the pattern *did* match.
DOCTOR_OUTPUT="$("${CLI[@]}" doctor 2>&1 || true)"
if ! printf '%s\n' "${DOCTOR_OUTPUT}" | grep -q "analyzeHeadless: OK"; then
    echo "skip: Ghidra not installed (analyzeHeadless missing)" >&2
    exit 77
fi

echo ">> tearing down any prior bridge for project=${PROJECT}"
"${CLI[@]}" stop --project "${PROJECT}" >/dev/null 2>&1 || true

# Remove cached project so the next import is a true cold start.
# Ghidra writes ${PROJECT}.gpr + ${PROJECT}.rep alongside each other.
rm -f  "${PROJECT_DIR}/${PROJECT}.gpr" 2>/dev/null || true
rm -rf "${PROJECT_DIR}/${PROJECT}.rep" 2>/dev/null || true

# Clear the prior cold-start snapshot so we don't accidentally read a stale
# value if this run fails to emit one.
rm -f "${DATA_DIR}/cold-start.json" 2>/dev/null || true

echo ">> cold import: project=${PROJECT} binary=${BINARY}"
"${CLI[@]}" import "${BINARY}" --project "${PROJECT}" --program cold_start_fixture

# Always stop after measurement so re-runs are repeatable.
"${CLI[@]}" stop --project "${PROJECT}" >/dev/null 2>&1 || true

SNAPSHOT="${DATA_DIR}/cold-start.json"
if [[ ! -f "${SNAPSHOT}" ]]; then
    echo "error: cold-start snapshot not produced at ${SNAPSHOT}" >&2
    echo "       (bridge.rs::emit_cold_start_event should have written it)" >&2
    exit 1
fi

# Extract cold_start_ms. We avoid a jq dep: the snapshot is a single-line
# JSON object so a grep+sed pair is enough.
COLD_MS="$(sed -E 's/.*"cold_start_ms":[[:space:]]*([0-9]+).*/\1/' "${SNAPSHOT}")"
if ! [[ "${COLD_MS}" =~ ^[0-9]+$ ]]; then
    echo "error: could not parse cold_start_ms from snapshot:" >&2
    cat "${SNAPSHOT}" >&2
    exit 1
fi

echo "cold_start_ms=${COLD_MS}  threshold_ms=${THRESHOLD_MS}"
if (( COLD_MS >= THRESHOLD_MS )); then
    echo "FAIL: cold start regressed (${COLD_MS} ms >= ${THRESHOLD_MS} ms)" >&2
    cat "${SNAPSHOT}" >&2
    exit 1
fi

echo "PASS: cold start within budget"
