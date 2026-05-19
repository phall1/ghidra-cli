#!/usr/bin/env bash
#
# check_transactions.sh - Static analysis: enforce transaction wrapping on
# Ghidra program-mutation API calls in GhidraCliBridge.java.
#
# Background: every write that mutates `currentProgram` MUST be enclosed by
# `currentProgram.startTransaction(...)` ... `currentProgram.endTransaction(...)`
# so failures can be rolled back. This script flags any mutating API call that
# is not lexically wrapped in a transaction block.
#
# Strategy:
#   1. Identify each occurrence of a known mutation API in the bridge.
#   2. Walk the preceding lines (within ~200 lines, bounded by the enclosing
#      method/handler) looking for `startTransaction(`.
#   3. Walk the following lines for a matching `endTransaction(`.
#   4. If either is missing, print the offending line and exit non-zero.
#
# A small set of mutation calls that legitimately do NOT need a program
# transaction (DomainFile-level project ops) are filtered via ALLOW_LINES.
#
# Exit status:
#   0 - all mutations properly wrapped
#   1 - at least one unwrapped mutation found (the offending lines are printed)
#   2 - usage / configuration error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET="${1:-${REPO_ROOT}/src/ghidra/scripts/GhidraCliBridge.java}"

if [[ ! -f "${TARGET}" ]]; then
    echo "error: target file not found: ${TARGET}" >&2
    exit 2
fi

# Mutation API surface to audit. Patterns are extended-regex (egrep).
# Each is something we have observed mutates the open Ghidra program and
# therefore requires a transaction. Extend this list when new write handlers
# are added.
MUTATION_PATTERNS=(
    '\.setName\('
    '\.setComment\('
    '\.setBytes\('
    '\.setFieldName\('
    '\.setReturnType\('
    '\.setBookmark\('
    '\.removeBookmark\('
    '\.removeFunction\('
    '\.createFunction\('
    '\.createLabel\('
    '\.addDataType\('
    'HighFunctionDBUtil\.updateDBVariable\('
    'HighFunctionDBUtil\.commitParamsToDatabase\('
    'cmd\.applyTo\('
    'analysisOptions\.setBoolean\('
    'mgr\.reAnalyzeAll\('
    'listing\.createData\('
)

# Lines that match a mutation pattern but are NOT program-transactional
# (e.g. DomainFile-level project operations). Update with a comment when
# adding new exceptions.
#
# - line 1581: programFile.delete() - DomainFile delete, project-level op,
#   not subject to Program.startTransaction
ALLOW_LINE_REGEXES=(
    'programFile\.delete\('
)

# Build a combined egrep pattern.
joined="$(IFS='|'; echo "${MUTATION_PATTERNS[*]}")"

# Pull every (line_no:content) hit.
mapfile -t HITS < <(grep -nE "${joined}" "${TARGET}" || true)

violations=0

is_allowed() {
    local content="$1"
    for re in "${ALLOW_LINE_REGEXES[@]}"; do
        if [[ "${content}" =~ ${re} ]]; then
            return 0
        fi
    done
    return 1
}

# For a given hit line N, search backward up to LOOKBACK lines for the
# most recent `startTransaction(` and forward up to LOOKAHEAD for an
# `endTransaction(`. The scan stops if we cross a method boundary
# (`private ` or `public ` at column 4).
LOOKBACK=300
LOOKAHEAD=300

for hit in "${HITS[@]}"; do
    lineno="${hit%%:*}"
    content="${hit#*:}"

    if is_allowed "${content}"; then
        continue
    fi

    # Look backward for startTransaction without crossing a method definition.
    start_lineno=$(( lineno > LOOKBACK ? lineno - LOOKBACK : 1 ))
    pre_block=$(sed -n "${start_lineno},${lineno}p" "${TARGET}")

    # Trim to the current method by cutting at the last `private ` / `public `
    # declaration we encounter walking backwards.
    method_block=$(echo "${pre_block}" | awk '
        /^[[:space:]]*(private|public|protected)[[:space:]].*\(.*\)[[:space:]]*\{?[[:space:]]*$/ {
            buf=""
        }
        { buf = buf $0 "\n" }
        END { printf "%s", buf }
    ')

    if ! echo "${method_block}" | grep -qE 'currentProgram\.startTransaction\(|\.startTransaction\("'; then
        echo "MISSING startTransaction before mutation at ${TARGET}:${lineno}:${content}"
        violations=$((violations + 1))
        continue
    fi

    end_lineno=$(( lineno + LOOKAHEAD ))
    post_block=$(sed -n "${lineno},${end_lineno}p" "${TARGET}")

    if ! echo "${post_block}" | grep -qE 'currentProgram\.endTransaction\('; then
        echo "MISSING endTransaction after mutation at ${TARGET}:${lineno}:${content}"
        violations=$((violations + 1))
        continue
    fi

    # Verify rollback exists somewhere in the post block - the convention is
    # endTransaction(txId, false) in a catch path.
    if ! echo "${post_block}" | grep -qE 'endTransaction\([^,]+,[[:space:]]*false\)'; then
        echo "MISSING rollback endTransaction(txId, false) near mutation at ${TARGET}:${lineno}:${content}"
        violations=$((violations + 1))
        continue
    fi
done

if (( violations > 0 )); then
    echo ""
    echo "FAIL: ${violations} unwrapped mutation(s) found in ${TARGET}" >&2
    exit 1
fi

echo "OK: all $(printf '%s\n' "${HITS[@]}" | wc -l | tr -d ' ') mutation call(s) are transaction-wrapped."
exit 0
