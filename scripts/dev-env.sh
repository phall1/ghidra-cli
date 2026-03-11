#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_GHIDRA_DIR="${ROOT_DIR}/../ghidra/build/dist/ghidra_12.2_DEV"
DEFAULT_PROJECT_DIR="${HOME}/Library/Caches/ghidra-cli/projects"

resolve_java_home() {
  if [[ -n "${JAVA_HOME:-}" && -d "${JAVA_HOME}" ]]; then
    printf '%s\n' "${JAVA_HOME}"
    return
  fi

  if [[ -d "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" ]]; then
    printf '%s\n' "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
    return
  fi

  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    local detected
    detected="$(/usr/libexec/java_home -v 21 2>/dev/null || /usr/libexec/java_home 2>/dev/null || true)"
    if [[ -n "${detected}" && -d "${detected}" ]]; then
      printf '%s\n' "${detected}"
      return
    fi
  fi

  return 1
}

setup_dev_env() {
  GHIDRA_DIR="${GHIDRA_INSTALL_DIR:-${DEFAULT_GHIDRA_DIR}}"
  PROJECT_DIR="${GHIDRA_PROJECT_DIR:-${DEFAULT_PROJECT_DIR}}"

  if [[ ! -d "${GHIDRA_DIR}" ]]; then
    echo "Ghidra install dir not found: ${GHIDRA_DIR}" >&2
    return 1
  fi

  JAVA_HOME_CANDIDATE="$(resolve_java_home || true)"
  if [[ -z "${JAVA_HOME_CANDIDATE}" || ! -d "${JAVA_HOME_CANDIDATE}" ]]; then
    echo "JAVA_HOME is not set to a valid JDK directory." >&2
    return 1
  fi

  export JAVA_HOME="${JAVA_HOME_CANDIDATE}"
  export GHIDRA_INSTALL_DIR="${GHIDRA_DIR}"
  export GHIDRA_PROJECT_DIR="${PROJECT_DIR}"
}
