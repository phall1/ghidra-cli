#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev-env.sh"

setup_dev_env

cargo run --bin ghidra -- config set ghidra_install_dir "${GHIDRA_INSTALL_DIR}"
cargo run --bin ghidra -- config set ghidra_project_dir "${GHIDRA_PROJECT_DIR}"
cargo run --bin ghidra -- doctor

echo "Configured ghidra-cli for local development."
echo "JAVA_HOME=${JAVA_HOME}"
echo "GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR}"
echo "ghidra_project_dir=${GHIDRA_PROJECT_DIR}"
