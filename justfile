set shell := ["bash", "-uc"]

default:
    @just --list

bootstrap:
    ./scripts/bootstrap-dev.sh

doctor:
    ./scripts/with-ghidra-env.sh cargo run --bin ghidra -- doctor

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    ./scripts/with-ghidra-env.sh cargo clippy --all-targets --all-features -- -D warnings

build:
    ./scripts/with-ghidra-env.sh cargo build

test-no-run:
    ./scripts/with-ghidra-env.sh cargo test --no-run

test-bin:
    ./scripts/with-ghidra-env.sh cargo test --bin ghidra

test-analysis:
    ./scripts/with-ghidra-env.sh cargo test --test analysis_tests -- --nocapture

test-mcp:
    ./scripts/with-ghidra-env.sh cargo test --test mcp_integration_tests -- --nocapture

test-workflow:
    ./scripts/with-ghidra-env.sh cargo test --test workflow_tests -- --nocapture

clean:
    cargo clean

nuke:
    @if [ "${NUKE_CONFIRM:-}" != "YES" ]; then echo "Refusing to run nuke. Re-run with NUKE_CONFIRM=YES just nuke"; exit 1; fi
    just clean
    rm -rf "$HOME/.ghidra-projects"
    rm -rf "$HOME/Library/Caches/ghidra-cli/projects"
    rm -rf "$HOME/.local/share/ghidra-cli"
    rm -rf "$HOME/Library/Application Support/ghidra-cli"
    rm -rf "$HOME/Library/ghidra"

test-fast:
    just test-bin
    just test-no-run

test-all:
    just test-fast
    just test-analysis
    just test-mcp
    just test-workflow

verify:
    just doctor
    just test-fast
