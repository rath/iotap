#!/bin/bash
# The same checks on each release platform, as an unprivileged user.
set -euo pipefail

cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo test --release --locked
cargo build --release --locked
