# Dev Quickcheck

Run these before opening a PR.

## 1) Format
- `cargo fmt --all`

## 2) Lint
- `cargo clippy --all-targets --all-features -- -D warnings`

## 3) Tests
- `cargo test --all --all-features`

## 4) Optional: minimal build
- `cargo build --release`
