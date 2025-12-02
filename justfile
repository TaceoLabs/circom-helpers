[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

lint-bin:
    cargo clippy --features="bin" --workspace --tests --examples --benches --bins -q -- -D warnings

lint: lint-bin
    cargo fmt --all -- --check
    # We do these standalone checks to not have wrong passes due to workspace dependencies
    # So we cd into the subcrate and run the checks as if it was standalone
    just lint-subcrate circom-types
    just lint-subcrate ark-serde-compat
    just lint-subcrate groth16
    just lint-subcrate groth16-material
    just lint-subcrate groth16-sol


lint-subcrate SUBCRATE:
    cd {{SUBCRATE}} && cargo all-features clippy --all-targets -q -- -D warnings
    cd {{SUBCRATE}} && RUSTDOCFLAGS='-D warnings' cargo all-features doc -q --no-deps

test:
    cargo test --all-features --all-targets

check-pr: lint test
