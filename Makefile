.PHONY: fmt lint test build check bench

fmt:
	cargo fmt --check

lint:
	cargo clippy --workspace -- -D warnings

test:
	cargo test --workspace

build:
	cargo build --workspace

check: fmt lint test build

bench:
	cargo bench --workspace --no-fail-fast
