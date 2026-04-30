.PHONY: fmt lint test build check bench demo demo-repl demo-ci

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

demo:
	./scripts/demo.sh hero

demo-repl:
	./scripts/demo.sh repl

demo-ci:
	./scripts/demo.sh ci
