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
	./examples/demo/run.sh hero

demo-repl:
	./examples/demo/run.sh repl

demo-ci:
	./examples/demo/run.sh ci
