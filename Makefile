.PHONY: fmt lint test build check stress-http

fmt:
	cargo fmt --check

lint:
	cargo clippy --workspace -- -D warnings

test:
	cargo test --workspace

build:
	cargo build --workspace

check: fmt lint test build

stress-http:
	cargo test -p firma-sidecar --test interception_stress -- --nocapture
