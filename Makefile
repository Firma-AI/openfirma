.PHONY: fmt lint test build check stress-http stress-shared-state stress-loom stress-miri

fmt:
	cargo fmt --check

lint:
	cargo clippy --workspace -- -D warnings

test:
	cargo test --workspace

build:
	cargo build --workspace

check: fmt lint test stress-loom build

stress-http:
	cargo test -p firma-sidecar --test interception_stress -- --nocapture

stress-shared-state:
	cargo test -p firma-sidecar --test interception_stress stress_shared_state_mutation_produces_only_valid_decisions -- --exact --nocapture

stress-loom:
	cargo test -p firma-sidecar --test loom_shared_state --features loom-tests -- --nocapture

stress-miri:
	cargo +nightly miri test -p firma-sidecar --test interception_stress
