.PHONY: fmt lint test build check bench docs docs-build docs-dev demo demo-repl demo-ci

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

docs-build:
	cd docs-site && corepack pnpm install --frozen-lockfile --registry=https://registry.npmjs.org/
	cd docs-site && ASTRO_TELEMETRY_DISABLED=1 corepack pnpm run build:with-rustdoc

docs: docs-build
	cd docs-site && ASTRO_TELEMETRY_DISABLED=1 corepack pnpm exec astro preview --host 127.0.0.1 --open

docs-dev:
	cd docs-site && corepack pnpm install --frozen-lockfile --registry=https://registry.npmjs.org/
	cd docs-site && corepack pnpm run build:rustdoc-mdx
	cd docs-site && ASTRO_TELEMETRY_DISABLED=1 corepack pnpm dev --host 127.0.0.1 --open

demo:
	./examples/demo/run.sh hero

demo-repl:
	./examples/demo/run.sh repl

demo-ci:
	./examples/demo/run.sh ci
