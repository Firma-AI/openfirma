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
	cargo doc --workspace --no-deps
	rm -rf docs-site/public/api
	mkdir -p docs-site/public/api
	cp -R target/doc/. docs-site/public/api/
	cd docs-site && node scripts/write-rustdoc-index.mjs public/api
	cd docs-site && ASTRO_TELEMETRY_DISABLED=1 corepack pnpm dev --host 127.0.0.1 --open

demo:
	./examples/demo/run.sh hero

demo-repl:
	./examples/demo/run.sh repl

demo-ci:
	./examples/demo/run.sh ci
