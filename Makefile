.PHONY: fmt lint test build check fuzz-check bench docs docs-build docs-dev demo demo-repl demo-ci install install-system install-cargo-tools install-docs-deps install-tools managed-seccomp-compat-check

install: install-system install-cargo-tools install-docs-deps install-tools
	@echo "Dev environment ready. Try 'make check' or 'make docs-dev'."

install-system:
	@command -v cargo >/dev/null 2>&1 || { echo "cargo not found — install rustup from https://rustup.rs"; exit 1; }
	@command -v node >/dev/null 2>&1 || { echo "node not found — install Node.js >= 20.19 (e.g. via nvm or 'brew install node')"; exit 1; }
	@command -v corepack >/dev/null 2>&1 || { echo "corepack not found — ships with Node.js >= 16.10; if missing, run 'npm i -g corepack'"; exit 1; }
	@if ! command -v protoc >/dev/null 2>&1; then \
	  echo "Installing protoc..."; \
	  if [ "$$(uname)" = "Darwin" ]; then \
	    command -v brew >/dev/null 2>&1 || { echo "Homebrew not found — install from https://brew.sh, then re-run 'make install'"; exit 1; }; \
	    brew install protobuf; \
	  elif command -v apt-get >/dev/null 2>&1; then \
	    sudo apt-get update && sudo apt-get install -y protobuf-compiler; \
	  else \
	    echo "Please install protoc for your platform and re-run 'make install'"; exit 1; \
	  fi; \
	fi
	@if ! command -v dprint >/dev/null 2>&1; then \
	  echo "Installing dprint..."; \
	  curl -fsSL https://dprint.dev/install.sh | sh; \
	fi
	@corepack enable >/dev/null 2>&1 || echo "warning: 'corepack enable' failed; you may need to run it with sudo"

install-tools:
	@if ! command -v trufflehog >/dev/null 2>&1; then \
	  echo "warning: trufflehog not found — install from https://github.com/trufflesecurity/trufflehog/releases"; \
	  echo "         (macOS: brew install trufflehog)"; \
	fi
	@git config core.hooksPath .githooks
	@echo "Git hooks wired to .githooks/"

install-cargo-tools:
	@command -v cargo-doc-md >/dev/null 2>&1 || cargo install cargo-doc-md
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit --locked
	@command -v cargo-deny >/dev/null 2>&1 || cargo install cargo-deny --locked

install-docs-deps:
	cd docs-site && corepack pnpm install --frozen-lockfile --registry=https://registry.npmjs.org/

fmt:
	dprint check

lint:
	cargo clippy --all-features --all-targets

test:
	cargo test --all-features --all-targets

build:
	cargo build --all-features --all-targets

audit:
	cargo audit --deny warnings

deny:
	cargo deny check licenses bans sources

check: fmt lint test build audit deny

# Requires nightly: rustup toolchain install nightly
fuzz-check:
	cd fuzz && cargo +nightly check

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

managed-seccomp-compat-check:
	./scripts/seccomp/check-managed-compatibility.sh
