set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

install: install-system install-cargo-tools install-docs-deps install-tools
  @echo "Dev environment ready. Try 'just check' or 'just docs-dev'."

install-system:
  ./scripts/dev/install-system.sh

install-tools:
  if ! command -v trufflehog >/dev/null 2>&1; then \
    echo "warning: trufflehog not found - install from https://github.com/trufflesecurity/trufflehog/releases"; \
    echo "         (macOS: brew install trufflehog)"; \
  fi
  git config core.hooksPath .githooks
  echo "Git hooks wired to .githooks/"

install-cargo-tools:
  ./scripts/dev/install-cargo-tools.sh

install-docs-deps:
  cd docs-site && corepack pnpm install --frozen-lockfile --registry=https://registry.npmjs.org/

fmt:
  dprint check

lint:
  cargo clippy --all-features --all-targets -- -D warnings

test:
  cargo nextest run --all-features --all-targets --no-fail-fast
  # nextest runs unit + integration tests; it does not run doctests, so those
  # run separately via `cargo test --doc`.
  cargo test --all-features --doc

build:
  cargo build --all-features --all-targets

macos-vz-runner-dev:
  cargo build -p firma-vz-runner
  ./scripts/macos-vz/sign-vz-runner-dev.sh

e2e:
  cargo nextest run -p firma --test e2e --run-ignored all

audit:
  cargo audit --deny warnings

deny:
  cargo deny check licenses bans sources

check: fmt lint test build audit deny

coverage:
  cargo llvm-cov nextest --workspace --all-features --codecov --output-path codecov.json

fuzz-check:
  nightly="$(< .rust-nightly)"
  cd fuzz && cargo +"$nightly" check

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
