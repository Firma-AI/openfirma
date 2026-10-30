set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

install: install-tools install-docs-deps
  @echo "Dev environment ready. Try 'just check' or 'just docs-dev'."

install-tools:
  command -v mise >/dev/null 2>&1 || { echo "mise not found - install it from https://mise.jdx.dev/getting-started.html"; exit 1; }
  command -v cargo >/dev/null 2>&1 || { echo "cargo not found - install rustup from https://rustup.rs"; exit 1; }
  mise install --locked
  mise exec -- corepack enable >/dev/null 2>&1 || echo "warning: 'corepack enable' failed; you may need to run it with administrator privileges"
  if ! command -v trufflehog >/dev/null 2>&1; then \
    echo "warning: trufflehog not found - install from https://github.com/trufflesecurity/trufflehog/releases"; \
    echo "         (macOS: brew install trufflehog)"; \
  fi

install-docs-deps:
  cd docs-site && mise exec -- corepack pnpm install --frozen-lockfile --registry=https://registry.npmjs.org/

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

macos-vz-guest-artifacts:
  if [ -z "${FIRMA_VZ_GUEST_KERNEL:-}" ]; then ./scripts/macos-vz/fetch-kata-kernel.sh; fi
  ./scripts/macos-vz/build-guest-artifacts.sh

macos-vz-kata-kernel:
  ./scripts/macos-vz/fetch-kata-kernel.sh

macos-vz-runner-dev:
  cargo build -p firma-vz-runner
  ./scripts/macos-vz/sign-vz-runner-dev.sh

macos-vz-basic-exec:
  just --justfile examples/firma-run/macos-vz-basic-exec/justfile run

macos-vz-codex-pty:
  just --justfile examples/firma-run/macos-vz-codex-pty/justfile run

live-agent-e2e:
  cargo nextest run -p firma --test live-agent --run-ignored all --no-tests=fail

audit:
  cargo deny --locked check -D index-failure -D index-cache-load-failure advisories

deny:
  cargo deny check licenses bans sources

release-tools-test:
  ruff format --check scripts/release
  ruff check scripts/release
  python3 -m unittest discover -s scripts/release -p "test_*.py"

check: fmt lint test build audit deny release-tools-test

coverage:
  cargo llvm-cov nextest --workspace --all-features --codecov --output-path codecov.json

fuzz-check:
  cd fuzz && cargo +"$(< ../.rust-nightly)" check

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

git-demo-ci:
  ./examples/firma-git-demo/run.sh ci

policy-control:
  @just --justfile examples/policy-control/justfile policy-control

managed-seccomp-compat-check:
  ./scripts/seccomp/check-managed-compatibility.sh
