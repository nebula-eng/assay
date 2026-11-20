# Assay — developer entry points.
#
# Every target here is also what CI runs, so `make check` locally means the same
# thing as a green pipeline.

SHELL := /bin/sh
CARGO ?= cargo
NPM   ?= npm
# Where the UI checks expect a served bundle. Override to point at a preview
# server: `make ui-verify UI_URL=http://127.0.0.1:5173/`.
UI_URL ?= http://127.0.0.1:8801/

.DEFAULT_GOAL := help
.PHONY: help build release test check fmt clippy audit samples demo icons cli ui serve ui-verify e2e desktop calibrate links clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Debug build of the CLI
	$(CARGO) build

release: ## Optimised build of the CLI
	$(CARGO) build --release -p assay-cli

test: ## Run the full test suite
	$(CARGO) test --workspace

check: fmt clippy test links e2e ## Everything CI runs in one command

fmt: ## Verify formatting
	$(CARGO) fmt --all -- --check

clippy: ## Lint with warnings as errors
	$(CARGO) clippy --workspace --all-targets -- -D warnings

audit: ## Check dependencies for known advisories
	$(CARGO) audit

samples: ## Regenerate the synthetic test fixtures
	python scripts/make_samples.py --out samples

demo: build samples ## Refresh the report embedded in the UI demo mode
	./target/debug/assay analyze samples/suspicious.exe --format json \
		--output ui/src/lib/demo-report.json

icons: ## Regenerate the application icon set
	python scripts/make_icons.py --out crates/assay-desktop/icons

cli: build ## Smoke-test the CLI against the fixtures
	./target/debug/assay --version
	./target/debug/assay rules validate rules/builtin.json
	@# The corpus is built to be detected, so `batch` must return a risk verdict
	@# (1 = high, 2 = critical). Any other code means the scan itself broke, so
	@# this asserts the code rather than swallowing it.
	@./target/debug/assay batch samples > /dev/null; code=$$?; \
		if [ $$code -ne 1 ] && [ $$code -ne 2 ]; then \
			echo "batch returned $$code, expected a risk verdict (1 or 2)"; \
			exit 1; \
		fi

ui: ## Type-check and build the front end
	$(NPM) --prefix ui install --no-audit --no-fund
	$(NPM) --prefix ui run build

serve: ui ## Serve the built bundle on :8801 for the browser checks
	@printf 'serving ui/dist on http://127.0.0.1:8801/ (Ctrl-C to stop)\n'
	python -m http.server 8801 --bind 127.0.0.1 --directory ui/dist

ui-verify: ui ## Render, geometry and design checks against $(UI_URL)
	@curl -sf -o /dev/null $(UI_URL) || { \
		printf 'no server at %s\n' "$(UI_URL)"; \
		printf 'start one first:\n  make serve\n\n'; \
		exit 1; \
	}
	node scripts/ui_smoke.mjs     --url $(UI_URL)
	node scripts/ui_shots.mjs     --url $(UI_URL) --out .shots
	node scripts/design_audit.mjs --url $(UI_URL)

e2e: build samples ## End-to-end assertions against the CLI
	python tests/e2e.py --binary target/debug/assay --samples samples

calibrate: release ## Measure the false-positive corpus (needs a Windows host)
	python scripts/calibrate.py --binary target/release/assay

links: ## Verify every relative link and heading anchor in the docs
	python scripts/linkcheck.py

desktop: ui ## Build the desktop shell (needs platform WebView dependencies)
	$(CARGO) build -p assay-desktop --release

clean: ## Remove build artefacts
	$(CARGO) clean
	rm -rf ui/dist ui/node_modules .shots
