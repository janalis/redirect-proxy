.DEFAULT_GOAL := help
.PHONY: help deps build run dev test coverage fmt fmt-check lint lint-versions lint-erlang \
	lint-shell lint-actions lint-docker lint-markdown check bench bench-compare bench-handler bench-matcher bench-store bundle \
	bundle-portable deb docker docker-run docs-deps screenshots docs docs-dev release-dry clean

VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' gleam.toml)
UNAME_S := $(shell uname -s | tr '[:upper:]' '[:lower:]')
UNAME_M := $(shell uname -m)
ARCH := $(if $(filter x86_64 amd64,$(UNAME_M)),amd64,$(if $(filter aarch64 arm64,$(UNAME_M)),arm64,$(UNAME_M)))
TARGET ?= $(UNAME_S)-$(ARCH)
CONFIG ?= config.example.toml
COVERAGE_MIN ?= 90
IMAGE ?= ghcr.io/janalis/redirect-proxy
MAINTAINER ?= Janalis
# STRICT=1: a missing linter fails instead of being skipped (as in CI)
STRICT ?=

# $(call missing,tool): skip, or fail with STRICT=1
missing = { echo "$(1) not installed$(if $(STRICT),,$(comma) skipping)"; exit $(if $(STRICT),1,0); }
comma := ,

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "redirect-proxy $(VERSION)\n\nUsage: make <target>\n\n"} \
		/^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

deps: ## Download dependencies
	gleam deps download

build: ## Compile (warnings are errors)
	gleam build --warnings-as-errors

run: ## Run the server with $(CONFIG)
	RP_CONFIG=$(CONFIG) RP_STORAGE_DATA_DIR=$${RP_STORAGE_DATA_DIR:-./data} gleam run -- serve

dev: ## Run with a throwaway admin (admin / change-me-please) in ./data
	RP_CONFIG=$(CONFIG) RP_STORAGE_DATA_DIR=./data \
	RP_BOOTSTRAP_ADMIN_USERNAME=admin RP_BOOTSTRAP_ADMIN_PASSWORD=change-me-please \
	RP_LOG_LEVEL=debug gleam run -- serve

test: ## Run the test suite
	gleam test

coverage: build ## Run tests with coverage (fails under COVERAGE_MIN %)
	escript scripts/coverage.escript $(COVERAGE_MIN)

fmt: ## Format sources
	gleam format src test

fmt-check: ## Check formatting
	gleam format --check src test

lint: fmt-check build lint-versions lint-erlang lint-shell lint-actions lint-docker lint-markdown ## Run every linter available

lint-versions: ## Dockerfile versions and checksums match .tool-versions (needs network)
	scripts/check-versions.sh --online

lint-erlang: ## Compile Erlang FFI with warnings as errors
	@mkdir -p build/lint
	erlc -Wall -Werror -o build/lint src/*.erl

lint-shell: ## shellcheck scripts
	@command -v shellcheck >/dev/null || $(call missing,shellcheck); \
	shellcheck scripts/*.sh packaging/bin/redirect-proxy packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm packaging/docker/healthcheck.sh

lint-actions: ## actionlint GitHub workflows
	@command -v actionlint >/dev/null || $(call missing,actionlint); \
	actionlint

lint-docker: ## hadolint the Dockerfile
	@command -v hadolint >/dev/null || $(call missing,hadolint); \
	hadolint Dockerfile

lint-markdown: ## markdownlint documentation
	@command -v markdownlint-cli2 >/dev/null || $(call missing,markdownlint-cli2); \
	markdownlint-cli2 "*.md" "docs/**/*.md" ".github/**/*.md"

check: lint test ## Lint and test (what CI runs)

bench-matcher: ## Matcher work per request vs the baseline (BEAM reductions)
	python3 scripts/matcher-bench.py

bench-compare: docker ## Compare with nginx, HAProxy, Caddy, Traefik and Apache (needs Docker)
	RP_IMAGE=$(IMAGE):dev python3 scripts/bench-compare.py

bench-handler: ## Time to parse a request head and run the handler, in-process
	gleam run -m handler_bench

bench-store: ## Time loading 50 000 rules and changing one
	gleam run -m store_bench

bench: bundle ## Load test the redirect listener (needs oha or ab)
	scripts/bench.sh $(CURDIR)/dist/redirect-proxy-$(VERSION)-$(TARGET)

bundle: ## Self-contained bundle with the Erlang runtime for this platform
	scripts/bundle.sh $(VERSION) $(TARGET) --with-erts

bundle-portable: ## Portable bundle that uses the system Erlang (OTP 27+)
	scripts/bundle.sh $(VERSION) erlang

deb: bundle ## Debian/Ubuntu package (Linux only; nfpm or Docker)
	@test "$(UNAME_S)" = linux || { echo "build .deb packages on Linux (or via the release workflow)"; exit 1; }
	MAINTAINER="$(MAINTAINER)" scripts/package-deb.sh $(VERSION) $(ARCH) dist/redirect-proxy-$(VERSION)-$(TARGET)

docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):dev .

docker-run: docker ## Run the container image locally
	docker run --rm -p 8080:8080 -p 127.0.0.1:8081:8081 \
		-e RP_BOOTSTRAP_ADMIN_USERNAME=admin -e RP_BOOTSTRAP_ADMIN_PASSWORD=change-me-please \
		$(IMAGE):dev

docs-deps: ## Install the documentation tools (Node 20+, Playwright's Chromium)
	npm --prefix docs ci
	cd docs && npx playwright install chromium

screenshots: ## Take the documentation screenshots from the server (docs/public/screenshots)
	npm --prefix docs run screenshots

docs: docs-deps screenshots ## Build the documentation site to docs/.vitepress/dist
	npm --prefix docs run build

docs-dev: ## Serve the documentation with live reload (run make screenshots once first)
	npm --prefix docs run dev

release-dry: ## Preview the next release-please release
	npx --yes release-please release-pr --dry-run \
		--repo-url=janalis/redirect-proxy --token=$${GITHUB_TOKEN:?set GITHUB_TOKEN}

clean: ## Remove build artefacts
	rm -rf build dist coverage docs/.vitepress/dist docs/.vitepress/cache docs/public/screenshots
