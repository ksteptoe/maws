# --- Makefile (PyScaffold Clickstart; pyproject-only, Ruff-only) -------------
# Provides:
#   - Auto versioned builds (setuptools_scm)
#   - Linting/formatting via Ruff
#   - Incremental pytest testing via STAMPs
#   - Release helpers (Git tag based)
#   - venv-based bootstrap (.venv by default; override with VENV=...)
# -----------------------------------------------------------------------------

.SILENT:
.ONESHELL:
SHELL := $(shell which bash)
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# ---- Python / venv ----------------------------------------------------------
VENV ?= .venv

# ---- Environment install stamp ---------------------------------------------

CONF_FILES := pyproject.toml
ENV_STAMP := $(VENV)/.installed

$(ENV_STAMP): $(CONF_FILES) | venv
	@echo "Installing project dependencies (editable)..."
	"$(PY)" -m pip install -U pip setuptools wheel
	"$(PY)" -m pip install -e ".[dev]"
	@echo "installed" > "$(ENV_STAMP)"


# Pick a system Python: use 'python' if present, else Windows launcher 'py -3'
PYTHON_SYS := $(shell command -v python >/dev/null 2>&1 && echo python || echo py -3)

# Linux Friendly too
PY = $(if $(wildcard $(VENV)/Scripts/python.exe),$(VENV)/Scripts/python.exe,$(VENV)/bin/python)

# Main code package (templated)
PKG        := maws
CODE_DIRS  := src/$(PKG)
STAMPS_DIR := .stamps
UNIT_STAMP  := $(STAMPS_DIR)/unit.ok
INTEG_STAMP := $(STAMPS_DIR)/integration.ok
NO_CACHE  ?= 0

# Default release kind for `make release` (patch|minor|major)
KIND ?= patch

# Pytest flags
PYTEST           := $(PY) -m pytest
PYTEST_Q         := -q
PYTEST_WARN      := --disable-warnings
PYTEST_COV_BASE  := --cov=$(PKG)
PYTEST_COV_UNIT  := $(PYTEST_COV_BASE) --cov-report= --cov-append
PYTEST_COV_INTEG := $(PYTEST_COV_BASE) --cov-report= --cov-append
PYTEST_XDIST    ?= -n auto
PYTEST_TIMEOUT  ?= --timeout=60

# Test directories
UNIT_DIR   := tests/unit
INTEG_DIR  := tests/integration
SYSTEM_DIR := tests/system  # live/system tests (opt-in, uncached)

.PHONY: help venv bootstrap precommit docs lint format \
        test test-all test-live clean-tests \
        build upload version fetch-tags changelog changelog-md \
        release-show release release-patch release-minor release-major \
        clean run-cli check-clean

help:
	@echo "Common targets:"
	@echo "  make venv                - create virtual environment"
	@echo "  make bootstrap           - create $(VENV) and install .[dev]"
	@echo "  make precommit           - install pre-commit hook (requires bootstrap)"
	@echo "  make docs                - build Sphinx/MyST docs to docs/_build/html"
	@echo "  make lint                - run Ruff checks"
	@echo "  make format              - auto-fix via Ruff"
	@echo "  make test                - run cached unit+integration tests (not live)"
	@echo "  make test-all            - run all non-live tests (no stamps)"
	@echo "  make test-live           - run @live tests only (no cache)"
	@echo "  make build               - build wheel+sdist"
	@echo "  make upload              - upload to PyPI (via Twine)"
	@echo "  make version             - print setuptools_scm inferred version"
	@echo "  make changelog           - show changes since last Git tag"
	@echo "  make changelog-md        - write docs/CHANGELOG.md from Git history"
	@echo "  make release-show        - show scm ver, installed ver, last Git tag"
	@echo "  make release             - run tests, show changelog and tag (KIND=patch|minor|major)"
	@echo "  make clean               - remove build artifacts"
	@echo "  make run-cli             - run via python -m package (pass CLI_ARGS=...)"
	@echo ""
	@echo "Tip (Windows/OneDrive permission issues):"
	@echo '  make bootstrap VENV="$$HOME/.venvs/maws"'
	@echo '  make release   VENV="$$HOME/.venvs/maws" KIND=major'

$(VENV)/pyvenv.cfg:
	$(PYTHON_SYS) -m venv $(VENV)

venv: $(VENV)/pyvenv.cfg

bootstrap: $(ENV_STAMP)
	@echo "Environment ready."


precommit: bootstrap
	"$(PY)" -m pre_commit install

# -----------------------------------------------------------------------------#
# Docs
docs: $(ENV_STAMP)
	"$(PY)" -m sphinx -b html docs docs/_build/html

# -----------------------------------------------------------------------------#
# Linting / Formatting
lint: $(ENV_STAMP)
	"$(PY)" -m ruff check .
	"$(PY)" -m ruff format --check .

format: $(ENV_STAMP)
	"$(PY)" -m ruff check --fix .
	"$(PY)" -m ruff format .

# -----------------------------------------------------------------------------#
# Incremental Testing (cache via stamps)

$(STAMPS_DIR):
	mkdir -p $(STAMPS_DIR)

UNIT_SIG    := $(STAMPS_DIR)/unit.sig
INTEG_SIG   := $(STAMPS_DIR)/integration.sig

define compute_dir_sig
{ [ -d "$(1)" ] && find $(1) -type f -not -path "*/__pycache__/*" -print0 || true; } \
| LC_ALL=C sort -z | xargs -0r sha1sum | sha1sum | awk '{print $$1}'
endef


$(UNIT_STAMP): | $(STAMPS_DIR) $(ENV_STAMP)
	@tests_sig=$$( $(call compute_dir_sig,$(UNIT_DIR)) ); \
	code_sig=$$( $(call compute_dir_sig,$(CODE_DIRS)) ); \
	conf_sig=$$( sha1sum $(CONF_FILES) 2>/dev/null | awk '{print $$1}' | sha1sum | awk '{print $$1}' ); \
	new_sig=$$( printf "%s\n%s\n%s\n" "$$tests_sig" "$$code_sig" "$$conf_sig" | sha1sum | awk '{print $$1}' ); \
	old_sig=$$(cat $(UNIT_SIG) 2>/dev/null || echo -n); \
	if [ "$(NO_CACHE)" = "1" ] || [ "$$new_sig" != "$$old_sig" ] || [ ! -f $@ ]; then \
	  echo "=== Running unit tests ==="; \
	  rm -f .coverage; \
	  set +e; \
	  "$(PY)" -m pytest -q $(UNIT_DIR) -m "not live" $(PYTEST_WARN) $(PYTEST_XDIST) $(PYTEST_TIMEOUT) $(PYTEST_COV_UNIT); \
	  status=$$?; \
	  set -e; \
	  if [ "$$status" -eq 5 ]; then \
	    echo "No unit tests collected; treating as success."; \
	  elif [ "$$status" -ne 0 ]; then \
	    exit $$status; \
	  fi; \
	  echo "$$new_sig" > $(UNIT_SIG); \
	  touch $@; \
	else \
	  echo "No changes detected; skipping unit tests."; \
	fi

$(INTEG_STAMP): | $(STAMPS_DIR) $(ENV_STAMP)
	@tests_sig=$$( $(call compute_dir_sig,$(INTEG_DIR)) ); \
	code_sig=$$( $(call compute_dir_sig,$(CODE_DIRS)) ); \
	conf_sig=$$( sha1sum $(CONF_FILES) 2>/dev/null | awk '{print $$1}' | sha1sum | awk '{print $$1}' ); \
	new_sig=$$( printf "%s\n%s\n%s\n" "$$tests_sig" "$$code_sig" "$$conf_sig" | sha1sum | awk '{print $$1}' ); \
	old_sig=$$(cat $(INTEG_SIG) 2>/dev/null || echo -n); \
	if [ "$(NO_CACHE)" = "1" ] || [ "$$new_sig" != "$$old_sig" ] || [ ! -f $@ ]; then \
	  echo "=== Running integration tests ==="; \
	  set +e; \
	  "$(PY)" -m pytest -q $(INTEG_DIR) -m "not live" $(PYTEST_WARN) $(PYTEST_XDIST) $(PYTEST_TIMEOUT) $(PYTEST_COV_INTEG); \
	  status=$$?; \
	  set -e; \
	  if [ "$$status" -eq 5 ]; then \
	    echo "No integration tests collected; treating as success."; \
	  elif [ "$$status" -ne 0 ]; then \
	    exit $$status; \
	  fi; \
	  echo "$$new_sig" > $(INTEG_SIG); \
	  touch $@; \
	else \
	  echo "No changes detected; skipping integration tests."; \
	fi


test: $(UNIT_STAMP) $(INTEG_STAMP)
	@echo "=== Aggregated coverage report ==="
	"$(PY)" -m coverage report
	"$(PY)" -m coverage xml
	@echo "✅ Unit + Integration tests up-to-date (not live)"

# Full non-live run, no stamps (useful before releases)
test-all: $(ENV_STAMP)
	"$(PY)" -m pytest -v -m "not live" $(PYTEST_WARN) $(PYTEST_XDIST) $(PYTEST_TIMEOUT) --cov=$(PKG) --cov-report=term-missing --cov-report=xml --cov-fail-under=40

# Live tests are explicit & uncached (gentle on API; clearer intent)
test-live: $(ENV_STAMP)
	SF_LIVE_TESTS=true "$(PY)" -m pytest -v -m live $(PYTEST_WARN) --timeout=180 --cov=$(PKG) --cov-report=xml

clean-tests:
	rm -rf $(STAMPS_DIR)

# -----------------------------------------------------------------------------#
# Build & Publish
build: $(ENV_STAMP)
	"$(PY)" -m pip install -U build
	"$(PY)" -m build

upload: build
	"$(PY)" -m pip install -U twine
	"$(PY)" -m twine check dist/*
	"$(PY)" -m twine upload dist/*

# -----------------------------------------------------------------------------#
# Version & Release helpers (setuptools_scm + Git tags)
fetch-tags:
	git fetch --tags --force --prune 2>/dev/null || true

# Always resolve a tag (fallback to v0.0.0 if none exist)
LAST_TAG := $(strip $(shell git tag --list "v[0-9]*.[0-9]*.[0-9]*" --sort=-version:refname | head -n 1))
ifeq ($(LAST_TAG),)
LAST_TAG := v0.0.0
endif

MAJOR := $(shell echo "$(LAST_TAG)" | sed -E 's/^v([0-9]+)\..*/\1/')
MINOR := $(shell echo "$(LAST_TAG)" | sed -E 's/^v[0-9]+\.([0-9]+)\..*/\1/')
PATCH := $(shell echo "$(LAST_TAG)" | sed -E 's/^v[0-9]+\.[0-9]+\.([0-9]+).*/\1/')

version: $(ENV_STAMP)
	@"$(PY)" -m setuptools_scm || true

# Changelog text since LAST_TAG (if LAST_TAG is v0.0.0 and doesn't exist, use full history)
define CHANGELOG
$(shell \
  if git rev-parse "$(LAST_TAG)" >/dev/null 2>&1; then \
    git log "$(LAST_TAG)..HEAD" --pretty=format:"- %s (%h)" --no-merges; \
  else \
    git log HEAD --pretty=format:"- %s (%h)" --no-merges; \
  fi \
)
endef

changelog: fetch-tags
	@echo "Changes since $(LAST_TAG):"
	@echo "$(CHANGELOG)"

changelog-md: fetch-tags
	@mkdir -p docs
	@echo "Writing docs/CHANGELOG.md ..."
	@printf "# Changelog\n\n## Since %s\n\n%s\n" "$(LAST_TAG)" "$(CHANGELOG)" > docs/CHANGELOG.md
	@echo "✅ docs/CHANGELOG.md updated"

release-show: fetch-tags $(ENV_STAMP)
	@echo "python exe:"; "$(PY)" -c "import sys; print(sys.executable)"
	@echo "setuptools_scm version:"; "$(PY)" -m setuptools_scm || echo "(unavailable)"
	@echo "installed dist version:"; "$(PY)" -c "import importlib.metadata as m; print(m.version('$(PKG)'))" || echo "(package not installed)"
	@echo "Last Git tag: $(LAST_TAG)"


check-clean:
	@if ! git diff --quiet || ! git diff --cached --quiet; then \
		echo "❌ Working directory not clean. Commit or stash changes before releasing."; \
		git status -s; \
		exit 1; \
	fi
	@if [ "$(git rev-parse @ 2>/dev/null)" != "$(git rev-parse @{u} 2>/dev/null)" ]; then \
		echo "❌ Local branch not in sync with upstream (push/pull first)."; \
		exit 1; \
	fi

NL := $(shell printf "\n")

release-patch: fetch-tags check-clean
	@NEW="v$(MAJOR).$(MINOR).$$(($(PATCH) + 1))"; \
	git tag -a "$$NEW" -m "release: $$NEW$(NL)$(NL)$(CHANGELOG)"; \
	git push origin "$$NEW"; \
	echo "Tagged $$NEW"

release-minor: fetch-tags check-clean
	@NEW="v$(MAJOR).$$(($(MINOR) + 1)).0"; \
	git tag -a "$$NEW" -m "release: $$NEW$(NL)$(NL)$(CHANGELOG)"; \
	git push origin "$$NEW"; \
	echo "Tagged $$NEW"

release-major: fetch-tags check-clean
	@NEW="v$$(($(MAJOR) + 1)).0.0"; \
	git tag -a "$$NEW" -m "release: $$NEW$(NL)$(NL)$(CHANGELOG)"; \
	git push origin "$$NEW"; \
	echo "Tagged $$NEW"


release: fetch-tags $(ENV_STAMP)
	@echo "=== Running full test suite before release ==="
	$(MAKE) test-all
	@echo "=== Changelog (from $(LAST_TAG) to HEAD) ==="
	$(MAKE) changelog
	@echo "=== Performing $(KIND) release ==="
	@if [ "$(KIND)" = "patch" ]; then \
	  $(MAKE) release-patch; \
	elif [ "$(KIND)" = "minor" ]; then \
	  $(MAKE) release-minor; \
	elif [ "$(KIND)" = "major" ]; then \
	  $(MAKE) release-major; \
	else \
	  echo "Unknown KIND=$(KIND). Use: patch | minor | major"; \
	  exit 1; \
	fi

# -----------------------------------------------------------------------------#
# CLI convenience
CLI_ARGS ?=
run-cli: $(ENV_STAMP)
	"$(PY)" -m maws $(CLI_ARGS)

# -----------------------------------------------------------------------------#
clean:
	rm -rf build dist .eggs *.egg-info .coverage htmlcov .pytest_cache coverage.xml
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	rm -rf $(STAMPS_DIR)
