SHELL := /usr/bin/env bash
PYTHON ?= python3
VENV ?= .venv

.DEFAULT_GOAL := help

.PHONY: help bootstrap scan lint format-check test audit shellcheck markdown workflow-lint \
	compose-check preflight firmware-v1 firmware-v2 clean

help: ## Show available commands.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Create a local virtual environment and install development tools.
	$(PYTHON) -m venv "$(VENV)"
	"$(VENV)/bin/python" -m pip install --upgrade pip
	"$(VENV)/bin/python" -m pip install -r requirements-dev.txt

scan: ## Scan source and docs for secrets and private infrastructure.
	$(PYTHON) scripts/scan_public_safety.py .

lint: ## Run Ruff lint checks.
	$(PYTHON) -m ruff check bridge installer scripts tests

format-check: ## Verify Python formatting without modifying files.
	$(PYTHON) -m ruff format --check bridge installer scripts tests

test: ## Run the Python test suite.
	$(PYTHON) -m pytest

audit: ## Audit development Python dependencies.
	$(PYTHON) -m pip_audit -r requirements-dev.txt

shellcheck: ## Run ShellCheck on repository scripts.
	@command -v shellcheck >/dev/null || { echo "shellcheck is required" >&2; exit 1; }
	@shellcheck install.sh
	@find scripts installer -type f -name '*.sh' -print0 | xargs -0 shellcheck

markdown: ## Lint Markdown with markdownlint-cli2.
	@command -v markdownlint-cli2 >/dev/null || { echo "markdownlint-cli2 is required" >&2; exit 1; }
	markdownlint-cli2

workflow-lint: ## Validate GitHub Actions workflows with actionlint.
	@command -v actionlint >/dev/null || { echo "actionlint is required" >&2; exit 1; }
	actionlint .github/workflows/*.yml

compose-check: ## Validate the Docker Compose model.
	docker compose --env-file .env.example config --quiet

preflight: ## Run the single-command publication preflight.
	./scripts/preflight.sh

firmware-v1: ## Build firmware for the V1 board using local provisioning.
	./scripts/build-firmware.sh v1

firmware-v2: ## Build firmware for the V2 board using local provisioning.
	./scripts/build-firmware.sh v2

clean: ## Remove only generated local development output.
	rm -rf .pytest_cache .ruff_cache htmlcov
	find scripts tests bridge -type d -name __pycache__ -prune -exec rm -rf {} +
