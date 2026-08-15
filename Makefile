# Convenience targets. `make help` lists them.
#
# Uses python -m so it works inside or outside a virtualenv without assuming a
# console-scripts install.

PY ?= python
PIP ?= $(PY) -m pip

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# -------------------------------------------------------------------- setup

.PHONY: install
install: ## Install runtime + dev dependencies
	$(PIP) install -r requirements.txt -r requirements-dev.txt

.PHONY: install-full
install-full: install ## Also install optional features (ssh capture, geoip)
	$(PIP) install paramiko geoip2

.PHONY: dashboard-install
dashboard-install: ## Install dashboard npm dependencies
	cd dashboard && npm install

# --------------------------------------------------------------------- run

.PHONY: seed
seed: ## Generate a synthetic demo dataset
	$(PY) -m tools.seed_fake_data --attackers 150 --days 14

.PHONY: honeypot
honeypot: ## Run the sensor (all enabled services)
	$(PY) -m honeypot.main

.PHONY: api
api: ## Run the API with autoreload
	$(PY) -m uvicorn api.main:app --reload --port 8000

.PHONY: dashboard
dashboard: ## Run the dashboard dev server
	cd dashboard && npm run dev

.PHONY: attack
attack: ## Fire all test scenarios at a local sensor
	$(PY) -m attacker.run --target 127.0.0.1 --scenario all

.PHONY: detect
detect: ## Re-run detection over the last 7 days
	$(PY) -c "from storage.db import session_scope; from pipeline.detection.rules import run_detection; \
		import json; \
		[print(json.dumps(run_detection(db, since_hours=168), indent=2)) for db in [session_scope().__enter__()]]"

.PHONY: report
report: ## Print the daily summary (Markdown)
	$(PY) -m pipeline.reporting.daily_summary --days 1

.PHONY: digest
digest: ## Send the daily digest to DIGEST_WEBHOOK_URL
	$(PY) -m pipeline.reporting.digest

.PHONY: digest-preview
digest-preview: ## Print the digest payload without sending it
	$(PY) -m pipeline.reporting.digest --dry-run

# ------------------------------------------------------------------- checks

.PHONY: test
test: ## Run the full test suite
	$(PY) -m pytest

.PHONY: lint
lint: ## Lint with ruff
	$(PY) -m ruff check .

.PHONY: fmt
fmt: ## Format with ruff
	$(PY) -m ruff format .

.PHONY: check
check: lint test ## Lint then test

# -------------------------------------------------------------------- infra

.PHONY: up
up: ## Bring up the full docker stack
	docker compose up --build

.PHONY: down
down: ## Tear down the docker stack
	docker compose down

.PHONY: reset
reset: ## Drop and recreate the database (destructive)
	$(PY) -m tools.reset_db --yes

.PHONY: clean
clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .ruff_cache **/__pycache__ dashboard/dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
