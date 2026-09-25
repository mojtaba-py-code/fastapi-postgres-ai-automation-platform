.DEFAULT_GOAL := help
UV ?= uv
DEMO_COMPOSE = docker compose -f docker-compose.yml -f docker-compose.demo.yml
E2E_BASE_URL ?= https://localhost

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

install: ## Install runtime + dev dependencies (incl. embedded PostgreSQL for tests)
	$(UV) sync --frozen --group dev --group localdb

lint: ## Ruff (lint + format check), mypy, architecture contracts, drift checks
	$(UV) run ruff check src tests scripts migrations
	$(UV) run ruff format --check src tests scripts migrations
	$(UV) run mypy src
	$(UV) run lint-imports
	$(UV) run python scripts/gen_config_reference.py --check
	$(UV) run python scripts/pin_images.py --check

security: ## Bandit, dependency audit, n8n workflow lint
	$(UV) run bandit -c pyproject.toml -r src scripts -q
	$(UV) export --frozen --no-dev --all-extras --no-emit-project --format requirements-txt -o /tmp/nexusflow-req.txt
	$(UV) run pip-audit -r /tmp/nexusflow-req.txt --require-hashes --disable-pip
	$(UV) run python scripts/validate_n8n_workflows.py

test: ## Unit tests
	$(UV) run pytest tests/unit

test-all: ## Every test except e2e (integration tests start an embedded PostgreSQL)
	$(UV) run pytest

e2e: ## End-to-end tests against the running demo stack (make demo-up first)
	NEXUSFLOW_E2E_BASE_URL=$(E2E_BASE_URL) NEXUSFLOW_E2E_CA_BUNDLE=deploy/certs/dev-ca.pem \
	NEXUSFLOW_E2E_MAILPIT_URL=http://127.0.0.1:8025 $(UV) run pytest tests/e2e -m e2e

check: lint security test-all ## Everything CI runs

config-docs: ## Regenerate docs/CONFIGURATION.md from the settings classes
	$(UV) run python scripts/gen_config_reference.py

pin-images: ## Pin every base and third-party image to the digest its tag points at now
	$(UV) run python scripts/pin_images.py

secrets: ## Generate ./secrets for docker compose
	$(UV) run python scripts/generate_secrets.py
	$(UV) run python scripts/internal_pki.py

dev-certs: ## Local development CA + TLS certificate in deploy/certs (never for production)
	$(UV) run python scripts/dev_certs.py

up: ## Build and start the production-like stack
	docker compose up -d --build

down: ## Stop the stack
	docker compose down

demo-up: ## Start the stack with the demo overlay (Mailpit, internal orchestration)
	$(DEMO_COMPOSE) up -d --build

demo: ## Scripted walkthrough against the running demo stack
	$(UV) run python scripts/demo.py --base-url https://localhost --ca-file deploy/certs/dev-ca.pem

demo-down: ## Stop the demo stack
	$(DEMO_COMPOSE) down

.PHONY: help install lint security test test-all e2e check config-docs pin-images secrets dev-certs up down demo-up demo demo-down
