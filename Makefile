# Convenience targets for local development. Run `make help` for a list.

PYTHON ?= python3
VENV   ?= .venv
BIN     = $(VENV)/bin

.PHONY: help install install-backend install-web run run-prod demo api tui web preview link test test-backend test-integration test-web lint format build-web

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

install: install-backend install-web  ## Install all dependencies

install-backend:  ## Create .venv and install the Python package with dev extras
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

install-web:  ## Install dashboard dependencies
	cd web && npm ci

run: $(BIN)/traceforge web/node_modules  ## Start API + dashboard in one terminal and print a sign-in link
	$(BIN)/python scripts/run_local.py

run-prod: $(BIN)/traceforge web/node_modules  ## Same, with the hardened production build (strict CSP)
	$(BIN)/python scripts/run_local.py --prod

demo: $(BIN)/traceforge web/node_modules  ## `make run` plus a loopback-only demo project and target
	$(BIN)/python scripts/run_local.py --demo

# First use on a fresh clone: install whatever is missing.
$(BIN)/traceforge:
	$(MAKE) install-backend

web/node_modules:
	$(MAKE) install-web

api:  ## Run only the API on http://127.0.0.1:8000
	$(BIN)/traceforge serve

tui:  ## Run the terminal interface
	$(BIN)/traceforge tui

web:  ## Run only the dashboard dev server on http://127.0.0.1:5173
	cd web && npm run dev

preview: build-web  ## Serve the hardened production build on http://127.0.0.1:4173
	cd web && npm run preview

link:  ## Print a single-use dashboard sign-in link
	$(BIN)/traceforge dashboard-link


test: test-backend test-web  ## Run all tests

test-backend:  ## Run Python tests (integration tests scan only 127.0.0.1)
	$(BIN)/pytest

test-integration:  ## Run only the real-Nmap loopback integration tests
	$(BIN)/pytest -m integration

test-web:  ## Type-check and test the dashboard
	cd web && npm run typecheck && npm test

lint:  ## Lint Python code
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format:  ## Auto-format Python code
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

build-web:  ## Production build of the dashboard into web/dist
	cd web && npm run build
