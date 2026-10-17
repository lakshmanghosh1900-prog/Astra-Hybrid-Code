PYTHON ?= python3.12
PIP ?= $(PYTHON) -m pip

.PHONY: install test lint typecheck security format check dashboard-install

install:
	$(PIP) install -r requirements.lock

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check src tests

format:
	$(PYTHON) -m ruff format --check src tests

typecheck:
	$(PYTHON) -m mypy src

security:
	@set -e; if command -v semgrep >/dev/null 2>&1; then semgrep --config semgrep.yml --error; else echo "semgrep unavailable: install it for release verification"; fi
	@set -e; if command -v gitleaks >/dev/null 2>&1; then gitleaks detect --no-banner --redact; else echo "gitleaks unavailable: install it for release verification"; fi

dashboard-install:
	cd dashboard && npm ci
