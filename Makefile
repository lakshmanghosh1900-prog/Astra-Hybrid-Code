PYTHON ?= python3.12
PIP ?= $(PYTHON) -m pip
SEMGREP ?= semgrep
GITLEAKS ?= gitleaks

.PHONY: install test lint format typecheck security benchmark check dashboard-install

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
	@set -e; if command -v $(SEMGREP) >/dev/null 2>&1 || [ -x "$(SEMGREP)" ]; then $(SEMGREP) --config semgrep.yml --error; else echo "semgrep unavailable: release gate blocked"; exit 2; fi
	@set -e; if command -v $(GITLEAKS) >/dev/null 2>&1; then $(GITLEAKS) detect --no-banner --redact; elif [ -x .tools/gitleaks ]; then .tools/gitleaks detect --no-banner --redact; else echo "gitleaks unavailable: release gate blocked"; exit 2; fi

benchmark:
	PYTHONPATH=src $(PYTHON) -m astra_coder.benchmark

check: test lint format typecheck

dashboard-install:
	cd dashboard && npm ci
