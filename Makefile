.PHONY: setup dev dev-api dev-threat-intel migrate seed reset-db test test-api test-threat-intel clean

PY := .venv/bin/python

# ---------------------------------------------------------------------------- #
# Setup - run once
# ---------------------------------------------------------------------------- #

setup:
	@python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
		|| (echo "Python 3.10+ required, found $$(python3 -V). Install a newer python3 and retry."; exit 1)
	python3 -m venv .venv
	.venv/bin/pip install --quiet --upgrade pip
	.venv/bin/pip install --quiet -r api/requirements.txt -r threat-intel/requirements.txt
	$(MAKE) seed
	@echo ""
	@echo "Done. Run 'make dev' - Platform API on :8000, Threat Intel on :8001"

# ---------------------------------------------------------------------------- #
# Run
# ---------------------------------------------------------------------------- #

# Starts Platform API on :8000 and the simulated Threat Intel on :8001. Ctrl-C stops both.
dev:
	$(MAKE) -j2 dev-api dev-threat-intel

# Platform API only, on :8000. Scan endpoints return 503 until Threat Intel is up on :8001.
dev-api:
	cd api && ../$(PY) manage.py runserver 8000

# Simulated Threat Intel only, on :8001.
dev-threat-intel:
	cd threat-intel && ../.venv/bin/uvicorn threat_intel.main:app --port 8001

migrate:
	cd api && ../$(PY) manage.py migrate

# Wipes and re-creates the demo data. Creates the tables first if they are gone,
# so this works on an empty or deleted database too.
seed: migrate
	cd api && ../$(PY) manage.py seed

# Throws the database away and rebuilds it from scratch.
reset-db:
	rm -f api/db.sqlite3
	$(MAKE) seed

# ---------------------------------------------------------------------------- #
# Tests - the Platform API suite is the spec. Green means done.
# ---------------------------------------------------------------------------- #

# Runs both suites even when the first one fails; the exit code still says so.
test:
	$(MAKE) --no-print-directory -k test-api test-threat-intel

test-api:
	cd api && ../$(PY) -m pytest

# Sanity tests for the simulated Threat Intel. Not an exercise; they pass as given.
test-threat-intel:
	cd threat-intel && ../$(PY) -m pytest

clean:
	rm -rf .venv api/db.sqlite3
