# TrustLens AI. OWNER: Dev D (targets), but anyone may add a target under their own prefix (sandbox-*, eval-*, bench-*).
SHELL := /bin/bash
PY ?= .venv/bin/python
PIP ?= .venv/bin/pip
.DEFAULT_GOAL := help
.PHONY: help setup setup-dev check-env demo demo-live demo-all demo-compare serve eval eval-live test lint fmt audit fixtures bench-data kit clean

help:  ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n",$$1,$$2}'

setup:  ## create .venv with runtime deps (pinned)
	python3 -m venv .venv && $(PIP) install -q -r requirements.txt

setup-dev: setup  ## + pytest, ruff, audit tools, GuardDog, PipCanary baselines
	$(PIP) install -q -r requirements-dev.txt

check-env:  ## can this laptop run the bwrap sandbox? (do this first)
	-bash scripts/check_env.sh

demo:  ## end-to-end on recorded fixtures (no sandbox needed): scan 4 toy packages, write HTML reports to reports/demo/
	@mkdir -p reports/demo
	@for p in malicious/evil_slug malicious/delayed_slug clean/clean_slug clean/rest_wrapper; do \
	  n=$$(basename $$p); \
	  $(PY) -m trustlens scan bench/packages/$$p --runner fixture --offline --out reports/demo/$$n --format text | head -12; rc=$${PIPESTATUS[0]}; \
	  echo "  -> exit code $$rc (0=PASS 10=REVIEW 20=BLOCK)  report: reports/demo/$$n/report.html"; echo; done
	@echo "open reports/demo/evil_slug/report.html"

demo-live:  ## same, but really runs the toys in bwrap (needs bwrap; toys only!)
	$(PY) -m trustlens scan bench/packages/malicious/evil_slug --runner live --out reports/demo-live/evil_slug --format text; test $$? -eq 20

demo-all:  ## scan every bench/labels.yaml package and print verification table
	$(PY) -m trustlens demo-all --runner fixture

demo-compare:  ## generate side-by-side comparison report (clean vs malicious) for presentation slides
	$(PY) -m trustlens compare-demo
	@echo "open reports/compare_demo.html"

serve:  ## launch localhost Web UI console at http://127.0.0.1:8765/
	$(PY) -m trustlens serve --port 8765

eval:  ## PS1-Bench eval on fixtures: metrics + heatmap + baselines (if installed) -> reports/eval/
	$(PY) -m eval.run_eval --runner fixture --tools trustlens,guarddog,pipcanary
	@echo "see reports/eval/summary.md and reports/eval/heatmap.html"

eval-live:  ## eval with the live bwrap runner (slower)
	$(PY) -m eval.run_eval --runner live --tools trustlens,guarddog,pipcanary

test:  ## pytest (all dev folders) + contract audit
	$(PY) -m pytest
	$(PY) scripts/audit_contracts.py

lint:  ## ruff
	$(PY) -m ruff check .

fmt:  ## ruff autofix (only your own folder please: ruff check --fix <dir>)
	$(PY) -m ruff check --fix .

audit:  ## AUDIT.md automated checks
	bash scripts/audit.sh

fixtures:  ## regenerate claims/fingerprint/verdict example JSONs (lead only)
	$(PY) scripts/make_examples.py

bench-data:  ## Dev C: fetch clean list + seeded Datadog sample (needs network; data/ is gitignored)
	bash scripts/fetch_clean_list.sh 30
	bash scripts/fetch_datadog_sample.sh 150

kit:  ## zip the repo without venv/data/reports
	bash scripts/build_kit.sh

clean:  ## remove outputs (never touches data/)
	rm -rf reports .pytest_cache .ruff_cache .trustlens_work
