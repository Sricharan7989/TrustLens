#!/usr/bin/env bash
# Automated half of AUDIT.md. Exit 1 if any FAIL. WARN/SKIP never fail. Run before every merge and at H-2.
cd "$(dirname "$0")/.."
PY="${PY:-.venv/bin/python}"; [ -x "$PY" ] || PY=python3
mkdir -p reports/audit; LOG=reports/audit/latest.txt; : > "$LOG"
fail=0
res() { printf '%-5s %-34s %s\n' "$1" "$2" "$3" | tee -a "$LOG"; [ "$1" = FAIL ] && fail=1; return 0; }

# 1 lint
if $PY -m ruff --version >/dev/null 2>&1; then $PY -m ruff check . >/tmp/tl_ruff.txt 2>&1 && res PASS "ruff" "" || { res FAIL "ruff" "see: make lint"; cat /tmp/tl_ruff.txt | head -20; }; else res SKIP "ruff" "not installed (make setup-dev)"; fi
# 2 contracts
$PY scripts/audit_contracts.py >/tmp/tl_ac.txt 2>&1 && res PASS "contracts (schemas vs examples)" "$(tail -1 /tmp/tl_ac.txt)" || { res FAIL "contracts" ""; cat /tmp/tl_ac.txt; }
# 3 tests
if $PY -m pytest --version >/dev/null 2>&1; then $PY -m pytest >/tmp/tl_pt.txt 2>&1 && res PASS "pytest" "$(tail -1 /tmp/tl_pt.txt)" || { res FAIL "pytest" ""; tail -20 /tmp/tl_pt.txt; }; else res SKIP "pytest" "not installed"; fi
# 4 secrets
bash scripts/scan_secrets.sh >/tmp/tl_sec.txt 2>&1 && res PASS "secrets scan" "$(tail -1 /tmp/tl_sec.txt)" || { res FAIL "secrets scan" ""; cat /tmp/tl_sec.txt; }
# 5 banned claims in pitch-facing docs
BAN='first (ever )?sandbox|first (tool )?to (use|run|do).*sandbox|first (false.?positive|FP)|first (eval|evaluation|benchmark)|nobody (else )?compar|no one (else )?compar|100% (accurate|detection)|zero false.positive|catches (all|every)|detects all|solves supply'
hits=$(grep -inE "$BAN" README.md docs/ARCHITECTURE.md docs/DEMO_SCRIPT.md docs/PPT_OUTLINE.md 2>/dev/null | grep -viE 'do not claim|never claim|not claim' || true)
[ -z "$hits" ] && res PASS "banned claims" "" || { res FAIL "banned claims" "see below"; echo "$hits"; }
# 6 supply-chain-guard name trap (pip package of that name is a DIFFERENT, hostile project)
grep -riEn "supply-chain-guard" requirements*.txt pyproject.toml Makefile scripts/*.sh 2>/dev/null | grep -v "^scripts/audit.sh" >/tmp/tl_scg.txt
[ ! -s /tmp/tl_scg.txt ] && res PASS "no pip supply-chain-guard" "" || { res FAIL "supply-chain-guard referenced in install files" ""; cat /tmp/tl_scg.txt; }
# 7 licensing: no Packj code
grep -rEn "^\s*(import|from)\s+packj" --include=*.py . 2>/dev/null | grep -v "^./.venv" >/tmp/tl_pk.txt
[ ! -s /tmp/tl_pk.txt ] && res PASS "no Packj import (AGPL)" "" || { res FAIL "Packj imported" ""; cat /tmp/tl_pk.txt; }
# 8 no hidden network in product code (offline mode); bench/ tools & scripts/fetch_* are the only network users
grep -rEn "import requests|urllib\.request\.urlopen|http\.client|urlopen\(" trustlens/ eval/ --include=*.py 2>/dev/null | grep -v "sandbox/agent/" >/tmp/tl_net.txt
[ ! -s /tmp/tl_net.txt ] && res PASS "no network calls in trustlens/ eval/" "" || { res WARN "network usage found (must be behind a non-offline flag)" ""; cat /tmp/tl_net.txt; }
# 9 malware hygiene: data & archives not tracked, data ignored
if git rev-parse --git-dir >/dev/null 2>&1; then
  bad=$(git ls-files | grep -E '^(data|samples)/|\.zip$|\.whl$|\.tar\.gz$' || true)
  [ -z "$bad" ] && res PASS "no data/zips tracked" "" || { res FAIL "tracked data/archives" ""; echo "$bad"; }
  git check-ignore -q data/x && res PASS "data/ gitignored" "" || res FAIL "data/ gitignored" "add data/ to .gitignore"
else res SKIP "git hygiene" "not a git repo"; fi
# 10 dependency pins
unp=$(grep -vE '^\s*(#|-r|$)' requirements.txt requirements-dev.txt | grep -v '==' || true)
[ -z "$unp" ] && res PASS "all deps pinned (==)" "" || { res FAIL "unpinned deps" ""; echo "$unp"; }
# 11 licenses of installed deps (flag GPL/AGPL)
if $PY -m piplicenses --version >/dev/null 2>&1; then
  $PY -m piplicenses --format=csv --with-system 2>/dev/null | grep -iE 'AGPL|GPL-3|GNU General' | grep -viE 'LGPL' >/tmp/tl_lic.txt
  [ ! -s /tmp/tl_lic.txt ] && res PASS "dep licenses (no GPL/AGPL)" "" || { res WARN "GPL-family dep present: review DEPENDENCIES.md" ""; cat /tmp/tl_lic.txt; }
  $PY -m piplicenses --format=markdown --output-file=reports/audit/licenses.md >/dev/null 2>&1
else res SKIP "pip-licenses" "not installed"; fi
# 12 pip-audit (needs network to fetch advisories; skipped cleanly offline)
if $PY -m pip_audit --version >/dev/null 2>&1; then
  if timeout 5 curl -sI https://pypi.org >/dev/null 2>&1; then
    timeout 120 $PY -m pip_audit -r requirements.txt --progress-spinner off >/tmp/tl_pa.txt 2>&1 && res PASS "pip-audit" "" || { res WARN "pip-audit findings/err" ""; tail -8 /tmp/tl_pa.txt; }
  else res SKIP "pip-audit" "offline"; fi
else res SKIP "pip-audit" "not installed"; fi
# 13 fixture replays must self-identify as stub (never pass off as a live run)
grep -q '"stub"\|stub=True\|\["stub"\]' trustlens/sandbox/fixture_runner.py && res PASS "fixture runner marks stub" "" || res FAIL "fixture runner must set run.stub=true" ""
# 14 sandbox flags still present in the live runner (guard against accidental removal)
miss=""; for f in --unshare-net --unshare-pid --clearenv --die-with-parent; do grep -q -- "$f" trustlens/sandbox/*.py || miss="$miss $f"; done
[ -z "$miss" ] && res PASS "bwrap isolation flags present" "" || res FAIL "bwrap flags missing" "$miss"
# 15 ownership (only when on a dev branch)
br=$(git rev-parse --abbrev-ref HEAD 2>/dev/null); case "$br" in dev-a*|dev-b*|dev-c*|dev-d*) d=${br:4:1}; $PY scripts/check_ownership.py --dev "$d" >/tmp/tl_own.txt 2>&1 && res PASS "ownership ($d)" "" || { res FAIL "ownership ($d)" ""; cat /tmp/tl_own.txt; };; *) res SKIP "ownership" "branch $br";; esac
echo; echo "log: $LOG   ($(date -u '+%F %T UTC'))"
[ $fail = 0 ] && echo "AUDIT AUTOMATED CHECKS: PASS (manual checklist in AUDIT.md still required)" || echo "AUDIT AUTOMATED CHECKS: FAIL"
exit $fail
