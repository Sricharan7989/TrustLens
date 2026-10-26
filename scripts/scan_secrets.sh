#!/usr/bin/env bash
# Secrets scan: gitleaks if installed, else a grep fallback. Planted CANARY values (see allowlist below) are fake on purpose.
cd "$(dirname "$0")/.."
if command -v gitleaks >/dev/null; then gitleaks detect --no-banner --redact -s . && echo "gitleaks: clean"; exit $?; fi
PAT='(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----[A-Za-z0-9+/=\s]{40,}|AIza[0-9A-Za-z_-]{35})'
hits=$(git ls-files -z 2>/dev/null | xargs -0 grep -InE "$PAT" 2>/dev/null | grep -viE 'canary|TRUSTLENS_FAKE|example|fixture' || true)
if [ -n "$hits" ]; then echo "POSSIBLE SECRETS:"; echo "$hits"; exit 1; fi
echo "secrets grep: clean (gitleaks not installed; fallback grep used)"
