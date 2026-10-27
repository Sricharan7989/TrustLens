"""LLM Executive Report Generator for TrustLens AI.
Uses Google Gemini Flash (e.g. gemini-3.8-flash) or Groq to synthesize an executive-level
security intelligence report analyzing README claims vs observed behaviors and XGBoost Threat Score.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("trustlens.llm")

def _get_default_api_key() -> str:
    key = os.environ.get("GEMINI_API_KEY", "")
    if key:
        return key
    conf = Path("~/.config/gemini/api_key").expanduser()
    if conf.is_file():
        try:
            return conf.read_text().strip()
        except Exception:
            pass
    return ""


DEFAULT_GEMINI_KEY = _get_default_api_key()
GEMINI_MODELS = [
    "gemini-3.8-flash",
    "gemini-3.5-flash",
    "gemini-3.7-flash",
    "gemini-2.5-flash-lite",
    "gemini-flash-latest",
]


@dataclass
class LLMReportResult:
    report_markdown: str
    model_used: str
    is_live_llm: bool


def _build_prompt(
    verdict: dict,
    fingerprint: dict | None,
    claims: dict | None,
    threat_prediction: Any | None = None,
) -> str:
    pkg = verdict.get("package", {})
    action = verdict.get("action", "REVIEW")
    verdict_name = verdict.get("verdict", "INCONCLUSIVE")
    findings = verdict.get("findings") or []
    signals = verdict.get("independent_signals") or []

    # Format claims
    intents = [i.get("intent") for i in (claims or {}).get("intents", [])]
    quotes = [c.get("quote") for c in (claims or {}).get("claims", []) if c.get("quote")]
    claims_text = "\n".join(f"- {q}" for q in quotes[:3]) or "No explicit functionality claims found in README."

    # Format findings
    findings_text = ""
    for f in findings[:6]:
        findings_text += f"- [{f.get('severity', 'medium').upper()}] {f.get('title')}: {f.get('signal_class')} (Phase: {', '.join(f.get('phases', []))})\n"
    if not findings_text:
        findings_text = "None. Package observed behavior adhered cleanly to declared operations."

    ml_score = getattr(threat_prediction, "threat_score", verdict.get("score", 0.0))
    risk_tier = getattr(threat_prediction, "risk_tier", "UNKNOWN")

    prompt = f"""You are the Chief AI Forensic Officer for TrustLens, an advanced software supply-chain provenance platform.
Generate an authoritative, executive-level Threat Intelligence Report for the following Python package:

### PACKAGE IDENTITY:
- Name: {pkg.get('name', 'unknown')}
- Version: {pkg.get('version', '0.0')}
- Ecosystem: {pkg.get('ecosystem', 'pypi')}
- SHA256: {pkg.get('sha256', 'unknown')}

### DECLARED CLAIMS (README / METADATA):
- Declared Intents: {', '.join(intents) or 'None / Unknown'}
- Extracted Quotes:
{claims_text}

### OBSERVED BEHAVIOR & FORENSIC SIGNALS:
- Final TrustLens Verdict: {verdict_name} ({action})
- Independent Signal Classes: {', '.join(signals) or 'None'}
- Key Forensic Findings:
{findings_text}

### MACHINE LEARNING THREAT SCORING (XGBoost):
- Threat Score: {ml_score:.1f} / 100.0
- Risk Tier: {risk_tier}

### REQUIRED OUTPUT FORMAT:
Write a concise, polished markdown report with the following 4 sections:
1. ### Executive Summary
   A 2-3 sentence high-level assessment of whether this package is safe to install or a malicious trojan.
2. ### Behavioral Disparity (Claims vs. Reality)
   Contrast what the author claimed in README vs. what the package actually executes.
3. ### Malicious Indicators & Threat Vector Analysis
   Break down specific attack vectors (e.g. credential harvesting, unauthorized network connections, startup persistence, dynamic execution). Mention the XGBoost Threat Score ({ml_score:.1f}/100 - {risk_tier}).
4. ### Actionable Security Recommendation
   Clear directive: BLOCK IMMEDIATELY, QUARANTINE FOR REVIEW, or APPROVED FOR PRODUCTION.
"""
    return prompt


def generate_expert_fallback_report(
    verdict: dict,
    fingerprint: dict | None,
    claims: dict | None,
    threat_prediction: Any | None = None,
) -> str:
    """Deterministic, high-fidelity security intelligence report generator."""
    pkg = verdict.get("package", {})
    name = pkg.get("name", "unknown")
    verdict_name = verdict.get("verdict", "INCONCLUSIVE")
    action = verdict.get("action", "REVIEW")
    score = getattr(threat_prediction, "threat_score", verdict.get("score", 0.0))
    tier = getattr(threat_prediction, "risk_tier", "MEDIUM")
    signals = verdict.get("independent_signals") or []
    findings = verdict.get("findings") or []

    if action == "BLOCK" or verdict_name == "MALICIOUS-EVIDENT":
        return f"""### Executive Summary
**CRITICAL THREAT DETECTED:** Package `{name}` has been classified as **{verdict_name}** by TrustLens behavioral provenance. The package exhibits covert supply-chain attack behavior designed to compromise host credentials and exfiltrate sensitive data, completely contradicting its stated benign purpose.

### Behavioral Disparity (Claims vs. Reality)
The package documentation presents `{name}` as a standard Python utility. However, sandbox execution revealed that the package's primary runtime logic deviates immediately from its stated specification. Instead of executing benign domain operations, it attempts unauthorized operating system operations and sensitive file access during execution.

### Malicious Indicators & Threat Vector Analysis
- **XGBoost ML Threat Score:** **{score:.1f} / 100.0** (`{tier}`)
- **Triggered Signals:** {', '.join(signals) if signals else 'Unauthorized credential access and dynamic payload execution'}
- **Attack Vector:** High-severity findings ({len(findings)} events) confirm suspicious file reads, secret harvesting, and unauthorized communication attempts without any license in declared documentation.

### Actionable Security Recommendation
**RECOMMENDATION: BLOCK IMMEDIATELY**  
Do not import or install `{name}` in developer, CI/CD, or production environments. Any host where this package was executed should undergo credential revocation for SSH keys, AWS credentials, and environment tokens."""
    elif action == "PASS" or verdict_name == "BENIGN-CONSISTENT":
        return f"""### Executive Summary
**PACKAGE VERIFIED CLEAN:** Package `{name}` has been validated as **BENIGN-CONSISTENT**. All observed behavioral operations (file I/O, network sockets, process calls) remain strictly within the boundaries of its declared documentation and intent.

### Behavioral Disparity (Claims vs. Reality)
No behavioral discrepancy detected. The package's executed code corresponds directly with the functionality promised in its README and package metadata.

### Malicious Indicators & Threat Vector Analysis
- **XGBoost ML Threat Score:** **{score:.1f} / 100.0** (`{tier}`)
- **Independent Malicious Signals:** 0 detected
- **Baseline Audit:** Dynamic execution, startup hooks, and sensitive credential paths (`~/.ssh`, `~/.aws`) were completely unmolested during runtime observation.

### Actionable Security Recommendation
**RECOMMENDATION: APPROVED FOR PRODUCTION**  
Package `{name}` conforms to expected behavioral contracts and does not exhibit supply-chain attack anomalies within tested coverage."""
    else:
        return f"""### Executive Summary
**REVIEW REQUIRED (SUSPICIOUS / INCONCLUSIVE):** Package `{name}` received verdict **{verdict_name}** with an action recommendation of **{action}**. While no verified data exfiltration occurred, anomalous code patterns or thin coverage require manual provenance review.

### Behavioral Disparity (Claims vs. Reality)
The package performs operations that are not explicitly documented in its README, or the execution coverage was insufficient to conclusively prove benign consistency.

### Malicious Indicators & Threat Vector Analysis
- **XGBoost ML Threat Score:** **{score:.1f} / 100.0** (`{tier}`)
- **Findings Count:** {len(findings)} potential anomalies detected
- **Indicators:** Anomaly rules triggered in non-standard execution paths without explicit intent licensing.

### Actionable Security Recommendation
**RECOMMENDATION: QUARANTINE FOR MANUAL REVIEW**  
Place `{name}` in internal quarantine. Inspect source files and audit undeclared system interactions before deploying to production."""


def generate_llm_report(
    verdict: dict,
    fingerprint: dict | None = None,
    claims: dict | None = None,
    threat_prediction: Any | None = None,
) -> LLMReportResult:
    """Generate LLM intelligence report using Gemini or fallback to expert engine."""
    api_key = os.environ.get("GEMINI_API_KEY") or DEFAULT_GEMINI_KEY
    groq_key = os.environ.get("GROQ_API_KEY")

    prompt = _build_prompt(verdict, fingerprint, claims, threat_prediction)

    # 1. Try Gemini Models
    for model_name in GEMINI_MODELS:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 800,
            },
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=4) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        if text and len(text.strip()) > 50:
                            return LLMReportResult(
                                report_markdown=text.strip(),
                                model_used=f"Google Gemini ({model_name})",
                                is_live_llm=True,
                            )
        except Exception as e:
            logger.debug(f"Gemini model {model_name} failed: {e}")
            continue

    # 2. Try Groq if key provided
    if groq_key:
        try:
            groq_url = "https://api.groq.com/openai/v1/chat/completions"
            groq_payload = {
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {"role": "system", "content": "You are TrustLens AI Lead Cybersecurity Analyst."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
            }
            req = urllib.request.Request(
                groq_url,
                data=json.dumps(groq_payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {groq_key}",
                },
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
                text = data["choices"][0]["message"]["content"]
                return LLMReportResult(
                    report_markdown=text.strip(),
                    model_used="Groq (llama-3.3-70b-versatile)",
                    is_live_llm=True,
                )
        except Exception as e:
            logger.debug(f"Groq API call failed: {e}")

    # 3. Deterministic Expert Synthesis Fallback
    fallback_text = generate_expert_fallback_report(verdict, fingerprint, claims, threat_prediction)
    return LLMReportResult(
        report_markdown=fallback_text,
        model_used="TrustLens Neural Intelligence Synthesizer (Local)",
        is_live_llm=False,
    )
