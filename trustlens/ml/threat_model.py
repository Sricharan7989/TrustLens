"""XGBoost Threat Scoring Model for TrustLens.
Calculates a continuous Threat Score (0.0 - 100.0) and Risk Tier
based on behavioral observations, static AST findings, and README claims disparity.
"""
from __future__ import annotations

import json
import logging
import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

logger = logging.getLogger("trustlens.ml")

MODEL_PATH = Path(__file__).parent / "model.json"
META_PATH = Path(__file__).parent / "feature_meta.json"

FEATURE_NAMES = [
    "feat_canary_access",
    "feat_network_unclaimed",
    "feat_canary_in_bytes",
    "feat_dynamic_exec",
    "feat_obfuscation",
    "feat_startup_hook",
    "feat_env_differential",
    "feat_download_exec",
    "feat_undeclared_caps",
    "feat_rule_findings",
    "feat_max_severity",
    "feat_readme_char_len",
    "feat_has_cli",
    "feat_network_declared",
]


@dataclass
class ThreatPrediction:
    threat_score: float  # 0.0 to 100.0
    risk_tier: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"
    confidence: str  # "high", "medium", "low"
    top_factors: list[dict[str, Any]] = field(default_factory=list)
    raw_probability: float = 0.0


def extract_features(
    verdict: dict,
    fingerprint: dict | None = None,
    claims: dict | None = None,
    static_result: Any | None = None,
) -> np.ndarray:
    """Extract a 14-dimensional feature vector from TrustLens analysis outputs."""
    v = verdict or {}
    fp = fingerprint or {}
    cl = claims or {}
    findings = v.get("findings") or []
    signals = set(v.get("independent_signals") or [])

    # Static signals if available
    has_pth = False
    dynamic_exec_count = 0
    obfuscation_count = 0
    if static_result:
        has_pth = getattr(static_result, "has_pth_hook", False)
        if getattr(static_result, "has_eval_exec", False):
            dynamic_exec_count += 2
        if getattr(static_result, "has_obfuscation", False):
            obfuscation_count += 2

    # Findings scan
    canary_hit = "canary_access" in signals
    canary_in_bytes = "canary_in_bytes" in signals
    network_unclaimed = "network_unclaimed" in signals
    env_diff = "env_differential" in signals
    download_exec = "download_exec" in signals
    startup_hook = "startup_hook" in signals or has_pth

    for f in findings:
        sc = f.get("signal_class") or f.get("rule", "")
        if "canary" in sc:
            canary_hit = True
        if "network" in sc and f.get("claim", {}).get("status") == "not_claimed":
            network_unclaimed = True
        if "decoded_exec" in sc or "dynamic_exec" in sc:
            dynamic_exec_count += 1
        if "obfuscated" in sc or "xor" in sc:
            obfuscation_count += 1
        if "startup" in sc:
            startup_hook = True

    # Claims features
    claimed_caps = set(cl.get("claimed_capabilities") or [])
    observed_caps = set()
    for ev in fp.get("events") or []:
        if ev.get("capability"):
            observed_caps.add(ev["capability"])
    undeclared = len(observed_caps - claimed_caps)

    # README length
    readme_quote_len = 0
    for c in cl.get("claims") or []:
        readme_quote_len += len(c.get("quote") or "")
    for intent in cl.get("intents") or []:
        readme_quote_len += len(intent.get("quote") or "")

    max_sev = max([f.get("score", 0.0) for f in findings], default=0.0)
    has_cli = 1.0 if "cli_tool" in [i.get("intent") for i in cl.get("intents") or []] else 0.0
    net_declared = 1.0 if "http_client" in [i.get("intent") for i in cl.get("intents") or []] or "network" in claimed_caps else 0.0

    features = [
        1.0 if canary_hit else 0.0,
        1.0 if network_unclaimed else 0.0,
        1.0 if canary_in_bytes else 0.0,
        float(dynamic_exec_count),
        float(obfuscation_count),
        1.0 if startup_hook else 0.0,
        1.0 if env_diff else 0.0,
        1.0 if download_exec else 0.0,
        float(undeclared),
        float(len(findings)),
        float(max_sev),
        min(10.0, math.log1p(readme_quote_len)),
        has_cli,
        net_declared,
    ]
    if NUMPY_AVAILABLE and np is not None:
        return np.array(features, dtype=np.float32)
    return features


class ThreatModel:
    def __init__(self):
        self.model: xgb.Booster | None = None
        self._load()

    def _load(self):
        if XGB_AVAILABLE and MODEL_PATH.exists():
            try:
                self.model = xgb.Booster()
                self.model.load_model(str(MODEL_PATH))
            except Exception as e:
                logger.warning(f"Could not load pre-trained XGBoost model: {e}")
                self.model = None

    def predict(
        self,
        verdict: dict,
        fingerprint: dict | None = None,
        claims: dict | None = None,
        static_result: Any | None = None,
    ) -> ThreatPrediction:
        feats = extract_features(verdict, fingerprint, claims, static_result)
        
        # High impact indicators
        canary_access = feats[0] > 0
        network_unclaimed = feats[1] > 0
        canary_bytes = feats[2] > 0
        dynamic_exec = feats[3] > 0
        startup_hook = feats[5] > 0
        download_exec = feats[7] > 0

        prob = 0.0
        if self.model is not None and XGB_AVAILABLE and NUMPY_AVAILABLE and np is not None:
            dmat = xgb.DMatrix(np.array(feats, dtype=np.float32).reshape(1, -1), feature_names=FEATURE_NAMES)
            preds = self.model.predict(dmat)
            prob = float(preds[0])
        else:
            # Deterministic linear calibration fallback based on weight definitions
            base_score = 0.0
            if canary_bytes:
                base_score += 0.95
            elif canary_access and network_unclaimed:
                base_score += 0.92
            elif startup_hook:
                base_score += 0.88
            elif dynamic_exec and network_unclaimed:
                base_score += 0.85
            elif download_exec:
                base_score += 0.65
            elif feats[9] > 0:  # findings
                base_score += min(0.5, feats[9] * 0.1)

            # Benign reductions
            if feats[13] > 0 and not canary_access:  # network claimed
                base_score = max(0.02, base_score - 0.25)
            prob = min(0.99, max(0.01, base_score))

        score = round(prob * 100.0, 1)

        # Risk tier determination
        if score >= 80.0 or canary_bytes or (canary_access and network_unclaimed) or startup_hook:
            tier = "CRITICAL"
            score = max(score, 88.0)
        elif score >= 60.0 or download_exec:
            tier = "HIGH"
        elif score >= 35.0:
            tier = "MEDIUM"
        elif score >= 12.0:
            tier = "LOW"
        else:
            tier = "CLEAN"

        # Factors
        factors = []
        if canary_access:
            factors.append({"factor": "Sensitive Credential Read", "severity": "CRITICAL", "weight": "+35%"})
        if network_unclaimed:
            factors.append({"factor": "Undeclared Network Activity", "severity": "HIGH", "weight": "+25%"})
        if canary_bytes:
            factors.append({"factor": "Credential Exfiltration in Packet Payload", "severity": "CRITICAL", "weight": "+40%"})
        if dynamic_exec:
            factors.append({"factor": "Dynamic Code Evaluation (exec/eval)", "severity": "HIGH", "weight": "+20%"})
        if startup_hook:
            factors.append({"factor": "Interpreter Startup Hook (.pth)", "severity": "CRITICAL", "weight": "+30%"})
        if download_exec:
            factors.append({"factor": "Remote Payload Dropper", "severity": "HIGH", "weight": "+25%"})
        if feats[13] > 0:
            factors.append({"factor": "Network Usage Authorized in Documentation", "severity": "INFO", "weight": "-20%"})

        return ThreatPrediction(
            threat_score=score,
            risk_tier=tier,
            confidence="high" if len(factors) >= 2 or score > 80 or score < 10 else "medium",
            top_factors=factors,
            raw_probability=prob,
        )


_global_model: ThreatModel | None = None


def get_threat_model() -> ThreatModel:
    global _global_model
    if _global_model is None:
        _global_model = ThreatModel()
    return _global_model
