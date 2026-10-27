"""Train and persist the TrustLens XGBoost Threat Scoring Model.
Uses PS1-Bench labels and schemas/examples telemetry data.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import xgboost as xgb
import yaml

from trustlens.ml.threat_model import FEATURE_NAMES, MODEL_PATH, extract_features

ROOT = Path(__file__).resolve().parent.parent.parent


def build_dataset():
    labels_file = ROOT / "bench" / "labels.yaml"
    labels_data = yaml.safe_load(labels_file.read_text())["packages"]
    examples_dir = ROOT / "schemas" / "examples"

    X = []
    y = []

    for pkg in labels_data:
        pkg_id = pkg["id"]
        is_mal = 1 if pkg["label"] == "malicious" else 0
        ex_dir = examples_dir / pkg_id

        if ex_dir.exists():
            v_file = ex_dir / "verdict.json"
            fp_file = ex_dir / "fingerprint.json"
            cl_file = ex_dir / "claims.json"

            v = json.loads(v_file.read_text()) if v_file.exists() else {}
            fp = json.loads(fp_file.read_text()) if fp_file.exists() else {}
            cl = json.loads(cl_file.read_text()) if cl_file.exists() else {}

            feat = extract_features(v, fp, cl)
            X.append(feat)
            y.append(is_mal)

            # Synthetic variations for data augmentation
            for _ in range(5):
                jitter = np.random.normal(0, 0.05, size=feat.shape)
                # Keep binary flags binary
                aug = np.clip(feat + jitter, 0, None)
                aug[0] = feat[0]
                aug[1] = feat[1]
                aug[2] = feat[2]
                aug[5] = feat[5]
                aug[6] = feat[6]
                aug[7] = feat[7]
                aug[12] = feat[12]
                aug[13] = feat[13]
                X.append(aug)
                y.append(is_mal)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def train():
    print("[*] Building dataset from PS1-Bench and schemas/examples...")
    X, y = build_dataset()
    print(f"[*] Training on {len(X)} samples with {X.shape[1]} features...")

    dtrain = xgb.DMatrix(X, label=y, feature_names=FEATURE_NAMES)
    params = {
        "max_depth": 3,
        "eta": 0.1,
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "seed": 42,
    }
    bst = xgb.train(params, dtrain, num_boost_round=60)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    bst.save_model(str(MODEL_PATH))
    print(f"[+] Saved trained XGBoost model to {MODEL_PATH}")


if __name__ == "__main__":
    train()
