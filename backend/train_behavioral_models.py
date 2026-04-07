#!/usr/bin/env python3
"""
Train the two-model behavioural anomaly detection ensemble on synthetic
cloud-storage behavioural data.

Models:
  - Isolation Forest  (unsupervised — catches unknown anomaly patterns)
  - Random Forest     (supervised  — high accuracy on known archetypes)

All 12 features match exactly what ai_detection_service.py extracts at
runtime, so there is no training/inference domain gap.

Usage:
    python train_behavioral_models.py
    # inside Docker:
    docker exec -it scp-gateway python train_behavioral_models.py
"""
from dotenv import load_dotenv
load_dotenv()

import os
import json
import logging
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report, roc_auc_score,
    average_precision_score, confusion_matrix,
)
import joblib

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("train_behavioral")

MODEL_DIR = os.getenv("MODEL_DIR", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

SEED = 42
np.random.seed(SEED)

# These 12 features must stay in sync with extract_features() in
# ai_detection_service.py — any change here requires a change there too.
BEHAVIORAL_FEATURES = [
    "hour_of_day",        # 0–23
    "day_of_week",        # 0–6  (Mon=0)
    "is_night",           # 1 if hour < 6
    "file_size_mb",       # file_size bytes / 1e6, clipped at 1000
    "is_upload",          # 1=upload, 0=download
    "events_1h",          # events in past hour (Redis)
    "events_24h",         # events in past 24 h (Redis)
    "rapid_succession",   # 1 if last event < 5 s ago
    "prev_anomaly_count", # historical anomaly count for this user
    "ip_is_private",      # 1 if RFC-1918 or loopback
    "events_per_hour",    # events_24h / 24
    "high_volume",        # 1 if events_1h > 10
]
N_FEATURES = len(BEHAVIORAL_FEATURES)


# ---------------------------------------------------------------------------
# Synthetic data generation
# ---------------------------------------------------------------------------

def generate_normal(n: int) -> pd.DataFrame:
    """Generate n normal-behaviour samples."""
    rng = np.random.default_rng(SEED)

    # 70 % business hours (9–17), 30 % any hour
    n_biz = int(n * 0.70)
    hours = np.concatenate([
        rng.choice(range(9, 18), n_biz),
        rng.integers(0, 24, n - n_biz),
    ])
    rng.shuffle(hours)

    # 85 % weekdays
    n_wk = int(n * 0.85)
    days = np.concatenate([
        rng.choice(range(0, 5), n_wk),
        rng.choice([5, 6], n - n_wk),
    ])
    rng.shuffle(days)

    file_mb = np.clip(np.exp(rng.normal(np.log(0.05), 2.0, n)), 0.001, 500.0)
    ev1h  = rng.poisson(2, n).astype(float)
    ev24h = np.maximum(rng.poisson(15, n).astype(float), ev1h)

    return pd.DataFrame({
        "hour_of_day":        hours.astype(float),
        "day_of_week":        days.astype(float),
        "is_night":           (hours < 6).astype(float),
        "file_size_mb":       file_mb,
        "is_upload":          rng.binomial(1, 0.6, n).astype(float),
        "events_1h":          ev1h,
        "events_24h":         ev24h,
        "rapid_succession":   rng.binomial(1, 0.03, n).astype(float),
        "prev_anomaly_count": rng.choice([0]*8 + [1, 2], n).astype(float),
        "ip_is_private":      rng.binomial(1, 0.75, n).astype(float),
        "events_per_hour":    ev24h / 24.0,
        "high_volume":        (ev1h > 10).astype(float),
    })


def generate_anomalous(n_per_type: int) -> pd.DataFrame:
    """Generate anomalous samples across 4 insider-threat archetypes."""
    rng = np.random.default_rng(SEED + 1)
    frames = []
    n = n_per_type

    # --- Archetype 1: late-night bulk download via public IP ---
    ev1 = rng.integers(5, 20, n).astype(float)
    ev24 = np.maximum(rng.integers(20, 60, n).astype(float), ev1)
    hrs = rng.choice(range(0, 6), n).astype(float)
    frames.append(pd.DataFrame({
        "hour_of_day":        hrs,
        "day_of_week":        rng.integers(0, 7, n).astype(float),
        "is_night":           np.ones(n),
        "file_size_mb":       np.clip(np.exp(rng.normal(np.log(50), 1.5, n)), 1.0, 1000.0),
        "is_upload":          np.zeros(n),
        "events_1h":          ev1,
        "events_24h":         ev24,
        "rapid_succession":   rng.binomial(1, 0.4, n).astype(float),
        "prev_anomaly_count": rng.integers(0, 4, n).astype(float),
        "ip_is_private":      np.zeros(n),
        "events_per_hour":    ev24 / 24.0,
        "high_volume":        np.ones(n),
    }))

    # --- Archetype 2: rapid bulk access / exfiltration ---
    ev1 = rng.integers(15, 50, n).astype(float)
    ev24 = np.maximum(rng.integers(40, 200, n).astype(float), ev1)
    frames.append(pd.DataFrame({
        "hour_of_day":        rng.integers(0, 24, n).astype(float),
        "day_of_week":        rng.integers(0, 7, n).astype(float),
        "is_night":           rng.binomial(1, 0.3, n).astype(float),
        "file_size_mb":       np.clip(np.exp(rng.normal(np.log(10), 1.5, n)), 0.1, 500.0),
        "is_upload":          rng.binomial(1, 0.5, n).astype(float),
        "events_1h":          ev1,
        "events_24h":         ev24,
        "rapid_succession":   np.ones(n),
        "prev_anomaly_count": rng.integers(0, 3, n).astype(float),
        "ip_is_private":      rng.binomial(1, 0.5, n).astype(float),
        "events_per_hour":    ev24 / 24.0,
        "high_volume":        np.ones(n),
    }))

    # --- Archetype 3: public IP + very large transfer ---
    ev1 = rng.integers(8, 30, n).astype(float)
    ev24 = np.maximum(rng.integers(40, 100, n).astype(float), ev1)
    frames.append(pd.DataFrame({
        "hour_of_day":        rng.integers(0, 24, n).astype(float),
        "day_of_week":        rng.integers(0, 7, n).astype(float),
        "is_night":           rng.binomial(1, 0.4, n).astype(float),
        "file_size_mb":       np.clip(np.exp(rng.normal(np.log(100), 1.0, n)), 10.0, 1000.0),
        "is_upload":          rng.binomial(1, 0.3, n).astype(float),
        "events_1h":          ev1,
        "events_24h":         ev24,
        "rapid_succession":   rng.binomial(1, 0.3, n).astype(float),
        "prev_anomaly_count": rng.integers(0, 5, n).astype(float),
        "ip_is_private":      np.zeros(n),
        "events_per_hour":    ev24 / 24.0,
        "high_volume":        rng.binomial(1, 0.7, n).astype(float),
    }))

    # --- Archetype 4: repeat offender with high anomaly history ---
    ev1 = rng.integers(3, 20, n).astype(float)
    ev24 = np.maximum(rng.integers(15, 80, n).astype(float), ev1)
    frames.append(pd.DataFrame({
        "hour_of_day":        rng.integers(0, 24, n).astype(float),
        "day_of_week":        rng.integers(0, 7, n).astype(float),
        "is_night":           rng.binomial(1, 0.5, n).astype(float),
        "file_size_mb":       np.clip(np.exp(rng.normal(np.log(5), 2.0, n)), 0.001, 500.0),
        "is_upload":          rng.binomial(1, 0.5, n).astype(float),
        "events_1h":          ev1,
        "events_24h":         ev24,
        "rapid_succession":   rng.binomial(1, 0.4, n).astype(float),
        "prev_anomaly_count": rng.integers(4, 20, n).astype(float),
        "ip_is_private":      rng.binomial(1, 0.4, n).astype(float),
        "events_per_hour":    ev24 / 24.0,
        "high_volume":        rng.binomial(1, 0.5, n).astype(float),
    }))

    return pd.concat(frames, ignore_index=True)


# ---------------------------------------------------------------------------
# Model training
# ---------------------------------------------------------------------------

def train_isolation_forest(X_normal: np.ndarray) -> IsolationForest:
    """Train IF on normal-only data."""
    logger.info(f"Training Isolation Forest on {len(X_normal):,} normal samples…")
    iso = IsolationForest(
        n_estimators=100, contamination=0.05,
        random_state=SEED, n_jobs=-1,
    )
    iso.fit(X_normal)
    return iso


def train_random_forest(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """Train RF on full labelled dataset."""
    logger.info(f"Training Random Forest on {len(X_train):,} samples…")
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=15,
        class_weight="balanced", random_state=SEED, n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    return rf


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(name: str, y_true: np.ndarray, scores: np.ndarray, thr: float = 0.5) -> None:
    preds = (scores >= thr).astype(int)
    print(f"\n{'='*60}\n  {name}\n{'='*60}")
    print(classification_report(y_true, preds, target_names=["Normal", "Anomalous"]))
    cm = confusion_matrix(y_true, preds)
    tn, fp, fn, tp = cm.ravel()
    print(f"  TN={tn}  FP={fp}  FN={fn}  TP={tp}")
    try:
        auc = roc_auc_score(y_true, scores)
        ap  = average_precision_score(y_true, scores)
        print(f"  ROC-AUC: {auc:.4f}  |  Avg Precision: {ap:.4f}")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    logger.info("Generating synthetic behavioural dataset…")
    df_norm  = generate_normal(80_000)
    df_anom  = generate_anomalous(n_per_type=5_000)
    df_norm["label"] = 0
    df_anom["label"] = 1

    df = (
        pd.concat([df_norm, df_anom], ignore_index=True)
        .sample(frac=1, random_state=SEED)
        .reset_index(drop=True)
    )
    X = df[BEHAVIORAL_FEATURES].values.astype(np.float32)
    y = df["label"].values.astype(int)
    logger.info(
        f"Dataset: {len(df):,} samples  "
        f"({int(y.sum()):,} anomalous / {int((y==0).sum()):,} normal)"
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=SEED, stratify=y
    )
    logger.info(f"Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    scaler = StandardScaler()
    X_tr_sc = scaler.fit_transform(X_train).astype(np.float32)
    X_te_sc = scaler.transform(X_test).astype(np.float32)

    X_tr_normal = X_tr_sc[y_train == 0]

    # Train both models
    iso = train_isolation_forest(X_tr_normal)
    rf  = train_random_forest(X_tr_sc, y_train)

    # Evaluate
    logger.info("\nEvaluating on test set…")

    if_raw    = -iso.score_samples(X_te_sc)
    if_scores = np.clip((if_raw - 0.1) / 0.9, 0.0, 1.0)
    evaluate("Isolation Forest", y_test, if_scores)

    rf_scores = rf.predict_proba(X_te_sc)[:, 1]
    evaluate("Random Forest", y_test, rf_scores)

    # Save artifacts
    logger.info(f"\nSaving artefacts to {MODEL_DIR}/")
    joblib.dump(iso,    os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    joblib.dump(rf,     os.path.join(MODEL_DIR, "random_forest.pkl"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))

    with open(os.path.join(MODEL_DIR, "feature_names.json"), "w") as fh:
        json.dump(BEHAVIORAL_FEATURES, fh)

    logger.info("All artefacts saved.")
    logger.info("Restart the AI service to reload models:  docker-compose … restart ai")


if __name__ == "__main__":
    main()
