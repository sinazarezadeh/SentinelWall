"""Traffic threat classifier using Random Forest."""

from __future__ import annotations

import logging
import numpy as np
from pathlib import Path
from typing import Optional
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib

from .anomaly import FEATURE_NAMES

logger = logging.getLogger(__name__)

THREAT_CLASSES = [
    "benign",
    "brute_force",
    "port_scan",
    "syn_flood",
    "udp_flood",
    "http_flood",
    "slowloris",
    "ddos",
]


class ThreatClassifier:
    """Multi-class threat type classifier."""

    def __init__(self) -> None:
        self.model: Optional[RandomForestClassifier] = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(THREAT_CLASSES)
        self._trained = False
        self.metrics: dict[str, float] = {}
        self.model_version = "0.0.0"

    def train(self, X: np.ndarray, y: np.ndarray) -> dict[str, float]:
        """Train the threat classifier."""
        if len(X) < 50:
            return {"error": "Need at least 50 samples to train"}

        logger.info(f"Training threat classifier on {len(X)} samples")

        X_scaled = self.scaler.fit_transform(X)
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_train, y_train)
        self._trained = True

        y_pred = self.model.predict(X_test)
        self.metrics = {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision": float(precision_score(y_test, y_pred, average="weighted", zero_division=0)),
            "recall": float(recall_score(y_test, y_pred, average="weighted", zero_division=0)),
            "f1": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
            "samples": float(len(X)),
        }

        logger.info(f"Classifier metrics: {self.metrics}")
        return self.metrics

    def predict(self, features: dict[str, float]) -> tuple[str, float, dict[str, float]]:
        """Predict threat type and return (class, confidence, class_probs)."""
        if not self._trained or self.model is None:
            return "unknown", 0.0, {}

        row = np.array([[features.get(f, 0.0) for f in FEATURE_NAMES]])
        row_scaled = self.scaler.transform(row)

        pred_idx = self.model.predict(row_scaled)[0]
        probs = self.model.predict_proba(row_scaled)[0]

        class_name = THREAT_CLASSES[pred_idx] if pred_idx < len(THREAT_CLASSES) else "unknown"
        confidence = float(probs[pred_idx])

        class_probs = {
            THREAT_CLASSES[i]: float(p)
            for i, p in enumerate(probs)
            if i < len(THREAT_CLASSES)
        }

        return class_name, confidence, class_probs

    def get_feature_importance(self) -> dict[str, float]:
        """Get feature importance scores."""
        if not self._trained or self.model is None:
            return {}
        importances = self.model.feature_importances_
        return {f: float(imp) for f, imp in zip(FEATURE_NAMES, importances)}

    def save(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        if self.model:
            joblib.dump(self.model, path / "classifier.joblib")
        joblib.dump(self.scaler, path / "classifier_scaler.joblib")

    def load(self, path: Path) -> bool:
        try:
            model_path = path / "classifier.joblib"
            scaler_path = path / "classifier_scaler.joblib"
            if model_path.exists() and scaler_path.exists():
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self._trained = True
                return True
        except Exception as e:
            logger.error(f"Failed to load classifier: {e}")
        return False
