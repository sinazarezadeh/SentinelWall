"""Anomaly detection using Isolation Forest and statistical methods."""

from __future__ import annotations

import logging
import numpy as np
import pandas as pd
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "connections_per_second",
    "bytes_per_second",
    "packets_per_second",
    "unique_ports",
    "failed_auths",
    "protocol_tcp_ratio",
    "protocol_udp_ratio",
    "avg_packet_size",
    "connection_duration_secs",
    "syn_ratio",
    "rst_ratio",
    "new_connections_per_min",
    "hour_of_day",
    "day_of_week",
]

SIGMA_THRESHOLD = 3.0
MIN_SAMPLES_FOR_DETECTION = 30
BASELINE_WINDOW = 1000


@dataclass
class PerIpBaseline:
    """Rolling baseline statistics for a single IP."""

    samples: deque = field(default_factory=lambda: deque(maxlen=BASELINE_WINDOW))
    mean: float = 0.0
    std: float = 0.0
    count: int = 0

    def update(self, value: float) -> None:
        self.samples.append(value)
        self.count += 1
        if len(self.samples) >= 5:
            arr = np.array(list(self.samples))
            self.mean = float(arr.mean())
            self.std = float(arr.std())

    def is_anomaly(self, value: float) -> tuple[bool, float]:
        """Returns (is_anomaly, z_score)."""
        if self.std < 1e-9 or self.count < MIN_SAMPLES_FOR_DETECTION:
            return False, 0.0
        z = abs(value - self.mean) / self.std
        return z > SIGMA_THRESHOLD, z


class StatisticalAnomalyDetector:
    """Per-IP statistical baseline anomaly detector."""

    def __init__(self) -> None:
        self._ip_baselines: dict[str, dict[str, PerIpBaseline]] = {}
        self._global: dict[str, PerIpBaseline] = {f: PerIpBaseline() for f in FEATURE_NAMES}

    def update(self, ip: str, features: dict[str, float]) -> None:
        if ip not in self._ip_baselines:
            self._ip_baselines[ip] = {f: PerIpBaseline() for f in FEATURE_NAMES}

        for feature, value in features.items():
            if feature in FEATURE_NAMES:
                self._ip_baselines[ip][feature].update(value)
                self._global[feature].update(value)

    def check(self, ip: str, features: dict[str, float]) -> dict[str, tuple[bool, float]]:
        """Check each feature for anomalies. Returns {feature: (is_anomaly, z_score)}."""
        results: dict[str, tuple[bool, float]] = {}

        if ip not in self._ip_baselines:
            return results

        for feature, value in features.items():
            if feature in self._ip_baselines.get(ip, {}):
                baseline = self._ip_baselines[ip][feature]
                is_anom, z = baseline.is_anomaly(value)
                if is_anom:
                    results[feature] = (True, z)

        return results

    def get_baseline(self, ip: str, feature: str) -> Optional[PerIpBaseline]:
        return self._ip_baselines.get(ip, {}).get(feature)

    def ip_count(self) -> int:
        return len(self._ip_baselines)


class IsolationForestDetector:
    """Unsupervised anomaly detection using Isolation Forest."""

    def __init__(self, contamination: float = 0.05) -> None:
        self.contamination = contamination
        self.model: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        self._training_buffer: list[list[float]] = []
        self._min_training_samples = 100
        self._trained = False
        self.model_version = "0.0.0"

    def add_sample(self, features: dict[str, float]) -> None:
        """Add a sample to the training buffer."""
        row = [features.get(f, 0.0) for f in FEATURE_NAMES]
        self._training_buffer.append(row)

        # Auto-retrain when buffer is full
        if len(self._training_buffer) >= 1000:
            self.train()

    def train(self, X: Optional[np.ndarray] = None) -> dict[str, float]:
        """Train or retrain the Isolation Forest model."""
        if X is None:
            if len(self._training_buffer) < self._min_training_samples:
                return {"error": f"Need at least {self._min_training_samples} samples"}
            X = np.array(self._training_buffer)
            self._training_buffer.clear()

        logger.info(f"Training Isolation Forest on {len(X)} samples")
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self._trained = True

        from datetime import datetime
        import hashlib
        self.model_version = hashlib.md5(
            f"{len(X)}{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:8]

        logger.info(f"Isolation Forest trained (version={self.model_version})")
        return {"samples": len(X), "version": self.model_version}

    def predict(self, features: dict[str, float]) -> tuple[bool, float]:
        """Predict if a sample is anomalous. Returns (is_anomaly, anomaly_score)."""
        if not self._trained or self.model is None:
            return False, 0.0

        row = np.array([[features.get(f, 0.0) for f in FEATURE_NAMES]])
        row_scaled = self.scaler.transform(row)

        prediction = self.model.predict(row_scaled)[0]
        score = -self.model.score_samples(row_scaled)[0]

        # IsolationForest: -1=anomaly, 1=normal
        is_anomaly = prediction == -1
        # Normalize score to [0, 1]
        anomaly_score = min(max((score - 0.3) / 0.7, 0.0), 1.0)

        return is_anomaly, anomaly_score

    def save(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        if self.model:
            joblib.dump(self.model, path / "isolation_forest.joblib")
        joblib.dump(self.scaler, path / "scaler.joblib")
        logger.info(f"Models saved to {path}")

    def load(self, path: Path) -> bool:
        try:
            model_path = path / "isolation_forest.joblib"
            scaler_path = path / "scaler.joblib"
            if model_path.exists() and scaler_path.exists():
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self._trained = True
                logger.info(f"Models loaded from {path}")
                return True
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
        return False
