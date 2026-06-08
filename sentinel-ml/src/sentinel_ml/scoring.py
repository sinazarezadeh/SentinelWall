"""Composite risk scoring combining statistical and ML signals."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from .models import ConnectionFeatures, ScoringResponse, ThreatSeverity
from .anomaly import StatisticalAnomalyDetector, IsolationForestDetector, FEATURE_NAMES
from .classifier import ThreatClassifier

logger = logging.getLogger(__name__)

# Scoring weights
WEIGHTS = {
    "statistical_anomaly": 0.30,
    "isolation_forest": 0.35,
    "classifier": 0.35,
}

# Score thresholds
SEVERITY_THRESHOLDS = {
    ThreatSeverity.CRITICAL: 0.85,
    ThreatSeverity.HIGH: 0.65,
    ThreatSeverity.MEDIUM: 0.40,
    ThreatSeverity.LOW: 0.20,
}


def features_to_dict(f: ConnectionFeatures) -> dict[str, float]:
    return {
        "connections_per_second": f.connections_per_second,
        "bytes_per_second": f.bytes_per_second,
        "packets_per_second": f.packets_per_second,
        "unique_ports": float(f.unique_ports),
        "failed_auths": float(f.failed_auths),
        "protocol_tcp_ratio": f.protocol_tcp_ratio,
        "protocol_udp_ratio": f.protocol_udp_ratio,
        "avg_packet_size": f.avg_packet_size,
        "connection_duration_secs": f.connection_duration_secs,
        "syn_ratio": f.syn_ratio,
        "rst_ratio": f.rst_ratio,
        "new_connections_per_min": f.new_connections_per_min,
        "hour_of_day": float(f.hour_of_day),
        "day_of_week": float(f.day_of_week),
    }


class RiskScorer:
    """Composite risk scorer combining multiple signals."""

    MODEL_VERSION = "0.1.0"

    def __init__(self) -> None:
        self.stat_detector = StatisticalAnomalyDetector()
        self.iso_forest = IsolationForestDetector(contamination=0.05)
        self.classifier = ThreatClassifier()

    def score(self, features: ConnectionFeatures) -> ScoringResponse:
        """Compute composite risk score for a connection."""
        feat_dict = features_to_dict(features)

        # 1. Statistical anomaly detection
        stat_anomalies = self.stat_detector.check(features.ip, feat_dict)
        stat_score = min(len(stat_anomalies) * 0.2, 1.0) if stat_anomalies else 0.0
        max_z = max((z for _, z in stat_anomalies.values()), default=0.0)
        stat_anomaly_score = min(max_z / 10.0, 1.0)

        # 2. Isolation Forest
        iso_is_anomaly, iso_score = self.iso_forest.predict(feat_dict)

        # 3. ML classifier
        threat_class, class_confidence, class_probs = self.classifier.predict(feat_dict)
        is_threat_class = threat_class != "benign" and threat_class != "unknown"
        classifier_score = class_confidence if is_threat_class else 0.0

        # Update baseline with this sample
        self.stat_detector.update(features.ip, feat_dict)
        self.iso_forest.add_sample(feat_dict)

        # Composite risk score
        risk_score = (
            WEIGHTS["statistical_anomaly"] * stat_anomaly_score
            + WEIGHTS["isolation_forest"] * iso_score
            + WEIGHTS["classifier"] * classifier_score
        )
        risk_score = min(max(risk_score, 0.0), 1.0)

        # Determine severity
        severity = ThreatSeverity.LOW
        for sev, threshold in sorted(SEVERITY_THRESHOLDS.items(), key=lambda x: x[1], reverse=True):
            if risk_score >= threshold:
                severity = sev
                break

        # Confidence (based on how much data we have)
        ip_sample_count = self.stat_detector._ip_baselines.get(features.ip, {})
        has_baseline = any(
            b.count >= 30 for b in ip_sample_count.values()
        ) if ip_sample_count else False
        confidence = 0.9 if (has_baseline and self.iso_forest._trained) else 0.5

        # Build explanation
        explanation = {
            "statistical_anomaly_score": stat_anomaly_score,
            "isolation_forest_score": iso_score,
            "classifier_score": classifier_score,
            "risk_score": risk_score,
            "statistical_features_flagged": float(len(stat_anomalies)),
            **{f"class_{k}": v for k, v in list(class_probs.items())[:5]},
        }

        return ScoringResponse(
            ip=features.ip,
            risk_score=risk_score,
            severity=severity,
            threat_probability=risk_score,
            anomaly_score=(stat_anomaly_score + iso_score) / 2.0,
            predicted_threat_type=threat_class if is_threat_class else None,
            confidence=confidence,
            features_used=list(stat_anomalies.keys()) + (["isolation_forest"] if iso_is_anomaly else []),
            model_version=self.MODEL_VERSION,
            explanation=explanation,
        )

    def batch_score(self, features_list: list[ConnectionFeatures]) -> list[ScoringResponse]:
        return [self.score(f) for f in features_list]
