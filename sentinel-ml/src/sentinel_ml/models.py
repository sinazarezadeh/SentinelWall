"""Pydantic models for the ML API."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field
from enum import Enum


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConnectionFeatures(BaseModel):
    """Features extracted from a connection for ML scoring."""

    ip: str = Field(..., description="Source IP address")
    connections_per_second: float = Field(0.0, ge=0.0)
    bytes_per_second: float = Field(0.0, ge=0.0)
    packets_per_second: float = Field(0.0, ge=0.0)
    unique_ports: int = Field(0, ge=0)
    failed_auths: int = Field(0, ge=0)
    protocol_tcp_ratio: float = Field(0.5, ge=0.0, le=1.0)
    protocol_udp_ratio: float = Field(0.5, ge=0.0, le=1.0)
    avg_packet_size: float = Field(64.0, ge=0.0)
    connection_duration_secs: float = Field(1.0, ge=0.0)
    syn_ratio: float = Field(0.5, ge=0.0, le=1.0)
    rst_ratio: float = Field(0.0, ge=0.0, le=1.0)
    new_connections_per_min: float = Field(0.0, ge=0.0)
    hour_of_day: int = Field(12, ge=0, le=23)
    day_of_week: int = Field(1, ge=0, le=6)


class ScoringRequest(BaseModel):
    """Request to score a connection for threat probability."""

    features: ConnectionFeatures
    context: dict[str, Any] = Field(default_factory=dict)


class ScoringResponse(BaseModel):
    """ML threat scoring response."""

    ip: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    severity: ThreatSeverity
    threat_probability: float = Field(..., ge=0.0, le=1.0)
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    predicted_threat_type: str | None
    confidence: float = Field(..., ge=0.0, le=1.0)
    features_used: list[str]
    model_version: str
    explanation: dict[str, float]


class TrainingData(BaseModel):
    """Training data for model updates."""

    features: list[ConnectionFeatures]
    labels: list[int]  # 0=benign, 1=threat


class ModelInfo(BaseModel):
    """Information about loaded models."""

    version: str
    trained_at: str | None
    accuracy: float | None
    precision: float | None
    recall: float | None
    f1_score: float | None
    samples_trained: int
    features: list[str]
    status: str


class AnomalyDetectionResult(BaseModel):
    """Result from anomaly detection."""

    ip: str
    is_anomaly: bool
    anomaly_score: float
    z_score: float
    baseline_mean: float
    baseline_std: float
    observed_value: float
    feature_name: str
