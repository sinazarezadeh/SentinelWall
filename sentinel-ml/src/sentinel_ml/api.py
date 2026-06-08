"""FastAPI application for SentinelWall ML service."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

from .models import (
    ConnectionFeatures, ScoringRequest, ScoringResponse,
    TrainingData, ModelInfo, AnomalyDetectionResult
)
from .scoring import RiskScorer
from .anomaly import FEATURE_NAMES

logger = logging.getLogger(__name__)

# Prometheus metrics
SCORING_REQUESTS = Counter("sentinel_ml_scoring_requests_total", "Total scoring requests")
SCORING_ERRORS = Counter("sentinel_ml_scoring_errors_total", "Total scoring errors")
SCORING_LATENCY = Histogram("sentinel_ml_scoring_latency_seconds", "Scoring latency")
HIGH_RISK_DETECTIONS = Counter("sentinel_ml_high_risk_detections_total", "High-risk detections")
ACTIVE_BASELINES = Gauge("sentinel_ml_active_baselines", "Number of IP baselines tracked")

MODEL_PATH = Path("/var/lib/sentinelwall/models")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: load models on startup."""
    scorer = get_scorer()
    scorer.iso_forest.load(MODEL_PATH)
    scorer.classifier.load(MODEL_PATH)
    logger.info("SentinelWall ML service started")
    yield
    scorer.iso_forest.save(MODEL_PATH)
    scorer.classifier.save(MODEL_PATH)
    logger.info("SentinelWall ML service stopped, models saved")


app = FastAPI(
    title="SentinelWall ML Service",
    description="AI/ML anomaly detection and threat classification for SentinelWall",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8765", "http://127.0.0.1:8765"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Singleton scorer
_scorer: RiskScorer | None = None


def get_scorer() -> RiskScorer:
    global _scorer
    if _scorer is None:
        _scorer = RiskScorer()
    return _scorer


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "sentinel-ml", "version": "0.1.0"}


@app.post("/score", response_model=ScoringResponse)
async def score_connection(
    request: ScoringRequest,
    scorer: RiskScorer = Depends(get_scorer),
) -> ScoringResponse:
    """Score a single connection for threat probability."""
    SCORING_REQUESTS.inc()
    start = time.time()

    try:
        result = scorer.score(request.features)

        if result.risk_score >= 0.65:
            HIGH_RISK_DETECTIONS.inc()

        ACTIVE_BASELINES.set(scorer.stat_detector.ip_count())

        return result

    except Exception as e:
        SCORING_ERRORS.inc()
        logger.error(f"Scoring error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scoring failed: {e}"
        )
    finally:
        SCORING_LATENCY.observe(time.time() - start)


@app.post("/score/batch", response_model=list[ScoringResponse])
async def score_batch(
    features_list: list[ScoringRequest],
    scorer: RiskScorer = Depends(get_scorer),
) -> list[ScoringResponse]:
    """Score multiple connections in a single request."""
    if len(features_list) > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch size limited to 1000"
        )
    return scorer.batch_score([r.features for r in features_list])


@app.post("/train")
async def train_models(
    data: TrainingData,
    scorer: RiskScorer = Depends(get_scorer),
) -> dict:
    """Trigger model retraining with provided labeled data."""
    import numpy as np
    from .scoring import features_to_dict

    if len(data.features) != len(data.labels):
        raise HTTPException(
            status_code=400,
            detail="features and labels must have the same length"
        )

    X = np.array([
        [features_to_dict(f).get(feat, 0.0) for feat in FEATURE_NAMES]
        for f in data.features
    ])
    y = np.array(data.labels)

    metrics = scorer.classifier.train(X, y)
    scorer.classifier.save(MODEL_PATH)

    return {"success": True, "metrics": metrics}


@app.post("/train/unsupervised")
async def train_unsupervised(
    scorer: RiskScorer = Depends(get_scorer),
) -> dict:
    """Trigger Isolation Forest retraining from buffered samples."""
    result = scorer.iso_forest.train()
    scorer.iso_forest.save(MODEL_PATH)
    return {"success": True, "result": result}


@app.get("/models/info", response_model=list[ModelInfo])
async def get_model_info(
    scorer: RiskScorer = Depends(get_scorer),
) -> list[ModelInfo]:
    """Get information about loaded models."""
    from datetime import datetime

    models = []

    iso_trained = scorer.iso_forest._trained
    models.append(ModelInfo(
        version=scorer.iso_forest.model_version,
        trained_at=datetime.utcnow().isoformat() if iso_trained else None,
        accuracy=None,
        precision=None,
        recall=None,
        f1_score=None,
        samples_trained=len(scorer.iso_forest._training_buffer),
        features=FEATURE_NAMES,
        status="ready" if iso_trained else "untrained",
    ))

    clf_trained = scorer.classifier._trained
    clf_metrics = scorer.classifier.metrics
    models.append(ModelInfo(
        version=scorer.classifier.model_version,
        trained_at=datetime.utcnow().isoformat() if clf_trained else None,
        accuracy=clf_metrics.get("accuracy"),
        precision=clf_metrics.get("precision"),
        recall=clf_metrics.get("recall"),
        f1_score=clf_metrics.get("f1"),
        samples_trained=int(clf_metrics.get("samples", 0)),
        features=FEATURE_NAMES,
        status="ready" if clf_trained else "untrained",
    ))

    return models


@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics() -> str:
    """Expose Prometheus metrics."""
    return generate_latest().decode("utf-8")


@app.get("/features")
async def get_features() -> dict:
    """Get the list of features used by ML models."""
    return {"features": FEATURE_NAMES, "count": len(FEATURE_NAMES)}
