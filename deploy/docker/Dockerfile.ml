# ─────────────────────────────────────────────────────
#  SentinelWall ML Service — Production Docker Image
# ─────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY sentinel-ml/pyproject.toml sentinel-ml/
WORKDIR /build/sentinel-ml

RUN pip install --no-cache-dir build wheel
COPY sentinel-ml/ .
RUN python -m build --wheel

# ─────────────────────────────────────────────────────
#  Runtime
# ─────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

RUN useradd -r -s /sbin/nologin sentinel
RUN install -d -o sentinel -g sentinel /var/lib/sentinelwall/models

WORKDIR /app
COPY --from=builder /build/sentinel-ml/dist/*.whl .
RUN pip install --no-cache-dir *.whl && rm -f *.whl

EXPOSE 8766

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD python -c "import httpx; httpx.get('http://localhost:8766/health').raise_for_status()"

USER sentinel
CMD ["sentinel-ml", "--host", "0.0.0.0", "--port", "8766"]
