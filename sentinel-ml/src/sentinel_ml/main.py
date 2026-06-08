"""Entry point for the SentinelWall ML service."""

from __future__ import annotations

import argparse
import logging
import sys
import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel-ml",
        description="SentinelWall ML Service — Anomaly detection and threat classification",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8766, help="Port")
    parser.add_argument("--workers", type=int, default=1, help="Worker processes")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    print(f"SentinelWall ML Service v0.1.0")
    print(f"Listening on http://{args.host}:{args.port}")

    uvicorn.run(
        "sentinel_ml.api:app",
        host=args.host,
        port=args.port,
        workers=args.workers if not args.reload else 1,
        log_level=args.log_level,
        reload=args.reload,
        access_log=True,
    )


if __name__ == "__main__":
    main()
