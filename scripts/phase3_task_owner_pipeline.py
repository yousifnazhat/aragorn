"""Four reviewed task-owner stages; keep the full legacy registry and its fingerprints intact."""
from scripts import phase3_pipeline


if __name__ == "__main__":
    phase3_pipeline.REGISTRY = "benchmark/phase3-task-owner-pipeline-v1.json"
    raise SystemExit(phase3_pipeline.main())
