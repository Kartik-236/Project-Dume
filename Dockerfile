# ── Project DUME — Dockerfile ────────────────────────────────────────────
# Lightweight Linux image for running the MVP detection pipeline.
#
# Build:
#   docker build -t project-dume .
#
# Run (basic — container-only telemetry):
#   docker run --rm project-dume
#
# Run (host visibility — requires elevated access):
#   docker run --rm --privileged \
#       -v /proc:/host/proc:ro \
#       -v /var/log:/host/log:ro \
#       project-dume
#
# NOTE: Without --privileged and bind mounts, collectors will only see
# container-scoped data.  The pipeline runs gracefully either way.
# ─────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

# Install lightweight Linux utilities used by collectors
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps \
        kmod \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source
COPY . .

# Default: run a single detection cycle with verbose output
CMD ["python", "main.py", "--run-once", "--verbose"]
