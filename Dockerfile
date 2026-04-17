# ── Project DUME — Dockerfile (Phase 2) ──────────────────────────────────
#
# Build:
#   docker build -t project-dume .
#
# Run standalone (SQLite fallback):
#   docker run --rm -p 8000:8000 project-dume
#
# Recommended: use docker-compose for PostgreSQL + web mode
#   docker compose up --build
# ─────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

# Install lightweight Linux utilities used by collectors
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps \
        kmod \
        util-linux \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source
COPY . .

# Ensure runtime directories exist
RUN mkdir -p baseline reporting/output storage

EXPOSE 8000

# Default: start the web dashboard
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
