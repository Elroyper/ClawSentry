# ClawSentry Gateway — multi-stage production image
# Usage: docker build -t clawsentry -f docker/Dockerfile .

# ---- builder stage ----
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml ./
COPY src/ src/
COPY CHANGELOG.md LICENSE README_PUBLIC.md ./

RUN pip install --no-cache-dir --prefix=/install ".[metrics]"

# ---- runtime stage ----
FROM python:3.12-slim AS runtime

# Non-root user
RUN groupadd -r clawsentry && useradd -r -g clawsentry -m clawsentry

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Data directory for SQLite trajectory DB
RUN mkdir -p /data && chown clawsentry:clawsentry /data
VOLUME ["/data"]

# Default environment
ENV CS_HTTP_HOST=0.0.0.0 \
    CS_HTTP_PORT=8080 \
    CS_TRAJECTORY_DB_PATH=/data/clawsentry-trajectory.db

EXPOSE 8080

USER clawsentry
WORKDIR /home/clawsentry

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

ENTRYPOINT ["clawsentry-gateway"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
