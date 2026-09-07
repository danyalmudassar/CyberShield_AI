# Python 3.12 / Debian bookworm; refresh this digest deliberately with verification.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
FROM ${PYTHON_IMAGE} AS dependencies
WORKDIR /build
COPY requirements-runtime.txt ./
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements-runtime.txt \
 && /opt/venv/bin/pip check

FROM ${PYTHON_IMAGE} AS runtime
ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CYBERSHIELD_DB=/app/data/scans.sqlite3 CYBERSHIELD_AUTH_DB=/app/data/auth.sqlite3 \
    CYBERSHIELD_DEMO_ONLY=true CYBERSHIELD_MP_METHOD=spawn
RUN groupadd --gid 10001 cybershield \
 && useradd --uid 10001 --gid 10001 --no-create-home cybershield \
 && mkdir -p /app/data /app/reports /app/backups \
 && chown -R 10001:10001 /app
WORKDIR /app
COPY --from=dependencies /opt/venv /opt/venv
COPY --chown=10001:10001 models.py server.py ./
COPY --chown=10001:10001 agents/ ./agents/
COPY --chown=10001:10001 utils/ ./utils/
COPY --chown=10001:10001 services/ ./services/
COPY --chown=10001:10001 mocks/ ./mocks/
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/ready', timeout=2).read()"]
CMD ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-proxy-headers", "--no-access-log"]
