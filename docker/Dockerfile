# syntax=docker/dockerfile:1.7
#
# NexusFlow AI platform image: one image, several roles (api, internal api,
# pipeline / integrations / sandbox workers, beat, migrations) selected by the
# command in docker-compose.yml.
#
# * dependencies come from uv.lock (hash-verified), no build tools at runtime;
# * runs as an unprivileged user with a read-only root filesystem;
# * pip / setuptools are removed from the runtime virtualenv.
# Pin base images by digest in production (Dependabot keeps them fresh).

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.18@sha256:3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------- builder
FROM ${PYTHON_IMAGE} AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /build

# Dependencies first (cached layer), strictly from the lock file.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable \
 && { /opt/venv/bin/python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true; }

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="nexusflow-ai" \
      org.opencontainers.image.description="NexusFlow AI - automation & intelligence platform" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 nexusflow \
 && useradd --system --uid 10001 --gid nexusflow --home-dir /nonexistent --shell /usr/sbin/nologin nexusflow \
 && { python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true; }

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    NEXUSFLOW_STORAGE__ROOT=/var/lib/nexusflow

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root alembic.ini ./
COPY --chown=root:root migrations ./migrations
COPY --chown=root:root docker/healthcheck.py /usr/local/bin/nexusflow-healthcheck

# /var/tmp/nexusflow: the API spools multipart uploads there (TMPDIR), on a
# volume that takes this owner when Docker first creates it.
RUN mkdir -p /var/lib/nexusflow /var/tmp/nexusflow \
 && chown nexusflow:nexusflow /var/lib/nexusflow /var/tmp/nexusflow \
 && chmod 0750 /var/lib/nexusflow /var/tmp/nexusflow

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "/usr/local/bin/nexusflow-healthcheck"]

# Default role: public API. Other roles override the command. Proxy headers are
# NOT processed by uvicorn: the application trusts X-Forwarded-For only from the
# configured proxy networks (NEXUSFLOW_APP__TRUSTED_PROXIES), in one place.
CMD ["uvicorn", "nexusflow.apps.api.main:create_public_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", \
     "--no-server-header", "--timeout-graceful-shutdown", "20", "--limit-concurrency", "1000"]
