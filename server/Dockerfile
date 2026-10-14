# ds-credential-issuer — multi-stage image.
#
# KERIpy needs libsodium at runtime (via pysodium / ctypes). Debian slim
# carries it; we don't need to build from source.

FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=1.8.3 \
    POETRY_VIRTUALENVS_CREATE=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libsodium23 \
        libsodium-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install "poetry==${POETRY_VERSION}"

WORKDIR /build
COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-root --without dev,test

COPY app ./app

# ---------------------------------------------------------------------------

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libsodium23 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 1000 --home-dir /app --shell /usr/sbin/nologin dsiss

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=builder /build/app /app

# KERI habery LMDB lives here — mount a PVC in-cluster.
RUN mkdir -p /var/lib/ds-credential-issuer /var/lib/ds-credential-issuer/keystore \
    && chown -R dsiss:dsiss /app /var/lib/ds-credential-issuer

USER dsiss
WORKDIR /app
EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
