## ------------------------------- Builder Stage ------------------------------ ## 
FROM python:3.13-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install --no-install-recommends -y \
    build-essential \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Download the latest installer, install it and then remove it
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && chmod +x /root/.local/bin/uv

# Set up the UV environment path correctly
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

COPY ./pyproject.toml .

RUN uv sync

## ------------------------------- Production Stage ------------------------------ ##
FROM python:3.13-slim-bookworm AS production

RUN useradd -m appuser
USER appuser

WORKDIR /app

COPY --chown=appuser:appuser src ./src
COPY --from=builder --chown=appuser:appuser /app/.venv .venv

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH=/app/src

EXPOSE 8000
