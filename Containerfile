## ------------------------------- Builder Stage ------------------------------ ## 
FROM python:3.13-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apk add --no-cache \
    build-base \
    bash \
    curl

# Download the latest installer, install it and then remove it
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && chmod +x /root/.local/bin/uv

# Set up the UV environment path correctly
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

COPY ./pyproject.toml .

RUN uv sync

## ------------------------------- Production Stage ------------------------------ ##
FROM python:3.13-alpine AS production

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH=/app/src

RUN adduser -D appuser
USER appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appuser /app/.venv .venv
COPY alembic.ini .
COPY alembic ./alembic
COPY --chown=appuser:appuser entrypoint.sh .
COPY --chown=appuser:appuser src ./src

RUN chmod +x entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]