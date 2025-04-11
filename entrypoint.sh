#!/bin/sh
set -e

alembic upgrade head

exec uvicorn fastapi_keycloak_app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir /app/src --no-access-log