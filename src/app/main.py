import time
from contextlib import asynccontextmanager
from contextvars import ContextVar

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.sessions import SessionMiddleware

from app.auth.routers import router as auth_router
from app.core.config import settings
from app.users.routers import router as user_router
from src.app.core.logging import Logger, configure_logging, generate_correlation_id, get_logger

configure_logging()

logger: Logger = get_logger(__name__)
access_log = get_logger("api.access")

request_id_context: ContextVar[str | None] = ContextVar("request_id", default=None)


class RequestContextLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Get or generate request ID
        request_id = request.headers.get("X-Request-ID", generate_correlation_id())

        # Set request ID in context var
        request_id_token = request_id_context.set(request_id)

        # Bind request ID and other request details to structlog context
        # These will be automatically included in logs within this request context
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else "unknown",
        )

        start_time = time.monotonic()
        response = None
        try:
            # Log request start
            await logger.ainfo("Request started")  # Use await for async logging

            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id  # Add request ID to response header

        except Exception as e:
            # Log unhandled exceptions during request processing
            await logger.aexception("Unhandled exception during request processing")  # aexception logs traceback
            # Re-raise the exception so FastAPI's exception handlers can process it
            # Or return a generic error response here if you prefer
            # response = JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
            raise e  # Re-raise is generally better to let handlers work
        finally:
            process_time = (time.monotonic() - start_time) * 1000  # ms
            status_code = response.status_code if response else 500

            # Bind status code and process time before logging request end
            structlog.contextvars.bind_contextvars(
                status_code=status_code,
                process_time_ms=round(process_time, 2),
            )
            if 400 <= status_code < 500:
                await logger.awarning("Request completed (Client Error)")
            elif status_code >= 500:
                await logger.aerror("Request completed (Server Error)")
            else:
                await logger.ainfo("Request completed")

            # Clean up context variables
            structlog.contextvars.clear_contextvars()
            request_id_context.reset(request_id_token)

        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Code here runs on startup
    logger.info("Application starting up...")
    yield
    # Code here runs on shutdown
    logger.info("Application shutting down...")


app = FastAPI(
    lifespan=lifespan,
    title=settings.APP_NAME,
    version=settings.API_VERSION,
    swagger_ui_init_oauth={
        "clientId": settings.KEYCLOAK_CLIENT_ID,
        "clientSecret": None,
        "realm": settings.KEYCLOAK_REALM,
        "appName": settings.APP_NAME,
        "usePkceWithAuthorizationCodeGrant": True,
        "scopes": "openid profile email",  # Common scopes
    },
    swagger_ui_oauth2_redirect_url="/api/docs/oauth2-redirect",  # Explicit redirect URL
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Add CORS middleware
if settings.ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.ALLOWED_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    logger.warning("CORS disabled. No origins allowed.")


# Add session middleware (Needed for Swagger UI OAuth state handling)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET_KEY,
    https_only=True,  # Set True if served over HTTPS
    # max_age=3600,  # Session cookie lifetime (optional)
)

app.add_middleware(RequestContextLogMiddleware)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Use await logger.aexception for async context
    await logger.aexception(  # aexception logs with ERROR level and includes traceback
        "Unhandled application error",
        # exc_info=exc # No need for exc_info=exc, aexception handles it
    )
    return JSONResponse(
        status_code=500,
        content={
            "message": "An unexpected error occurred.",
            "request_id": request_id_context.get() or "N/A",  # Get request_id from context
        },
    )


app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(user_router, prefix="/users", tags=["users"])
