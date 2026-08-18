"""FastAPI application factory."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api import auth, discovery, health, oauth
from app.config.settings import settings
from app.db.session import init_db
from app.models.schemas import ErrorResponse


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Initializes the database, registers routers, and configures middleware.

    When URL_PREFIX is set (e.g. "/oauth_issuer"), all routes are mounted under
    that prefix so the provider is reachable at {prefix}/login, {prefix}/oauth/…
    etc.  When URL_PREFIX is empty (default) routes are mounted at the root, so
    no existing deployments are affected.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="Identity Provider",
        description="OpenID Connect Compatible Identity Provider",
        version="1.0.0",
        root_path=settings.prefix,
    )

    @app.get("/")
    async def root() -> RedirectResponse:
        """Redirect bare-root requests to the login page."""
        return RedirectResponse(url="/login", status_code=302)

    if settings.prefix:
        # Also handle GET {prefix}/ so browsers that land on the prefixed root
        # are redirected cleanly instead of receiving a 404.
        @app.get(settings.prefix + "/")
        async def prefixed_root() -> RedirectResponse:
            return RedirectResponse(url="/login", status_code=302)

    # CORS middleware (allow all origins for development)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Custom exception handler for missing OAuth query parameters
    @app.exception_handler(RequestValidationError)
    async def oauth_validation_exception_handler(request, exc):
        """Handle validation errors on OAuth endpoints with proper error responses.
        
        Returns OAuth-compliant error JSON for missing required parameters.
        """
        # Build list of missing fields
        missing_fields = []
        for error in exc.errors():
            if error["type"] == "missing" and error["loc"][0] == "query":
                missing_fields.append(error["loc"][1])
        
        if missing_fields:
            error_msg = f"Missing required parameters: {', '.join(missing_fields)}"
            oauth_error = ErrorResponse(
                error="invalid_request",
                error_description=error_msg
            )
            return JSONResponse(
                status_code=400,
                content=oauth_error.model_dump()
            )
        
        # For non-OAuth validation errors, return the standard Pydantic response
        return JSONResponse(
            status_code=422,
            content={"detail": exc.errors()}
        )

    # Initialize database on first request
    @app.on_event("startup")
    async def startup():
        try:
            init_db()
        except Exception:
            # DB might not be available in test environments
            pass

    # Serve static assets (logo, etc.)
    static_dir = Path(__file__).parent / "static"
    static_dir.mkdir(exist_ok=True)
    app.mount( settings.prefix + "/static", StaticFiles(directory=str(static_dir)), name="static")

    # Register routers
    app.include_router(health.router, prefix=settings.prefix)
    app.include_router(discovery.router, prefix=settings.prefix)
    app.include_router(auth.router, prefix=settings.prefix)
    app.include_router(oauth.router, prefix=settings.prefix)

    return app


# Create the application instance
app = create_app()
