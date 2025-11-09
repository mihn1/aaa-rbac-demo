from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

if __package__ is None or __package__ == "":
    from config import settings  # type: ignore[no-redef]
    from db import init_db  # type: ignore[no-redef]
    from audit_logging import LoggingMiddleware  # type: ignore[no-redef]
    from routers import admin, auth, home, logs  # type: ignore[no-redef]
else:
    from .config import settings
    from .db import init_db
    from .audit_logging import LoggingMiddleware
    from .routers import admin, auth, home, logs

static_dir = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(LoggingMiddleware)

    app.include_router(auth.router, prefix="/auth", tags=["auth"])
    app.include_router(admin.router, prefix="/admin", tags=["admin"])
    app.include_router(home.router, tags=["home"])
    app.include_router(logs.router, prefix="/logs", tags=["logs"])

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):  # noqa: D401
        """Redirect HTML clients to login on auth errors, fall back to JSON otherwise."""

        if exc.status_code in {status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN}:
            accept = (request.headers.get("accept") or "").lower()
            if "text/html" in accept:
                response = RedirectResponse(
                    url="/auth/login-ui",
                    status_code=status.HTTP_303_SEE_OTHER,
                )
                if exc.status_code == status.HTTP_401_UNAUTHORIZED:
                    response.delete_cookie("access_token", path="/")
                    response.delete_cookie("refresh_token", path="/")
                return response

        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.get("/")
    async def root(request: Request) -> RedirectResponse:
        target = "/home" if request.cookies.get("access_token") else "/auth/login-ui"
        return RedirectResponse(url=target)

    @app.get("/healthz")
    async def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
