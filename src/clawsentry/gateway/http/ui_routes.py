"""Static UI route registration for the gateway HTTP app."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from starlette.responses import FileResponse, HTMLResponse


def register_ui_routes(app: FastAPI, ui_dir: Path) -> None:
    """Register unauthenticated SPA static routes under /ui."""
    if ui_dir.exists() and (ui_dir / "index.html").exists():
        index_html = (ui_dir / "index.html").read_text()

        @app.get("/ui/{path:path}")
        async def ui_spa_fallback(path: str):
            """SPA fallback: serve index.html for unmatched /ui/* paths."""
            # Check if requested path is a real file
            file_path = ui_dir / path
            if file_path.is_file() and file_path.resolve().is_relative_to(
                ui_dir.resolve()
            ):
                return FileResponse(str(file_path))
            return HTMLResponse(index_html)

        @app.get("/ui")
        async def ui_root():
            return HTMLResponse(index_html)
