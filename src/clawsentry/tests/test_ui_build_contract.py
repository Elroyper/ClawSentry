"""Static contract tests for UI entry assets and build splitting."""

from __future__ import annotations

from pathlib import Path


UI_ROOT = Path(__file__).resolve().parents[1] / "ui"


def test_index_html_declares_svg_favicon() -> None:
    source = (UI_ROOT / "index.html").read_text(encoding="utf-8")

    assert 'rel="icon"' in source
    assert "favicon.svg" in source


def test_favicon_asset_exists() -> None:
    favicon = UI_ROOT / "public" / "favicon.svg"

    assert favicon.exists()
    assert "<svg" in favicon.read_text(encoding="utf-8")


def test_vite_build_splits_heavy_vendor_chunks() -> None:
    source = (UI_ROOT / "vite.config.ts").read_text(encoding="utf-8")

    assert "manualChunks" in source
    assert "recharts" in source
    assert "d3-vendor" in source
    assert "lucide-react" in source
    assert "react-vendor" not in source


def test_dist_css_matches_light_theme_baseline() -> None:
    dist_dir = UI_ROOT / "dist" / "assets"
    css_files = sorted(dist_dir.glob("*.css"))

    assert css_files, "expected built CSS asset in ui/dist/assets"
    css = css_files[0].read_text(encoding="utf-8")

    assert "#f5f7f9" in css
    assert "Plus Jakarta Sans" in css
    assert "#06111c" not in css
    assert "Space Grotesk" not in css
