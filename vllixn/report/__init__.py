"""Report rendering: terminal text, JSON and self-contained HTML."""

from __future__ import annotations

from .html_export import render as render_html
from .json_export import render_json
from .terminal import render as render_terminal

__all__ = ["render_html", "render_json", "render_terminal"]
