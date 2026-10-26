"""Dev D: JSON / HTML / text reports. Public API frozen (docs/CONTRACTS.md 4)."""
from .html import render_html
from .text import render_json, render_text

__all__ = ["render_html", "render_json", "render_text"]
