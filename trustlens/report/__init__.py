"""Dev D: JSON / HTML / text / SARIF reports. Public API frozen (docs/CONTRACTS.md 4)."""
from .html import render_comparison_html, render_html
from .sarif import render_sarif
from .text import render_json, render_text

__all__ = ["render_html", "render_comparison_html", "render_json", "render_text", "render_sarif"]
