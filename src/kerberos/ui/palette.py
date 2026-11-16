"""Terminal palette and symbols (tech.md §14.1).

Colour never carries meaning alone: every risk and state is also shown with a
symbol and a word, so the screens read the same with NO_COLOR.
"""

from __future__ import annotations

from rich.theme import Theme

PALETTE: dict[str, str] = {
    "risk.high": "bold red",
    "risk.medium": "bold yellow",
    "risk.low": "cyan",
    "ok": "bold green",
    "muted": "grey50",
    "accent": "bold magenta",
    "danger.bg": "white on red",
}

SYMBOL_RISK = "●"
SYMBOL_OK = "✓"
SYMBOL_FAIL = "✗"
SYMBOL_RUNNING = "…"
SYMBOL_ROLLED_BACK = "↺"

RISK_STYLE: dict[str, str] = {
    "high": "risk.high",
    "medium": "risk.medium",
    "low": "risk.low",
    "info": "muted",
}


def theme() -> Theme:
    """Rich theme with the palette tokens as style names."""
    return Theme(PALETTE)


def risk_style(risk: str) -> str:
    return RISK_STYLE.get(risk, "muted")


def score_style(score: int) -> str:
    """Score colour per §12.2: red up to 59, yellow 60-84, green from 85."""
    if score >= 85:
        return "ok"
    if score >= 60:
        return "risk.medium"
    return "risk.high"
