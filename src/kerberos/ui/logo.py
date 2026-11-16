"""Logo and large digits: brand marks and graphics, not texts, so they live outside copy.py."""

from __future__ import annotations

# The brand mark, drawn with the `logo` palette token (red) in the header and on S1.
LOGO = "/// kerberos"

# Three rows per digit, three columns wide.
DIGITS = {
    "0": ("█▀█", "█ █", "▀▀▀"),
    "1": ("▀█ ", " █ ", "▀▀▀"),
    "2": ("▀▀█", "█▀▀", "▀▀▀"),
    "3": ("▀▀█", " ▀█", "▀▀▀"),
    "4": ("█ █", "▀▀█", "  ▀"),
    "5": ("█▀▀", "▀▀█", "▀▀▀"),
    "6": ("█▀▀", "█▀█", "▀▀▀"),
    "7": ("▀▀█", "  █", "  ▀"),
    "8": ("█▀█", "█▀█", "▀▀▀"),
    "9": ("█▀█", "▀▀█", "▀▀▀"),
}


def big_number(value: int) -> list[str]:
    """Rows of `value` drawn with DIGITS, one space between digits."""
    digits = str(max(0, value))
    return [" ".join(DIGITS[d][row] for d in digits) for row in range(3)]
