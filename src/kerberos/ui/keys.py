"""Keyboard input decoding: raw terminal bytes to key names.

Rich does not read keys (tech.md §3), so KERBEROS decodes them itself.
Key names: "up", "down", "left", "right", "home", "end", "pgup", "pgdn",
"delete", "enter", "esc", "space", "backspace", "tab", "ctrl-c", "ctrl-d",
or the typed character itself (Cyrillic included).
"""

from __future__ import annotations

import codecs

_CSI_KEYS = {
    "A": "up",
    "B": "down",
    "C": "right",
    "D": "left",
    "H": "home",
    "F": "end",
    "1~": "home",
    "7~": "home",
    "4~": "end",
    "8~": "end",
    "3~": "delete",
    "5~": "pgup",
    "6~": "pgdn",
}

_CONTROL_KEYS = {
    "\r": "enter",
    "\n": "enter",
    "\t": "tab",
    " ": "space",
    "\x7f": "backspace",
    "\x08": "backspace",
    "\x03": "ctrl-c",
    "\x04": "ctrl-d",
}

# Hotkeys work with the Russian layout too: the key under the Latin letter
# produces a Cyrillic one (ЙЦУКЕН over QWERTY).
_LAYOUT = dict(zip("йцукенгшщзфывапролдячсмить", "qwertyuiopasdfghjklzxcvbnm"))


class KeyDecoder:
    """Incremental decoder; keeps incomplete escape sequences between reads."""

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._buffer = ""

    @property
    def waiting_escape(self) -> bool:
        """True when the buffer holds a lone ESC that may start a sequence."""
        return self._buffer == "\x1b"

    def feed(self, data: bytes) -> list[str]:
        self._buffer += self._decoder.decode(data)
        return self._drain()

    def flush(self) -> list[str]:
        """Called after a short silence: a lone ESC is the Esc key."""
        if self._buffer == "\x1b":
            self._buffer = ""
            return ["esc"]
        return self._drain()

    def _drain(self) -> list[str]:
        keys: list[str] = []
        s = self._buffer
        i = 0
        while i < len(s):
            ch = s[i]
            if ch == "\x1b":
                if i + 1 >= len(s):
                    break  # maybe the start of a sequence: wait for more bytes
                nxt = s[i + 1]
                if nxt in "[O":
                    j = i + 2
                    while j < len(s) and not ("\x40" <= s[j] <= "\x7e"):
                        j += 1
                    if j >= len(s):
                        break  # incomplete sequence
                    body = s[i + 2 : j + 1]
                    # Strip modifier parameters like "1;5A" (Ctrl+Up) to the base key.
                    final = body[-1]
                    params = body[:-1].split(";")[0]
                    name = _CSI_KEYS.get(params + final if final == "~" else final)
                    if name:
                        keys.append(name)
                    i = j + 1
                    continue
                keys.append("esc")
                i += 1
                continue
            if ch in _CONTROL_KEYS:
                keys.append(_CONTROL_KEYS[ch])
            elif ch.isprintable():
                keys.append(ch)
            i += 1
        self._buffer = s[i:]
        return keys


def hotkey(key: str) -> str:
    """Normalise a key for hotkey matching: Cyrillic layout and Caps Lock."""
    if len(key) != 1:
        return key
    low = key.lower()
    return _LAYOUT.get(low, low)
