from kerberos.ui.keys import KeyDecoder, hotkey


def test_arrows_enter_space_backspace():
    d = KeyDecoder()
    assert d.feed(b"\x1b[A\x1b[B\x1b[C\x1b[D\r \x7f\t") == [
        "up", "down", "right", "left", "enter", "space", "backspace", "tab",
    ]


def test_application_mode_and_tilde_keys():
    d = KeyDecoder()
    assert d.feed(b"\x1bOA\x1b[3~\x1b[5~\x1b[6~\x1b[1~\x1b[4~") == [
        "up", "delete", "pgup", "pgdn", "home", "end",
    ]


def test_modifier_parameters_are_ignored():
    assert KeyDecoder().feed(b"\x1b[1;5A") == ["up"]


def test_lone_escape_waits_then_flushes():
    d = KeyDecoder()
    assert d.feed(b"\x1b") == []
    assert d.waiting_escape
    assert d.flush() == ["esc"]


def test_split_escape_sequence_is_joined():
    d = KeyDecoder()
    assert d.feed(b"\x1b[") == []
    assert d.feed(b"A") == ["up"]


def test_utf8_split_across_reads():
    d = KeyDecoder()
    data = "пароль".encode()
    keys = d.feed(data[:3]) + d.feed(data[3:])
    assert "".join(keys) == "пароль"


def test_ctrl_c_is_a_key():
    assert KeyDecoder().feed(b"\x03") == ["ctrl-c"]


def test_unknown_sequence_is_dropped():
    assert KeyDecoder().feed(b"\x1b[99zq") == ["q"]


def test_hotkeys_with_russian_layout_and_caps():
    assert hotkey("й") == "q"
    assert hotkey("ь") == "m"
    assert hotkey("ф") == "a"
    assert hotkey("ы") == "s"
    assert hotkey("Q") == "q"
    assert hotkey("enter") == "enter"
