"""Constructor normalization for explicit console/PTY modes."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import ConsoleConfig, ConsoleMode, ViewerConfig
from pwnc.gdb.dap.__init__ import _configure_console


class _FakeGdb:
    def __init__(self):
        self.calls = []

    def console(self, config=None, *, keep_open=False):
        self.calls.append((config, keep_open))
        return "console"


def test_default_and_explicit_none_allocate_no_console() -> None:
    gdb = _FakeGdb()
    _configure_console(
        gdb,
        headless=None,
        console=None,
        console_keep_open=False,
    )
    _configure_console(
        gdb,
        headless=True,
        console=ConsoleConfig.none(),
        console_keep_open=False,
    )
    assert gdb.calls == []


@pytest.mark.parametrize(
    "config",
    [
        ConsoleConfig.current(),
        ConsoleConfig.target("/dev/pts/123"),
        ConsoleConfig.owned(),
        ConsoleConfig.owned(viewer=ViewerConfig.current()),
    ],
)
def test_explicit_console_config_is_forwarded(config) -> None:
    gdb = _FakeGdb()
    _configure_console(
        gdb,
        headless=None,
        console=config,
        console_keep_open=False,
    )
    assert gdb.calls == [(config, False)]


def test_legacy_non_headless_and_launcher_shims() -> None:
    gdb = _FakeGdb()
    _configure_console(
        gdb,
        headless=False,
        console=None,
        console_keep_open=True,
    )
    _configure_console(
        gdb,
        headless=None,
        console=["xterm", "-e"],
        console_keep_open=False,
    )
    assert gdb.calls == [(None, True), (["xterm", "-e"], False)]


@pytest.mark.parametrize(
    "arguments",
    [
        {
            "headless": True,
            "console": ConsoleConfig.owned(),
            "console_keep_open": False,
        },
        {
            "headless": False,
            "console": ConsoleConfig.none(),
            "console_keep_open": False,
        },
        {
            "headless": True,
            "console": ["xterm", "-e"],
            "console_keep_open": False,
        },
        {
            "headless": None,
            "console": ConsoleConfig.owned(),
            "console_keep_open": True,
        },
    ],
)
def test_conflicting_legacy_and_explicit_modes_raise(arguments) -> None:
    with pytest.raises(ValueError):
        _configure_console(_FakeGdb(), **arguments)


def test_mode_names_are_stable() -> None:
    assert [mode.value for mode in ConsoleMode] == [
        "none",
        "current",
        "target",
        "owned",
    ]
