"""Compatibility entry point for existing `source dwarf/plugin/gdbinit.py` users."""

from pathlib import Path

script = Path(__file__).resolve().parents[1] / "gdb" / "teemo_gdb.py"
exec(compile(script.read_bytes(), str(script), "exec"), {"__file__": str(script), "__name__": "teemo_gdb"})
