"""Teemo: Binary Ninja HLIL debug information for GDB."""

from binaryninja import PluginCommand

from .teemo.commands import disable_live_export, enable_live_export, is_supported_view, schedule_export


PluginCommand.register(
    "Teemo\\Export or refresh GDB debug info",
    "Generate an atomic DWARF generation from the current Binary Ninja analysis",
    schedule_export,
    is_supported_view,
)
PluginCommand.register(
    "Teemo\\Enable live export",
    "Regenerate Teemo debug information after settled analysis changes",
    enable_live_export,
    is_supported_view,
)
PluginCommand.register(
    "Teemo\\Disable live export",
    "Stop watching this BinaryView for Teemo updates",
    disable_live_export,
    is_supported_view,
)
