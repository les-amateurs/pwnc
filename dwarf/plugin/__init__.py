from pathlib import Path
from binaryninja import (
    BinaryView,
    PluginCommand,
)
from .teemo.config import *
from .teemo.server import start_server, stop_server, update_server, stop_all_servers

def reload():
    import importlib
    import sys
    stop_all_servers()
    importlib.reload(teemo.config)
    importlib.reload(teemo.connect)
    importlib.reload(teemo.extract)
    importlib.reload(teemo.server)
    importlib.reload(teemo)
    importlib.reload(sys.modules[__name__])

class MenuPath:
    def __init__(self, name: str):
        self.components = [name]

    def __truediv__(self, other: str):
        self.components.append(other)
        return self

    def __str__(self):
        return " \\ ".join(self.components)

    def encode(self, encoding: str):
        return str(self).encode(encoding=encoding)

PluginCommand.register(
    MenuPath(NAME) / "start server",
    "",
    start_server,
)

PluginCommand.register(
    MenuPath(NAME) / "update server",
    "",
    update_server,
)

PluginCommand.register(
    MenuPath(NAME) / "stop server",
    "",
    stop_server,
)
