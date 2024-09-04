import os
from .util import *

def locate_cache():
    if "XDG_CACHE_HOME" in os.environ:
        return Path(os.environ["XDG_CACHE_HOME"]) / "pwnc"
    return Path(os.environ["HOME"]) / ".cache" / "pwnc"