import os
from .util import *
from .config import find_config, load_config

LOCAL_CACHE_NAME = "_cache"


def locate_global_cache():
    if "XDG_CACHE_HOME" in os.environ:
        return Path(os.environ["XDG_CACHE_HOME"]) / "pwnc"
    return Path(os.environ["HOME"]) / ".cache" / "pwnc"


def locate_local_cache():
    config_path = find_config()
    if config_path is None:
        load_config(True)
        return Path(".").absolute() / LOCAL_CACHE_NAME

    return config_path.parent.absolute() / LOCAL_CACHE_NAME
