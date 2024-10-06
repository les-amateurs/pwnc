import toml
import atexit
import os
from pathlib import Path

CONFIG_FILE = "pwnc.toml"
DEFAULT_GLOBAL_CONFIG = """
[gdb]
index-cache = true
# index-cache-path =
"""

def locate_global_config_directory():
    if "XDG_CONFIG_HOME" in os.environ:
        return Path(os.environ["XDG_CONFIG_HOME"])
    return Path(os.environ["HOME"]) / ".config" / "pwnc"

def load_global_config():
    config_path = config = locate_global_config_directory() / CONFIG_FILE
    if not config_path.exists():
        config_path.parent.mkdir(exist_ok=True)
        with open(config_path, "w+") as fp:
            fp.write(DEFAULT_GLOBAL_CONFIG)
            # toml.dump(DEFAULT_GLOBAL_CONFIG, fp)

    if config_path:
        with open(config_path, "r") as fp:
            return toml.load(fp)

def find_config():
    cwd = Path(".")
    while not (cwd / CONFIG_FILE).exists():
        if cwd == cwd.parent:
            return None
        
    return cwd / CONFIG_FILE

_global_config_ = load_global_config()
_local_config_ = None
_local_config_path_ = None
_old_serialized_config_ = None

def save_config():
    if _local_config_path_ is not None:
        _new_serialized_config_ = toml.dumps(_local_config_)
        if _new_serialized_config_ != _old_serialized_config_:
            with open(_local_config_path_, "w+") as fp:
                fp.write(_new_serialized_config_)

atexit.register(save_config)

def load_config(init: bool):
    global _local_config_, _local_config_path_, _old_serialized_config_
    if _local_config_ is None:
        config_path = find_config()
        if config_path is None:
            if init:
                _local_config_ = {}
                _local_config_path_ = Path(".") / CONFIG_FILE
        else:
            with open(config_path, "r") as fp:
                _old_serialized_config_ = fp.read()
            _local_config_ = toml.loads(_old_serialized_config_)
            _local_config_path_ = config_path

    return _local_config_

class Key:
    def __init__(self, key: str):
        self.parts = [key]

    def name(self):
        return self.parts[-1]
    
    def path(self):
        return self.parts[:-1]

    def __truediv__(self, other: str):
        new = Key("")
        new.parts = [part for part in self.parts] + [other]
        return new
    
    def __str__(self):
        return " -> ".join(self.parts)
    
    def __repr__(self):
        return f"{self}"

def traverse(config: dict, key: Key, create: bool):
    keys = iter(key.path())
    while True:
        try:
            next_key = next(keys)
        except StopIteration:
            break

        if next_key not in config:
            if create:
                subconfig = {}
                config[next_key] = subconfig
            else:
                raise KeyError(next_key)
            
        config = config[next_key]
            
    return config

def save(key: Key, info):
    config = load_config(True)
    traverse(config, key, True)[key.name()] = info

def load(key: Key):
    config = load_config(False)
    if config is not None:
        try:
            return traverse(config, key, False)[key.name()]
        except KeyError:
            pass

    try:
        return traverse(_global_config_, key, False)[key.name()]
    except KeyError:
        raise KeyError(key)
    
def exists(key: Key):
    config = load_config(False)
    if config is not None:
        try:
            traverse(config, key, False)[key.name()]
            return True
        except KeyError:
            pass
        
    try:
        traverse(_global_config_, key, False)[key.name()]
        return True
    except KeyError:
        pass
    
    return False