from ...cache import locate_global_cache
import shelve

SHELVES = {}
CACHE = locate_global_cache() / "shelves"
CACHE.mkdir(parents=True, exist_ok=True)

class Index:
    def __init__(self, name: str):
        global SHELVES

        if name in SHELVES:
            handle = SHELVES[name]
        else:
            filename = CACHE / name
            handle = shelve.open(filename)
            SHELVES[name] = handle

        self.handle = handle

    def __getitem__(self, key):
        return self.handle[key]
    
    def __setitem__(self, key, val):
        self.handle[key] = val

    def __contains__(self, key):
        return key in self.handle