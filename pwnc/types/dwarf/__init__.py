"""DwarfSource: load type information from DWARF debug info."""

import pickle
import struct
import zlib

from ..resolver import Source
from ..base import Type
from .info import (parse_compilation_units, parse_single_cu,
                   discover_cu_boundaries, index_type_names)
from .builder import build_types_from_cu

# ELF section flag for compressed sections
_SHF_COMPRESSED = 0x800


class DwarfSource(Source):
    """Type source that loads from DWARF debug info sections.

    Accepts a file path (string) or a pwnc.minelf.ELF instance.

    Modes:
        lazy=True (default): fully deferred — no indexing until first
            access that requires it. Previously accessed types are
            cached to disk and loaded instantly on next construction.
        lazy=False: parses all CUs at construction.
    """

    def __init__(self, elf_or_path, lazy=True):
        if isinstance(elf_or_path, str):
            from pwnc.minelf import ELF
            with open(elf_or_path, "rb") as f:
                elf = ELF(f.read())
        else:
            elf = elf_or_path

        # Read DWARF sections
        self._debug_info = self._get_section(elf, b".debug_info")
        self._debug_abbrev = self._get_section(elf, b".debug_abbrev")
        self._debug_str = self._get_section(elf, b".debug_str")
        self._debug_line_str = self._get_section(elf, b".debug_line_str",
                                                  required=False)

        self.lazy = lazy
        self._types = {}           # bytes key -> Type (built types)
        self._cached_types = {}
        self._lazy_index = None    # bytes key -> (cu_offset, die_offset)
        self._cu_boundaries = None
        self._index_ready = False
        self._cache_key = None     # computed lazily
        self._cache_ready = False
        self._types_dirty = False

        if not lazy:
            self._load_all()

    def __del__(self):
        """Flush accessed types to disk cache on destruction."""
        if self._types_dirty:
            self._save_types_cache()

    def hash(self) -> bytes | None:
        self._ensure_cache_key()
        if self._cache_key is not None:
            return self._cache_key.encode("utf-8")
        return None

    # ── cache infrastructure ────────────────────────────────────

    def _ensure_cache_key(self):
        """Compute cache key on first need."""
        if self._cache_key is not None:
            return
        if self._debug_info is None:
            return
        import hashlib
        data = self._debug_info
        size = len(data)
        tail = bytes(data[-0x1000:]) if size >= 0x1000 else bytes(data[:0x1000])
        h = hashlib.md5()
        h.update(size.to_bytes(8, "little"))
        h.update(tail)
        self._cache_key = h.hexdigest()[:32]

    def _ensure_cache(self):
        """Load type cache from disk on first need."""
        if self._cache_ready:
            return
        self._cache_ready = True
        self._ensure_cache_key()
        self._load_types_cache()

    @staticmethod
    def _cache_dir(key):
        from pwnc.cache import locate_local_cache
        return locate_local_cache() / "dwarf" / key

    def _load_types_cache(self):
        """Load previously accessed types from disk."""
        if self._cache_key is None:
            return
        try:
            path = self._cache_dir(self._cache_key) / "types"
            if path.exists():
                with open(path, "rb") as f:
                    self._cached_types = pickle.load(f)
        except Exception:
            pass

    def _save_types_cache(self):
        """Flush accessed types to disk."""
        if self._cache_key is None or not self._cached_types:
            return
        try:
            d = self._cache_dir(self._cache_key)
            d.mkdir(parents=True, exist_ok=True)
            with open(d / "types", "wb") as f:
                pickle.dump(self._cached_types, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            pass

    def _load_index_cache(self):
        """Load the name index from disk."""
        if self._cache_key is None:
            return None
        try:
            path = self._cache_dir(self._cache_key) / "index"
            if path.exists():
                with open(path, "rb") as f:
                    return pickle.load(f)
        except Exception:
            pass
        return None

    def _save_index_cache(self, data):
        """Save the name index to disk."""
        if self._cache_key is None:
            return
        try:
            d = self._cache_dir(self._cache_key)
            d.mkdir(parents=True, exist_ok=True)
            with open(d / "index", "wb") as f:
                pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            pass

    # ── deferred indexing ───────────────────────────────────────

    def _ensure_index(self):
        """Build or load the name index on first need."""
        if self._index_ready:
            return
        cached = self._load_index_cache()
        if cached is not None:
            self._cu_boundaries, self._lazy_index = cached
        else:
            self._cu_boundaries = discover_cu_boundaries(self._debug_info)
            self._lazy_index = index_type_names(
                self._debug_info, self._debug_abbrev, self._debug_str,
                self._debug_line_str, self._cu_boundaries
            )
            self._save_index_cache(
                (self._cu_boundaries, self._lazy_index))
        self._index_ready = True

    # ── section loading ─────────────────────────────────────────

    def _get_section(self, elf, name, required=True, raw=False):
        section = elf.section_from_name(name)
        if section is None:
            if not required:
                return None
            raise ValueError(f"ELF has no {name.decode()} section")
        content = elf.section_content(section)

        if not raw and section.flags & _SHF_COMPRESSED:
            content = self._decompress_section(content)

        return content

    @staticmethod
    def _decompress_section(data):
        if len(data) < 24:
            raise ValueError("compressed section too small for header")
        ch_type = struct.unpack_from("<I", data, 0)[0]
        if ch_type != 1:
            raise ValueError(
                f"unsupported compression type {ch_type} "
                f"(only ELFCOMPRESS_ZLIB=1 is supported)")
        ch_size = struct.unpack_from("<Q", data, 8)[0]
        decompressed = zlib.decompress(data[24:])
        if len(decompressed) != ch_size:
            raise ValueError(
                f"decompressed size {len(decompressed)} != expected {ch_size}")
        return decompressed

    # ── upfront loading ─────────────────────────────────────────

    def _load_all(self):
        """Parse all compilation units and merge types."""
        boundaries = discover_cu_boundaries(self._debug_info)
        self._cu_boundaries = boundaries

        for b in boundaries:
            cu = parse_single_cu(b, self._debug_info, self._debug_abbrev,
                                 self._debug_str, self._debug_line_str)
            if cu.root is None:
                continue
            types = build_types_from_cu(cu.root, cu.addr_size)
            for name, ty in types.items():
                if name not in self._types:
                    self._types[name] = ty

        self._types_dirty = True
        self._index_ready = True

    # ── lazy loading ────────────────────────────────────────────

    @staticmethod
    def _to_key(name):
        if isinstance(name, str):
            return name.encode("utf-8")
        return name

    def _lazy_load(self, key):
        """Lazy-load a type by parsing only the CU that contains it."""
        self._ensure_index()
        if key not in self._lazy_index:
            raise KeyError(key)

        cu_offset, die_offset = self._lazy_index[key]

        boundary = None
        if self._cu_boundaries is not None:
            for b in self._cu_boundaries:
                if b.offset == cu_offset:
                    boundary = b
                    break

        if boundary is None:
            raise KeyError(key)

        cu = parse_single_cu(boundary, self._debug_info, self._debug_abbrev,
                             self._debug_str, self._debug_line_str)
        if cu.root is not None:
            types = build_types_from_cu(cu.root, cu.addr_size)
            ty = types[key]
            self._types.update(types)
            self._types_dirty = True
            return ty

    # ── public API ──────────────────────────────────────────────

    def __getitem__(self, name: str) -> Type:
        key = self._to_key(name)

        # Check type cache first (deferred load from disk on first access)
        self._ensure_cache()
        if key in self._cached_types:
            return self._cached_types[key]
        
        ty = None
        if key in self._types:
            ty = self._types[key]

        # Lazy mode: ensure index, then load
        if ty is None and self.lazy:
            self._ensure_index()
            if key in self._lazy_index:
                ty = self._lazy_load(key)

        if ty:
            self._cached_types[key] = ty
            return ty

        raise KeyError(name)

    def __contains__(self, name: str) -> bool:
        key = self._to_key(name)

        # Check type cache first (deferred load from disk on first access)
        self._ensure_cache()
        if key in self._cached_types:
            return True

        # Check lazy index (triggers index build on first call)
        if self.lazy:
            self._ensure_index()
            if key in self._lazy_index:
                return True

        ty = self._types.get(key, None)
        if ty:
            self._cached_types[key] = ty
            return True

        return False

    def names(self) -> list[str]:
        if self.lazy:
            self._ensure_index()
            return [k.decode("utf-8", errors="replace")
                    for k in self._lazy_index.keys()]
        return [k.decode("utf-8", errors="replace")
                for k in self._types.keys()]

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"no type named '{name}'")
