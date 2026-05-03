from abc import ABC, abstractmethod
from .base import Type


class Source(ABC):
    @abstractmethod
    def __getitem__(self, name: str) -> Type: ...

    @abstractmethod
    def __contains__(self, name: str) -> bool: ...

    @abstractmethod
    def names(self) -> list[str]: ...

    @abstractmethod
    def hash(self) -> bytes | None:
        """Return a hash identifying this source's content, or None if not cacheable."""
        ...

    def __del__(self):
        """Called on destruction. Subclasses override to flush caches."""
        pass


class StaticSource(Source):
    def __init__(self, types):
        self._types = {}
        if isinstance(types, dict):
            self._types = dict(types)
        elif isinstance(types, list):
            for ty in types:
                self._types[ty.name] = ty
        else:
            raise TypeError("StaticSource accepts a list or dict of types")

    def __getitem__(self, name: str) -> Type:
        if name not in self._types:
            raise KeyError(name)
        return self._types[name]

    def __contains__(self, name: str) -> bool:
        return name in self._types

    def names(self) -> list[str]:
        return list(self._types.keys())

    def hash(self) -> bytes | None:
        return None


class Types:
    def __init__(self):
        self.sources = []
        self._user_types = {}

    def add(self, source: Source):
        self.sources.append(source)

    def define(self, name: str, ty: Type):
        self._user_types[name] = ty

    def __getitem__(self, name: str) -> Type:
        if name in self._user_types:
            return self._user_types[name]
        for source in self.sources:
            if name in source:
                return source[name]
        raise KeyError(name)

    def __contains__(self, name: str) -> bool:
        if name in self._user_types:
            return True
        return any(name in source for source in self.sources)

    def names(self) -> list[str]:
        seen = set()
        result = []
        for name in self._user_types:
            if name not in seen:
                seen.add(name)
                result.append(name)
        for source in self.sources:
            for name in source.names():
                if name not in seen:
                    seen.add(name)
                    result.append(name)
        return result

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"no type named '{name}'")
