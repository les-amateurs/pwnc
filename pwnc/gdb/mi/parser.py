"""Full MI3 output record parser for GDB Machine Interface v3."""

from dataclasses import dataclass, field


# --- Record types ---

@dataclass
class ResultRecord:
    token: int | None
    cls: str
    results: dict

@dataclass
class ExecAsync:
    token: int | None
    cls: str
    results: dict

@dataclass
class StatusAsync:
    token: int | None
    cls: str
    results: dict

@dataclass
class NotifyAsync:
    token: int | None
    cls: str
    results: dict

@dataclass
class ConsoleStream:
    text: str

@dataclass
class TargetStream:
    text: str

@dataclass
class LogStream:
    text: str


Record = ResultRecord | ExecAsync | StatusAsync | NotifyAsync | ConsoleStream | TargetStream | LogStream


# --- C-string unescaping ---

_SIMPLE_ESCAPES = {
    'n': '\n',
    't': '\t',
    'r': '\r',
    '\\': '\\',
    '"': '"',
    'a': '\a',
    'b': '\b',
    'f': '\f',
    'v': '\v',
}


def _unescape(s: str) -> str:
    """Unescape a GDB MI C-string (without surrounding quotes)."""
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == '\\' and i + 1 < n:
            nxt = s[i + 1]
            if nxt in _SIMPLE_ESCAPES:
                out.append(_SIMPLE_ESCAPES[nxt])
                i += 2
            elif '0' <= nxt <= '7':
                # octal escape: up to 3 digits
                end = i + 2
                while end < n and end < i + 4 and '0' <= s[end] <= '7':
                    end += 1
                out.append(chr(int(s[i + 1:end], 8)))
                i = end
            elif nxt == 'x':
                # hex escape
                end = i + 2
                while end < n and end < i + 4 and s[end] in '0123456789abcdefABCDEF':
                    end += 1
                if end > i + 2:
                    out.append(chr(int(s[i + 2:end], 16)))
                    i = end
                else:
                    out.append('\\')
                    out.append('x')
                    i += 2
            else:
                out.append('\\')
                out.append(nxt)
                i += 2
        else:
            out.append(c)
            i += 1
    return ''.join(out)


# --- Recursive descent parser ---

def _parse_cstring(s: str, pos: int) -> tuple[str, int]:
    """Parse a C-string starting at pos (which should point to opening quote)."""
    if pos >= len(s) or s[pos] != '"':
        raise ValueError(f"Expected '\"' at position {pos}")
    pos += 1  # skip opening quote
    start = pos
    parts = []
    while pos < len(s):
        c = s[pos]
        if c == '"':
            parts.append(s[start:pos])
            return _unescape(''.join(parts)), pos + 1
        if c == '\\':
            pos += 2  # skip escaped char
        else:
            pos += 1
    raise ValueError("Unterminated c-string")


def _parse_value(s: str, pos: int) -> tuple:
    """Parse a value: c-string | tuple | list."""
    if pos >= len(s):
        raise ValueError(f"Unexpected end of input at position {pos}")
    c = s[pos]
    if c == '"':
        return _parse_cstring(s, pos)
    elif c == '{':
        return _parse_tuple(s, pos)
    elif c == '[':
        return _parse_list(s, pos)
    else:
        raise ValueError(f"Unexpected character '{c}' at position {pos}")


def _parse_tuple(s: str, pos: int) -> tuple[dict, int]:
    """Parse a tuple: {} | { kv (, kv)* }"""
    pos += 1  # skip '{'
    if pos < len(s) and s[pos] == '}':
        return {}, pos + 1
    result = {}
    while True:
        key, pos = _parse_variable(s, pos)
        if pos >= len(s) or s[pos] != '=':
            raise ValueError(f"Expected '=' at position {pos}")
        pos += 1
        val, pos = _parse_value(s, pos)
        result[key] = val
        if pos >= len(s):
            raise ValueError("Unterminated tuple")
        if s[pos] == '}':
            return result, pos + 1
        if s[pos] == ',':
            pos += 1
        else:
            raise ValueError(f"Expected ',' or '}}' at position {pos}, got '{s[pos]}'")


def _parse_list(s: str, pos: int) -> tuple[list | dict, int]:
    """Parse a list: [] | [ value (, value)* ] | [ kv (, kv)* ]"""
    pos += 1  # skip '['
    if pos < len(s) and s[pos] == ']':
        return [], pos + 1

    # peek to decide: kv-list or value-list
    # kv starts with variable=, value starts with " { [
    if pos < len(s) and s[pos] not in '"[{':
        # could be a kv-list
        return _parse_kv_list(s, pos)

    # value list
    items = []
    while True:
        val, pos = _parse_value(s, pos)
        items.append(val)
        if pos >= len(s):
            raise ValueError("Unterminated list")
        if s[pos] == ']':
            return items, pos + 1
        if s[pos] == ',':
            pos += 1
        else:
            raise ValueError(f"Expected ',' or ']' at position {pos}")


def _parse_kv_list(s: str, pos: int) -> tuple[dict | list, int]:
    """Parse a list of key-value pairs.

    Returns a dict if all keys are unique.
    Returns a list of values if any key repeats (common in MI: [frame={},frame={}]).
    """
    pairs = []
    while True:
        key, pos = _parse_variable(s, pos)
        if pos >= len(s) or s[pos] != '=':
            raise ValueError(f"Expected '=' at position {pos}")
        pos += 1
        val, pos = _parse_value(s, pos)
        pairs.append((key, val))
        if pos >= len(s):
            raise ValueError("Unterminated kv-list")
        if s[pos] == ']':
            # check for duplicate keys
            keys = [k for k, v in pairs]
            if len(keys) == len(set(keys)):
                return {k: v for k, v in pairs}, pos + 1
            else:
                return [v for k, v in pairs], pos + 1
        if s[pos] == ',':
            pos += 1


def _parse_variable(s: str, pos: int) -> tuple[str, int]:
    """Parse a variable name (alphanumeric + underscore + hyphen)."""
    start = pos
    while pos < len(s) and (s[pos].isalnum() or s[pos] in '_-'):
        pos += 1
    if pos == start:
        raise ValueError(f"Expected variable name at position {pos}")
    return s[start:pos], pos


def _parse_results(s: str, pos: int) -> tuple[dict, int]:
    """Parse comma-separated key=value pairs until end of string."""
    results = {}
    while pos < len(s) and s[pos] == ',':
        pos += 1  # skip comma
        key, pos = _parse_variable(s, pos)
        if pos >= len(s) or s[pos] != '=':
            raise ValueError(f"Expected '=' at position {pos}")
        pos += 1
        val, pos = _parse_value(s, pos)
        results[key] = val
    return results, pos


# --- Top-level record parser ---

def parse_output(line: str) -> Record | None:
    """Parse a single MI output line into a Record.

    Returns None for the (gdb) prompt or empty lines.
    """
    line = line.rstrip('\r\n')
    if not line or line == '(gdb)' or line == '(gdb) ':
        return None

    pos = 0
    n = len(line)

    # extract optional token (leading digits)
    token = None
    while pos < n and line[pos].isdigit():
        pos += 1
    if pos > 0:
        token = int(line[:pos])

    if pos >= n:
        return None

    prefix = line[pos]
    pos += 1

    # stream records (no class, just c-string)
    if prefix == '~':
        text, _ = _parse_cstring(line, pos)
        return ConsoleStream(text)
    elif prefix == '@':
        text, _ = _parse_cstring(line, pos)
        return TargetStream(text)
    elif prefix == '&':
        text, _ = _parse_cstring(line, pos)
        return LogStream(text)

    # result / async records: prefix class [,kv]*
    cls_start = pos
    while pos < n and line[pos] not in ',\r\n':
        pos += 1
    cls = line[cls_start:pos]

    results, _ = _parse_results(line, pos)

    if prefix == '^':
        return ResultRecord(token, cls, results)
    elif prefix == '*':
        return ExecAsync(token, cls, results)
    elif prefix == '+':
        return StatusAsync(token, cls, results)
    elif prefix == '=':
        return NotifyAsync(token, cls, results)
    else:
        # unknown prefix — return as console stream
        return ConsoleStream(line)
