import re
from .primitives import Int, Bits, Float, Double, Ptr
from .containers import Struct, Union, Array, Enum
from .value import Value, ArrayValue

def _type_str(ty):
    """Short type string for a field (e.g. 'u32', 'f32', 'struct Vec3')."""
    if isinstance(ty, Bits):
        return f"bits({ty.nbits})"
    if isinstance(ty, Int):
        prefix = "i" if ty.signed else "u"
        return f"{prefix}{ty.nbits}"
    if isinstance(ty, Float):
        return "f32"
    if isinstance(ty, Double):
        return "f64"
    if isinstance(ty, Ptr):
        if ty.child is None:
            return "void*"
        return f"{_type_str(ty.child)}*"
    if isinstance(ty, Array):
        if ty.count == 0:
            return f"{_type_str(ty.child)}[]"
        return f"{_type_str(ty.child)}[{ty.count}]"
    if isinstance(ty, Enum):
        return f"enum {ty.name} : {_type_str(ty.child)}" if ty.name else f"enum : {_type_str(ty.child)}"
    if isinstance(ty, Struct):
        return f"struct {ty.name}"
    if isinstance(ty, Union):
        return f"union {ty.name}"
    return str(ty)


def _field_type_str(ty):
    """Type prefix for field display (no array suffix, that goes after the name)."""
    if isinstance(ty, Array):
        return _type_str(ty.child)
    return _type_str(ty)


def _field_suffix(ty):
    """Suffix after field name (array brackets)."""
    if isinstance(ty, Array):
        if ty.count == 0:
            return "[]"
        return f"[{ty.count}]"
    return ""


def _max_nesting(ty, _seen=None):
    """Compute the maximum nesting depth of a container type."""
    if _seen is None:
        _seen = set()
    if not isinstance(ty, (Struct, Union)):
        return 0
    if id(ty) in _seen:
        return 0
    _seen.add(id(ty))
    child_max = 0
    for _, ftype in ty._fields:
        child_max = max(child_max, _max_nesting(ftype, _seen))
    return 1 + child_max


def _resolve_depth(depth, ty):
    """Resolve depth to an internal countdown value.

    depth=None or 0: infinite (returns None)
    depth>0: show depth-1 layers of fields (1=collapse, 2=one layer, ...)
    depth<0: show all except |depth| deepest layers
    """
    if depth is None or depth == 0:
        return None
    if depth > 0:
        return depth
    # Negative: compute max nesting, subtract
    max_d = _max_nesting(ty)
    resolved = max_d + depth  # e.g. max=4, depth=-1 -> 3
    return max(1, resolved)  # at least 1 (collapse everything)


def format_type(ty, depth=None, filter=None, _indent=0, _seen=None):
    if _seen is None:
        _seen = set()

    if filter:
        filter = re.compile(filter)

    if isinstance(ty, (Int, Float, Double, Ptr)):
        return str(ty)

    if isinstance(ty, Bits):
        return str(ty)

    if isinstance(ty, Array):
        return str(ty)

    if isinstance(ty, Enum):
        return str(ty)

    if isinstance(ty, (Struct, Union)):
        resolved = _resolve_depth(depth, ty)
        return _format_container(ty, resolved, filter, _indent, _seen)

    return str(ty)


def _format_container(ty, depth, filter, indent, seen, base_offset=0, _ancestors=None):
    if _ancestors is None:
        _ancestors = set()

    kind = "struct" if isinstance(ty, Struct) else "union"
    prefix = "    " * indent
    inner_prefix = "    " * (indent + 1)

    ty_id = id(ty)

    # Cycle detection: if this type is an ancestor, always collapse
    if ty_id in _ancestors:
        return f"{prefix}{kind} {ty.name} {{ ... }}"

    mode_str = f", {ty.mode}" if isinstance(ty, Struct) else ""
    header = f"{prefix}{kind} {ty.name} {{  /* 0x{ty.nbytes:02x} bytes{mode_str} */"

    lines = [header]

    # Deduplication for limited-depth display
    is_repeat = depth is not None and ty_id in seen
    seen.add(ty_id)

    if is_repeat or (depth is not None and depth <= 1):
        lines = [f"{prefix}{kind} {ty.name} {{ ... }}"]
        return "\n".join(lines)

    child_depth = depth - 1 if depth is not None else None
    _ancestors.add(ty_id)

    # build a set of padding offsets for display
    pad_entries = []
    if isinstance(ty, Struct):
        pad_entries = list(ty._padding)

    # merge fields and padding, sorted by offset
    entries = []
    for fname, ftype, byte_off, bit_off in ty._layout:
        entries.append(("field", fname, ftype, byte_off, bit_off))
    for pad_off, pad_size in pad_entries:
        entries.append(("padding", None, None, pad_off, pad_size))

    entries.sort(key=lambda e: (e[3], 0 if e[0] == "field" else 1))

    for entry in entries:
        if entry[0] == "padding":
            _, _, _, pad_off, pad_size = entry
            lines.append(f"{inner_prefix}/* 0x{pad_off + base_offset:02x} padding({pad_size}) */")
        else:
            _, fname, ftype, byte_off, bit_off = entry

            # apply filter
            if filter is not None and not filter.search(fname):
                continue

            abs_off = byte_off + base_offset

            if isinstance(ftype, Bits):
                offset_str = f"0x{abs_off:02x}:{bit_off}"
            else:
                offset_str = f"0x{abs_off:02x}"

            # nested container
            if isinstance(ftype, (Struct, Union)):
                nested_kind = "struct" if isinstance(ftype, Struct) else "union"
                if id(ftype) in _ancestors or (child_depth is not None and (ftype_id_seen(ftype, seen) or child_depth <= 1)):
                    lines.append(f"{inner_prefix}/* {offset_str} */ {nested_kind} {ftype.name} {{ ... }} {fname};")
                else:
                    nested = _format_container(ftype, child_depth, None, indent + 1, seen, abs_off, _ancestors)
                    nested_lines = nested.split("\n")
                    if len(nested_lines) == 1:
                        # Collapsed to single line
                        lines.append(f"{inner_prefix}{nested_lines[0].lstrip()} {fname};")
                    else:
                        lines.append(f"{inner_prefix}{nested_lines[0].lstrip()}")
                        for nl in nested_lines[1:-1]:
                            lines.append(nl)
                        lines.append(f"{inner_prefix}}} {fname};")
            elif isinstance(ftype, Enum):
                type_label = _type_str(ftype)
                lines.append(f"{inner_prefix}/* {offset_str} */ {type_label} {fname};")
            elif isinstance(ftype, Array):
                elem_type = _field_type_str(ftype)
                suffix = _field_suffix(ftype)
                if any(isinstance(ft, Bits) for _, ft in ty._fields):
                    lines.append(f"{inner_prefix}/* {offset_str} */ {elem_type} {fname}{suffix};")
                else:
                    lines.append(f"{inner_prefix}/* {offset_str} */ {elem_type} {fname}{suffix};")
            else:
                type_label = _type_str(ftype)
                if isinstance(ty, Struct) and any(isinstance(ft, Bits) for _, ft in ty._fields) and not isinstance(ftype, Bits):
                    lines.append(f"{inner_prefix}/* {offset_str} */ {type_label} {fname};")
                else:
                    lines.append(f"{inner_prefix}/* {offset_str} */ {type_label} {fname};")

    _ancestors.discard(ty_id)
    lines.append(f"{inner_prefix}/* total size: 0x{ty.nbytes:x} */")
    lines.append(f"{prefix}}}")
    return "\n".join(lines)


def ftype_id_seen(ftype, seen):
    return id(ftype) in seen


def format_value(val, depth=None, filter=None, _indent=0):
    if filter:
        filter = re.compile(filter)

    ty = val._type
    prefix = "    " * _indent
    inner_prefix = "    " * (_indent + 1)

    if isinstance(ty, (Struct, Union)):
        depth = _resolve_depth(depth, ty)
        name = ty.name
        lines = [f"{prefix}{name} {{"]

        if depth is not None and depth <= 1:
            lines.append(f"{inner_prefix}...")
            lines.append(f"{prefix}}}")
            return "\n".join(lines)

        child_depth = depth - 1 if depth is not None else None

        for fname, ftype, byte_off, bit_off in ty._layout:
            if filter is not None and not filter.search(fname):
                continue

            field_offset = val._base_offset + byte_off
            field_val = Value(ftype, val._provider, field_offset)

            if isinstance(ftype, Bits):
                field_val._bit_offset = bit_off

            if isinstance(ftype, (Struct, Union)):
                if depth is not None and depth <= 1:
                    lines.append(f"{inner_prefix}{fname} = {ftype.name} {{ ... }}")
                else:
                    nested = format_value(field_val, depth=child_depth, _indent=_indent + 1)
                    nested_lines = nested.split("\n")
                    lines.append(f"{inner_prefix}{fname} = {nested_lines[0].lstrip()}")
                    for nl in nested_lines[1:]:
                        lines.append(nl)
            elif isinstance(ftype, Array):
                arr_val = ArrayValue(ftype, val._provider, field_offset)
                lines.append(f"{inner_prefix}{fname} = {arr_val}")
            elif isinstance(ftype, Enum):
                raw_val = Value(ftype.child, val._provider, field_offset)._resolve()
                name_str = ftype._reverse.get(raw_val)
                if name_str:
                    lines.append(f"{inner_prefix}{fname} = {name_str} ({raw_val})")
                else:
                    lines.append(f"{inner_prefix}{fname} = {raw_val}")
            elif isinstance(ftype, Bits):
                resolved = field_val._resolve()
                lines.append(f"{inner_prefix}{fname} = {resolved}")
            elif isinstance(ftype, Ptr):
                resolved = field_val._resolve()
                lines.append(f"{inner_prefix}{fname} = 0x{resolved:x}")
            else:
                resolved = field_val._resolve()
                lines.append(f"{inner_prefix}{fname} = {resolved}")

        lines.append(f"{prefix}}}")
        return "\n".join(lines)

    # Primitives
    return str(val)
