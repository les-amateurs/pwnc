"""Parse .debug_abbrev into abbreviation tables."""

from .reader import DwarfReader
from .constants import DW_FORM_implicit_const


class AbbrevEntry:
    __slots__ = ("code", "tag", "has_children", "attrs")

    def __init__(self, code, tag, has_children, attrs):
        self.code = code
        self.tag = tag
        self.has_children = has_children
        self.attrs = attrs  # list of (attribute, form, implicit_value)

    # For backward-compatible iteration that ignores the third element,
    # callers should use the full 3-tuple.


def parse_abbrev_table(data, offset):
    """Parse one abbreviation table starting at offset.

    Returns a dict mapping abbreviation code -> AbbrevEntry.

    Each attr entry is a 3-tuple: (attribute, form, implicit_value).
    implicit_value is only meaningful when form == DW_FORM_implicit_const;
    for all other forms it is None.
    """
    reader = DwarfReader(data, offset)
    table = {}

    while True:
        code = reader.read_uleb128()
        if code == 0:
            break

        tag = reader.read_uleb128()
        has_children = reader.read_u8() != 0

        attrs = []
        while True:
            attr = reader.read_uleb128()
            form = reader.read_uleb128()
            if attr == 0 and form == 0:
                break
            if form == DW_FORM_implicit_const:
                implicit_value = reader.read_sleb128()
            else:
                implicit_value = None
            attrs.append((attr, form, implicit_value))

        table[code] = AbbrevEntry(code, tag, has_children, attrs)

    return table
