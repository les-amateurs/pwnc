"""Walk .debug_info DIEs using abbreviation tables, produce DIE tree."""

from .reader import DwarfReader
from .abbrev import parse_abbrev_table
from .constants import *


class DIE:
    __slots__ = ("offset", "tag", "attrs", "children")

    def __init__(self, offset, tag):
        self.offset = offset
        self.tag = tag
        self.attrs = {}      # attribute -> value
        self.children = []   # list of DIE

    def attr(self, name, default=None):
        return self.attrs.get(name, default)

    def __repr__(self):
        tag_name = TAG_NAMES.get(self.tag, f"0x{self.tag:02x}")
        return f"DIE({tag_name} @ 0x{self.offset:x})"


class CompilationUnit:
    __slots__ = ("offset", "length", "version", "abbrev_offset", "addr_size", "root")

    def __init__(self):
        self.offset = 0
        self.length = 0
        self.version = 0
        self.abbrev_offset = 0
        self.addr_size = 0
        self.root = None  # root DIE (DW_TAG_compile_unit)


# ── CU boundary: lightweight metadata for parallelization ──────


class CUBoundary:
    """Lightweight CU descriptor used to parallelize parsing.

    Contains only header metadata — no DIE tree. Enough info to
    independently parse the CU later.
    """
    __slots__ = ("offset", "die_start", "cu_end", "version",
                 "abbrev_offset", "addr_size", "offset_size")

    def __init__(self, offset, die_start, cu_end, version,
                 abbrev_offset, addr_size, offset_size):
        self.offset = offset
        self.die_start = die_start
        self.cu_end = cu_end
        self.version = version
        self.abbrev_offset = abbrev_offset
        self.addr_size = addr_size
        self.offset_size = offset_size


def discover_cu_boundaries(debug_info):
    """Scan .debug_info headers to find CU boundaries without parsing DIEs.

    Returns a list of CUBoundary objects.
    """
    reader = DwarfReader(debug_info)
    boundaries = []

    debug_info_len = len(debug_info)
    while reader.offset < debug_info_len:
        cu_offset = reader.offset
        length = reader.read_u32()
        if length == 0xFFFFFFFF:
            raise NotImplementedError("64-bit DWARF not supported")

        offset_size = 4
        cu_end = reader.offset + length
        version = reader.read_u16()

        if version >= 5:
            _unit_type = reader.read_u8()
            addr_size = reader.read_u8()
            abbrev_offset = reader.read_u32()
        else:
            abbrev_offset = reader.read_u32()
            addr_size = reader.read_u8()

        die_start = reader.offset
        boundaries.append(CUBoundary(cu_offset, die_start, cu_end, version,
                                     abbrev_offset, addr_size, offset_size))
        reader.offset = cu_end

    return boundaries


def parse_single_cu(boundary, debug_info, debug_abbrev, debug_str,
                    debug_line_str=None):
    """Parse a single CU's DIE tree given its boundary metadata.

    Returns a CompilationUnit with its root DIE.
    """
    abbrev_table = parse_abbrev_table(debug_abbrev, boundary.abbrev_offset)
    reader = DwarfReader(debug_info, boundary.die_start)

    cu = CompilationUnit()
    cu.offset = boundary.offset
    cu.version = boundary.version
    cu.abbrev_offset = boundary.abbrev_offset
    cu.addr_size = boundary.addr_size

    cu.root = _parse_die_tree(reader, abbrev_table, boundary.addr_size,
                              debug_str, boundary.offset, boundary.cu_end,
                              debug_line_str, boundary.offset_size)
    return cu


# ── legacy entry point (sequential) ────────────────────────────


def parse_compilation_units(debug_info, debug_abbrev, debug_str,
                            debug_line_str=None):
    """Parse all compilation units from .debug_info (sequential).

    Returns a list of CompilationUnit objects.
    """
    boundaries = discover_cu_boundaries(debug_info)
    cus = []
    for b in boundaries:
        cu = parse_single_cu(b, debug_info, debug_abbrev, debug_str,
                             debug_line_str)
        cus.append(cu)
    return cus


# ── DIE tree parsing ────────────────────────────────────────────


def _parse_die_tree(reader, abbrev_table, addr_size, debug_str, cu_offset,
                    cu_end, debug_line_str=None, offset_size=4):
    """Parse a tree of DIEs until end of CU or a null entry at the current depth."""
    dies = []

    while reader.offset < cu_end:
        die_offset = reader.offset
        code = reader.read_uleb128()

        if code == 0:
            break

        if code not in abbrev_table:
            raise ValueError(f"unknown abbreviation code {code} at offset 0x{die_offset:x}")

        abbrev = abbrev_table[code]
        die = DIE(die_offset, abbrev.tag)

        for attr, form, implicit_value in abbrev.attrs:
            value = reader.read_form(form, addr_size, debug_str, cu_offset,
                                     debug_line_str, implicit_value, offset_size)
            die.attrs[attr] = value

        if abbrev.has_children:
            die.children = _parse_children(reader, abbrev_table, addr_size,
                                           debug_str, cu_offset, cu_end,
                                           debug_line_str, offset_size)

        dies.append(die)

    if len(dies) == 1:
        return dies[0]
    return dies[0] if dies else None


def _parse_children(reader, abbrev_table, addr_size, debug_str, cu_offset,
                    cu_end, debug_line_str=None, offset_size=4):
    """Parse children DIEs until a null entry."""
    children = []

    while reader.offset < cu_end:
        die_offset = reader.offset
        code = reader.read_uleb128()

        if code == 0:
            break

        if code not in abbrev_table:
            raise ValueError(f"unknown abbreviation code {code} at offset 0x{die_offset:x}")

        abbrev = abbrev_table[code]
        die = DIE(die_offset, abbrev.tag)

        for attr, form, implicit_value in abbrev.attrs:
            value = reader.read_form(form, addr_size, debug_str, cu_offset,
                                     debug_line_str, implicit_value, offset_size)
            die.attrs[attr] = value

        if abbrev.has_children:
            die.children = _parse_children(reader, abbrev_table, addr_size,
                                           debug_str, cu_offset, cu_end,
                                           debug_line_str, offset_size)

        children.append(die)

    return children


# ── type name indexing (for lazy mode) ──────────────────────────


_INDEX_TYPE_TAGS = frozenset({
    DW_TAG_structure_type, DW_TAG_class_type, DW_TAG_union_type,
    DW_TAG_enumeration_type, DW_TAG_typedef, DW_TAG_base_type,
})


def index_type_names(debug_info, debug_abbrev, debug_str,
                     debug_line_str=None, boundaries=None):
    """Build a lightweight index: type_name -> (cu_offset, die_offset).

    Used by lazy mode to know which types exist without fully parsing them.
    If boundaries is provided, skips the CU header scan.
    """
    if boundaries is None:
        boundaries = discover_cu_boundaries(debug_info)

    index = {}
    reader = DwarfReader(debug_info)
    abbrev_cache = {}
    plans_cache = {}

    for boundary in boundaries:
        # Cache abbreviation tables — many CUs share the same offset
        aoff = boundary.abbrev_offset
        cache_key = (aoff, boundary.addr_size, boundary.offset_size)
        plans = plans_cache.get(cache_key)
        if plans is None:
            abbrev_table = abbrev_cache.get(aoff)
            if abbrev_table is None:
                abbrev_table = parse_abbrev_table(debug_abbrev, aoff)
                abbrev_cache[aoff] = abbrev_table
            plans = _build_skip_plans(
                abbrev_table, boundary.addr_size, boundary.offset_size)
            plans_cache[cache_key] = plans

        reader.offset = boundary.die_start
        _index_cu(reader, plans, boundary.addr_size,
                  debug_str, debug_line_str, boundary.offset,
                  boundary.cu_end, boundary.offset_size, index)

    return index


PLAN_TYPE = 0
PLAN_SIBLING = 1
PLAN_SKIP = 2


def _compute_fixed_skip(forms, addr_size, offset_size):
    """Compute total byte size if all forms are fixed-size.

    Returns int if all fixed, or None if any form is variable.
    """
    total = 0
    for form in forms:
        size = FORM_FIXED_SIZE.get(form)
        if size is None:
            return None  # variable-length form present
        if size == -1:
            total += addr_size
        elif size == -2:
            total += offset_size
        else:
            total += size
    return total


def _compile_skip_sequence(forms, addr_size, offset_size):
    """Compile a list of forms into a sequence of (fixed_run, var_form) pairs.

    Batches consecutive fixed-size forms into a single offset increment,
    only calling skip_form for variable-length forms.
    Returns list of tuples: (fixed_bytes_to_skip, variable_form_or_None)
    """
    seq = []
    run = 0
    for form in forms:
        size = FORM_FIXED_SIZE.get(form)
        if size is None:
            seq.append((run, form))
            run = 0
        elif size == -1:
            run += addr_size
        elif size == -2:
            run += offset_size
        else:
            run += size
    if run > 0:
        seq.append((run, None))
    return seq


def _build_skip_plans(abbrev_table, addr_size, offset_size):
    """For each abbreviation code, build a compact plan for the indexer.

    Returns dict of code -> (action, has_children, skip_spec)
    """
    plans = {}
    type_tags = _INDEX_TYPE_TAGS

    for code, entry in abbrev_table.items():
        is_type = entry.tag in type_tags
        has_children = entry.has_children
        attrs = entry.attrs

        if is_type:
            plans[code] = (PLAN_TYPE, has_children, attrs)
        else:
            # Find DW_AT_sibling
            sibling_idx = -1
            for i, (attr, form, imp) in enumerate(attrs):
                if attr == DW_AT_sibling:
                    sibling_idx = i
                    break

            if sibling_idx >= 0 and has_children:
                pre_forms = [f for _, f, _ in attrs[:sibling_idx]]
                pre_skip = _compute_fixed_skip(pre_forms, addr_size, offset_size)
                sib_form = attrs[sibling_idx][1]
                if pre_skip is not None:
                    # All pre-sibling attrs are fixed size
                    plans[code] = (PLAN_SIBLING, True,
                                   (pre_skip, sib_form, None))
                else:
                    # Variable forms before sibling — compile a skip sequence
                    pre_seq = _compile_skip_sequence(pre_forms, addr_size, offset_size)
                    plans[code] = (PLAN_SIBLING, True,
                                   (pre_seq, sib_form, None))
            else:
                all_forms = [f for _, f, _ in attrs]
                total = _compute_fixed_skip(all_forms, addr_size, offset_size)
                if total is not None:
                    # All fixed — store single int
                    plans[code] = (PLAN_SKIP, has_children, total)
                else:
                    # Mixed — store compiled skip sequence
                    seq = _compile_skip_sequence(
                        all_forms, addr_size, offset_size)
                    plans[code] = (PLAN_SKIP, has_children, seq)

    return plans


def _index_cu(reader, plans, addr_size, debug_str, debug_line_str,
              cu_offset, cu_end, offset_size, index):
    """Index one CU's DIEs for type names."""
    skip_form = reader.skip_form
    read_form = reader.read_form

    while reader.offset < cu_end:
        die_offset = reader.offset
        code = reader.read_uleb128()

        if code == 0:
            return

        plan = plans.get(code)
        if plan is None:
            raise ValueError(
                f"unknown abbreviation code {code} at offset 0x{die_offset:x}")

        action = plan[0]
        has_children = plan[1]
        spec = plan[2]

        if action == PLAN_SKIP:
            if isinstance(spec, int):
                # All-fixed: single offset jump
                reader.offset += spec
            else:
                # Mixed: batched fixed runs + variable skips
                for fixed_run, var_form in spec:
                    reader.offset += fixed_run
                    if var_form is not None:
                        skip_form(var_form, addr_size, offset_size)
            if has_children:
                _index_cu(reader, plans, addr_size, debug_str,
                          debug_line_str, cu_offset, cu_end,
                          offset_size, index)

        elif action == PLAN_SIBLING:
            pre_skip, sib_form, _ = spec
            if isinstance(pre_skip, int):
                reader.offset += pre_skip
            else:
                # pre_skip is a compiled skip sequence
                for fixed_run, var_form in pre_skip:
                    reader.offset += fixed_run
                    if var_form is not None:
                        skip_form(var_form, addr_size, offset_size)
            sibling_off = read_form(sib_form, addr_size, debug_str,
                                    cu_offset, debug_line_str, None,
                                    offset_size)
            reader.offset = sibling_off

        else:
            # PLAN_TYPE — extract name, check declaration/byte_size
            name = None
            is_declaration = False
            has_byte_size = False

            for attr, form, implicit in spec:
                if attr == DW_AT_name:
                    name = read_form(form, addr_size, debug_str,
                                     cu_offset, debug_line_str,
                                     implicit, offset_size)
                elif attr == DW_AT_declaration:
                    val = read_form(form, addr_size, debug_str,
                                    cu_offset, debug_line_str,
                                    implicit, offset_size)
                    if val:
                        is_declaration = True
                elif attr == DW_AT_byte_size:
                    skip_form(form, addr_size, offset_size)
                    has_byte_size = True
                else:
                    skip_form(form, addr_size, offset_size)

            if name is not None:
                if not (is_declaration and not has_byte_size):
                    if name not in index:
                        index[name] = (cu_offset, die_offset)

            if has_children:
                _index_cu(reader, plans, addr_size, debug_str,
                          debug_line_str, cu_offset, cu_end,
                          offset_size, index)
