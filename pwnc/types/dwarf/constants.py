# DWARF Tags
DW_TAG_array_type = 0x01
DW_TAG_class_type = 0x02
DW_TAG_enumeration_type = 0x04
DW_TAG_formal_parameter = 0x05
DW_TAG_lexical_block = 0x0b
DW_TAG_member = 0x0d
DW_TAG_pointer_type = 0x0f
DW_TAG_reference_type = 0x10
DW_TAG_compile_unit = 0x11
DW_TAG_structure_type = 0x13
DW_TAG_subroutine_type = 0x15
DW_TAG_typedef = 0x16
DW_TAG_union_type = 0x17
DW_TAG_unspecified_parameters = 0x18
DW_TAG_inheritance = 0x1c
DW_TAG_subrange_type = 0x21
DW_TAG_base_type = 0x24
DW_TAG_const_type = 0x26
DW_TAG_enumerator = 0x28
DW_TAG_subprogram = 0x2e
DW_TAG_variable = 0x34
DW_TAG_volatile_type = 0x35
DW_TAG_restrict_type = 0x37
DW_TAG_namespace = 0x39
DW_TAG_unspecified_type = 0x3b
DW_TAG_rvalue_reference_type = 0x42

# DWARF Attributes
DW_AT_sibling = 0x01
DW_AT_location = 0x02
DW_AT_name = 0x03
DW_AT_byte_size = 0x0b
DW_AT_bit_size = 0x0d
DW_AT_bit_offset = 0x0c
DW_AT_stmt_list = 0x10
DW_AT_low_pc = 0x11
DW_AT_high_pc = 0x12
DW_AT_language = 0x13
DW_AT_comp_dir = 0x1a
DW_AT_const_value = 0x1c
DW_AT_declaration = 0x3c
DW_AT_upper_bound = 0x2f
DW_AT_count = 0x37
DW_AT_data_member_location = 0x38
DW_AT_decl_column = 0x39
DW_AT_decl_file = 0x3a
DW_AT_decl_line = 0x3b
DW_AT_encoding = 0x3e
DW_AT_external = 0x3f
DW_AT_frame_base = 0x40
DW_AT_type = 0x49
DW_AT_data_bit_offset = 0x6b
DW_AT_producer = 0x25
DW_AT_prototyped = 0x27
DW_AT_GNU_all_call_sites = 0x2117

# DWARF Forms
DW_FORM_addr = 0x01
DW_FORM_block2 = 0x03
DW_FORM_block4 = 0x04
DW_FORM_data2 = 0x05
DW_FORM_data4 = 0x06
DW_FORM_data8 = 0x07
DW_FORM_string = 0x08
DW_FORM_block = 0x09
DW_FORM_block1 = 0x0a
DW_FORM_data1 = 0x0b
DW_FORM_flag = 0x0c
DW_FORM_sdata = 0x0d
DW_FORM_strp = 0x0e
DW_FORM_udata = 0x0f
DW_FORM_ref_addr = 0x10
DW_FORM_ref1 = 0x11
DW_FORM_ref2 = 0x12
DW_FORM_ref4 = 0x13
DW_FORM_ref8 = 0x14
DW_FORM_ref_udata = 0x15
DW_FORM_indirect = 0x16
DW_FORM_sec_offset = 0x17
DW_FORM_exprloc = 0x18
DW_FORM_flag_present = 0x19
DW_FORM_strx = 0x1a
DW_FORM_addrx = 0x1b
DW_FORM_ref_sup4 = 0x1c
DW_FORM_data16 = 0x1e
DW_FORM_line_strp = 0x1f
DW_FORM_ref_sig8 = 0x20
DW_FORM_implicit_const = 0x21
DW_FORM_loclistx = 0x22
DW_FORM_rnglistx = 0x23
DW_FORM_strx1 = 0x25
DW_FORM_strx2 = 0x26
DW_FORM_strx3 = 0x27
DW_FORM_strx4 = 0x28

# Fixed form sizes: form -> byte count.
# None = variable length.  -1 = addr_size.  -2 = offset_size.
FORM_FIXED_SIZE = {
    DW_FORM_addr: -1,           # addr_size
    DW_FORM_block2: None,
    DW_FORM_block4: None,
    DW_FORM_data2: 2,
    DW_FORM_data4: 4,
    DW_FORM_data8: 8,
    DW_FORM_string: None,
    DW_FORM_block: None,
    DW_FORM_block1: None,
    DW_FORM_data1: 1,
    DW_FORM_flag: 1,
    DW_FORM_sdata: None,
    DW_FORM_strp: 4,
    DW_FORM_udata: None,
    DW_FORM_ref_addr: -2,       # offset_size
    DW_FORM_ref1: 1,
    DW_FORM_ref2: 2,
    DW_FORM_ref4: 4,
    DW_FORM_ref8: 8,
    DW_FORM_ref_udata: None,
    DW_FORM_indirect: None,
    DW_FORM_sec_offset: -2,     # offset_size
    DW_FORM_exprloc: None,
    DW_FORM_flag_present: 0,
    DW_FORM_strx: None,
    DW_FORM_addrx: None,
    DW_FORM_ref_sup4: 4,
    DW_FORM_data16: 16,
    DW_FORM_line_strp: 4,
    DW_FORM_ref_sig8: 8,
    DW_FORM_implicit_const: 0,
    DW_FORM_loclistx: None,
    DW_FORM_rnglistx: None,
    DW_FORM_strx1: 1,
    DW_FORM_strx2: 2,
    DW_FORM_strx3: 3,
    DW_FORM_strx4: 4,
}

# DWARF Encodings
DW_ATE_address = 0x01
DW_ATE_boolean = 0x02
DW_ATE_complex_float = 0x03
DW_ATE_float = 0x04
DW_ATE_signed = 0x05
DW_ATE_signed_char = 0x06
DW_ATE_unsigned = 0x07
DW_ATE_unsigned_char = 0x08

# Tag name lookup (for debugging)
TAG_NAMES = {
    DW_TAG_array_type: "DW_TAG_array_type",
    DW_TAG_enumeration_type: "DW_TAG_enumeration_type",
    DW_TAG_formal_parameter: "DW_TAG_formal_parameter",
    DW_TAG_lexical_block: "DW_TAG_lexical_block",
    DW_TAG_member: "DW_TAG_member",
    DW_TAG_pointer_type: "DW_TAG_pointer_type",
    DW_TAG_compile_unit: "DW_TAG_compile_unit",
    DW_TAG_structure_type: "DW_TAG_structure_type",
    DW_TAG_subroutine_type: "DW_TAG_subroutine_type",
    DW_TAG_typedef: "DW_TAG_typedef",
    DW_TAG_union_type: "DW_TAG_union_type",
    DW_TAG_subrange_type: "DW_TAG_subrange_type",
    DW_TAG_base_type: "DW_TAG_base_type",
    DW_TAG_const_type: "DW_TAG_const_type",
    DW_TAG_enumerator: "DW_TAG_enumerator",
    DW_TAG_subprogram: "DW_TAG_subprogram",
    DW_TAG_variable: "DW_TAG_variable",
    DW_TAG_volatile_type: "DW_TAG_volatile_type",
    DW_TAG_restrict_type: "DW_TAG_restrict_type",
}
