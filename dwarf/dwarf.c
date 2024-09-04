test.debug:	file format elf64-x86-64

.debug_abbrev contents:
Abbrev table for offset: 0x00000000
[1] DW_TAG_compile_unit	DW_CHILDREN_yes
	DW_AT_producer	DW_FORM_strp
	DW_AT_language	DW_FORM_data1
	DW_AT_name	DW_FORM_strp
	DW_AT_comp_dir	DW_FORM_strp
	DW_AT_low_pc	DW_FORM_addr
	DW_AT_high_pc	DW_FORM_data8
	DW_AT_stmt_list	DW_FORM_sec_offset
	DW_AT_GNU_macros	DW_FORM_sec_offset

[2] DW_TAG_subprogram	DW_CHILDREN_yes
	DW_AT_external	DW_FORM_flag_present
	DW_AT_name	DW_FORM_strp
	DW_AT_decl_file	DW_FORM_data1
	DW_AT_decl_line	DW_FORM_data1
	DW_AT_decl_column	DW_FORM_data1
	DW_AT_prototyped	DW_FORM_flag_present
	DW_AT_type	DW_FORM_ref4
	DW_AT_low_pc	DW_FORM_addr
	DW_AT_high_pc	DW_FORM_data8
	DW_AT_frame_base	DW_FORM_exprloc
	DW_AT_GNU_all_tail_call_sites	DW_FORM_flag_present
	DW_AT_sibling	DW_FORM_ref4

[3] DW_TAG_formal_parameter	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_decl_file	DW_FORM_data1
	DW_AT_decl_line	DW_FORM_data1
	DW_AT_decl_column	DW_FORM_data1
	DW_AT_type	DW_FORM_ref4
	DW_AT_location	DW_FORM_exprloc

[4] DW_TAG_variable	DW_CHILDREN_no
	DW_AT_name	DW_FORM_string
	DW_AT_decl_file	DW_FORM_data1
	DW_AT_decl_line	DW_FORM_data1
	DW_AT_decl_column	DW_FORM_data1
	DW_AT_type	DW_FORM_ref4
	DW_AT_location	DW_FORM_exprloc

[5] DW_TAG_lexical_block	DW_CHILDREN_yes
	DW_AT_low_pc	DW_FORM_addr
	DW_AT_high_pc	DW_FORM_data8

[6] DW_TAG_base_type	DW_CHILDREN_no
	DW_AT_byte_size	DW_FORM_data1
	DW_AT_encoding	DW_FORM_data1
	DW_AT_name	DW_FORM_string

[7] DW_TAG_pointer_type	DW_CHILDREN_no
	DW_AT_byte_size	DW_FORM_data1
	DW_AT_type	DW_FORM_ref4

[8] DW_TAG_base_type	DW_CHILDREN_no
	DW_AT_byte_size	DW_FORM_data1
	DW_AT_encoding	DW_FORM_data1
	DW_AT_name	DW_FORM_strp


.debug_info contents:
0x00000000: Compile Unit: length = 0x000000c9, format = DWARF32, version = 0x0004, abbr_offset = 0x0000, addr_size = 0x08 (next unit at 0x000000cd)

0x0000000b: DW_TAG_compile_unit
              DW_AT_producer	("GNU C17 14.2.1 20240805 -mtune=generic -march=x86-64 -g3 -gdwarf-4 -fno-eliminate-unused-debug-types")
              DW_AT_language	(DW_LANG_C99)
              DW_AT_name	("test.c")
              DW_AT_comp_dir	("/home/unvariant/code/tooling/pwnc/dwarf")
              DW_AT_low_pc	(0x0000000000001139)
              DW_AT_high_pc	(0x00000000000011eb)
              DW_AT_stmt_list	(0x00000000)
              DW_AT_GNU_macros	(0x00000000)

0x00000031:   DW_TAG_subprogram
                DW_AT_external	(true)
                DW_AT_name	("main")
                DW_AT_decl_file	("/home/unvariant/code/tooling/pwnc/dwarf/test.c")
                DW_AT_decl_line	(27)
                DW_AT_decl_column	(5)
                DW_AT_prototyped	(true)
                DW_AT_type	(0x000000ab "int")
                DW_AT_low_pc	(0x0000000000001139)
                DW_AT_high_pc	(0x00000000000011eb)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)
                DW_AT_GNU_all_tail_call_sites	(true)
                DW_AT_sibling	(0x000000ab)

0x00000053:     DW_TAG_formal_parameter
                  DW_AT_name	("argc")
                  DW_AT_decl_file	("/home/unvariant/code/tooling/pwnc/dwarf/test.c")
                  DW_AT_decl_line	(27)
                  DW_AT_decl_column	(14)
                  DW_AT_type	(0x000000ab "int")
                  DW_AT_location	(DW_OP_fbreg -52)

0x00000062:     DW_TAG_formal_parameter
                  DW_AT_name	("argv")
                  DW_AT_decl_file	("/home/unvariant/code/tooling/pwnc/dwarf/test.c")
                  DW_AT_decl_line	(27)
                  DW_AT_decl_column	(27)
                  DW_AT_type	(0x000000b2 "char **")
                  DW_AT_location	(DW_OP_fbreg -64)

0x00000071:     DW_TAG_variable
                  DW_AT_name	("b")
                  DW_AT_decl_file	("/home/unvariant/code/tooling/pwnc/dwarf/test.c")
                  DW_AT_decl_line	(28)
                  DW_AT_decl_column	(9)
                  DW_AT_type	(0x000000ab "int")
                  DW_AT_location	(DW_OP_fbreg -36)

0x0000007e:     DW_TAG_variable
                  DW_AT_name	("a")
                  DW_AT_decl_file	("/home/unvariant/code/tooling/pwnc/dwarf/test.c")
                  DW_AT_decl_line	(32)
                  DW_AT_decl_column	(12)
                  DW_AT_type	(0x000000c5 "double")
                  DW_AT_location	(DW_OP_fbreg -32)

0x0000008b:     DW_TAG_lexical_block
                  DW_AT_low_pc	(0x000000000000115e)
                  DW_AT_high_pc	(0x00000000000011c3)

0x0000009c:       DW_TAG_variable
                    DW_AT_name	("i")
                    DW_AT_decl_file	("/home/unvariant/code/tooling/pwnc/dwarf/test.c")
                    DW_AT_decl_line	(29)
                    DW_AT_decl_column	(14)
                    DW_AT_type	(0x000000ab "int")
                    DW_AT_location	(DW_OP_fbreg -40)

0x000000a9:       NULL

0x000000aa:     NULL

0x000000ab:   DW_TAG_base_type
                DW_AT_byte_size	(0x04)
                DW_AT_encoding	(DW_ATE_signed)
                DW_AT_name	("int")

0x000000b2:   DW_TAG_pointer_type
                DW_AT_byte_size	(0x08)
                DW_AT_type	(0x000000b8 "char *")

0x000000b8:   DW_TAG_pointer_type
                DW_AT_byte_size	(0x08)
                DW_AT_type	(0x000000be "char")

0x000000be:   DW_TAG_base_type
                DW_AT_byte_size	(0x01)
                DW_AT_encoding	(DW_ATE_signed_char)
                DW_AT_name	("char")

0x000000c5:   DW_TAG_base_type
                DW_AT_byte_size	(0x08)
                DW_AT_encoding	(DW_ATE_float)
                DW_AT_name	("double")

0x000000cc:   NULL

.eh_frame contents:

00000000 00000014 00000000 CIE
  Format:                DWARF32
  Version:               1
  Augmentation:          "zR"
  Code alignment factor: 1
  Data alignment factor: -8
  Return address column: 16
  Augmentation data:     1B

  DW_CFA_def_cfa: RSP +8
  DW_CFA_offset: RIP -8
  DW_CFA_nop:
  DW_CFA_nop:

  CFA=RSP+8: RIP=[CFA-8]

00000018 00000014 0000001c FDE cie=00000000 pc=00001040...00001066
  Format:       DWARF32
  DW_CFA_advance_loc: 4
  DW_CFA_undefined: RIP
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x1040: CFA=RSP+8: RIP=[CFA-8]
  0x1044: CFA=RSP+8: RIP=undefined

00000030 00000024 00000034 FDE cie=00000000 pc=00001020...00001040
  Format:       DWARF32
  DW_CFA_def_cfa_offset: +16
  DW_CFA_advance_loc: 6
  DW_CFA_def_cfa_offset: +24
  DW_CFA_advance_loc: 10
  DW_CFA_def_cfa_expression: DW_OP_breg7 RSP+8, DW_OP_breg16 RIP+0, DW_OP_lit15, DW_OP_and, DW_OP_lit11, DW_OP_ge, DW_OP_lit3, DW_OP_shl, DW_OP_plus
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x1020: CFA=RSP+16: RIP=[CFA-8]
  0x1026: CFA=RSP+24: RIP=[CFA-8]
  0x1030: CFA=DW_OP_breg7 RSP+8, DW_OP_breg16 RIP+0, DW_OP_lit15, DW_OP_and, DW_OP_lit11, DW_OP_ge, DW_OP_lit3, DW_OP_shl, DW_OP_plus: RIP=[CFA-8]

00000058 0000001c 0000005c FDE cie=00000000 pc=00001139...000011eb
  Format:       DWARF32
  DW_CFA_advance_loc: 1
  DW_CFA_def_cfa_offset: +16
  DW_CFA_offset: RBP -16
  DW_CFA_advance_loc: 3
  DW_CFA_def_cfa_register: RBP
  DW_CFA_advance_loc1: 173
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:

  0x1139: CFA=RSP+8: RIP=[CFA-8]
  0x113a: CFA=RSP+16: RBP=[CFA-16], RIP=[CFA-8]
  0x113d: CFA=RBP+16: RBP=[CFA-16], RIP=[CFA-8]
  0x11ea: CFA=RSP+8: RBP=[CFA-16], RIP=[CFA-8]

00000078 ZERO terminator

.debug_macro contents:
0x00000000:
macro header: version = 0x0004, flags = 0x02, format = DWARF32, debug_line_offset = 0x00000000
DW_MACRO_GNU_transparent_include - import offset: 0x0000001a
DW_MACRO_GNU_start_file - lineno: 0 filenum: 1
  DW_MACRO_GNU_start_file - lineno: 0 filenum: 2
    DW_MACRO_GNU_transparent_include - import offset: 0x00000960
  DW_MACRO_GNU_end_file
DW_MACRO_GNU_end_file

0x0000001a:
macro header: version = 0x0004, flags = 0x00, format = DWARF32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __STDC__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __STDC_VERSION__ 201710L
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __STDC_UTF_16__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __STDC_UTF_32__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __STDC_HOSTED__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GNUC__ 14
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GNUC_MINOR__ 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GNUC_PATCHLEVEL__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __VERSION__ "14.2.1 20240805"
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ATOMIC_RELAXED 0
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ATOMIC_SEQ_CST 5
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ATOMIC_ACQUIRE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ATOMIC_RELEASE 3
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ATOMIC_ACQ_REL 4
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ATOMIC_CONSUME 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __pic__ 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __PIC__ 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __pie__ 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __PIE__ 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FINITE_MATH_ONLY__ 0
DW_MACRO_GNU_define_indirect - lineno: 0 macro: _LP64 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LP64__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_INT__ 4
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_LONG__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_LONG_LONG__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_SHORT__ 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_FLOAT__ 4
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_DOUBLE__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_LONG_DOUBLE__ 16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_SIZE_T__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __CHAR_BIT__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BIGGEST_ALIGNMENT__ 16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ORDER_LITTLE_ENDIAN__ 1234
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ORDER_BIG_ENDIAN__ 4321
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ORDER_PDP_ENDIAN__ 3412
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLOAT_WORD_ORDER__ __ORDER_LITTLE_ENDIAN__
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_POINTER__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GNUC_EXECUTION_CHARSET_NAME "UTF-8"
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GNUC_WIDE_EXECUTION_CHARSET_NAME "UTF-32LE"
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZE_TYPE__ long unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __PTRDIFF_TYPE__ long int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __WCHAR_TYPE__ int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __WINT_TYPE__ unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INTMAX_TYPE__ long int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINTMAX_TYPE__ long unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __CHAR16_TYPE__ short unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __CHAR32_TYPE__ unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIG_ATOMIC_TYPE__ int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT8_TYPE__ signed char
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT16_TYPE__ short int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT32_TYPE__ int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT64_TYPE__ long int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT8_TYPE__ unsigned char
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT16_TYPE__ short unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT32_TYPE__ unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT64_TYPE__ long unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST8_TYPE__ signed char
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST16_TYPE__ short int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST32_TYPE__ int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST64_TYPE__ long int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_LEAST8_TYPE__ unsigned char
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_LEAST16_TYPE__ short unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_LEAST32_TYPE__ unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_LEAST64_TYPE__ long unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST8_TYPE__ signed char
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST16_TYPE__ long int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST32_TYPE__ long int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST64_TYPE__ long int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_FAST8_TYPE__ unsigned char
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_FAST16_TYPE__ long unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_FAST32_TYPE__ long unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_FAST64_TYPE__ long unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INTPTR_TYPE__ long int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINTPTR_TYPE__ long unsigned int
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GXX_ABI_VERSION 1019
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SCHAR_MAX__ 0x7f
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SHRT_MAX__ 0x7fff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_MAX__ 0x7fffffff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LONG_MAX__ 0x7fffffffffffffffL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LONG_LONG_MAX__ 0x7fffffffffffffffLL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __WCHAR_MAX__ 0x7fffffff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __WCHAR_MIN__ (-__WCHAR_MAX__ - 1)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __WINT_MAX__ 0xffffffffU
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __WINT_MIN__ 0U
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __PTRDIFF_MAX__ 0x7fffffffffffffffL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZE_MAX__ 0xffffffffffffffffUL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SCHAR_WIDTH__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SHRT_WIDTH__ 16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_WIDTH__ 32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LONG_WIDTH__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LONG_LONG_WIDTH__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __WCHAR_WIDTH__ 32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __WINT_WIDTH__ 32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __PTRDIFF_WIDTH__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZE_WIDTH__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BITINT_MAXWIDTH__ 65535
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INTMAX_MAX__ 0x7fffffffffffffffL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INTMAX_C(c) c ## L
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINTMAX_MAX__ 0xffffffffffffffffUL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINTMAX_C(c) c ## UL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INTMAX_WIDTH__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIG_ATOMIC_MAX__ 0x7fffffff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIG_ATOMIC_MIN__ (-__SIG_ATOMIC_MAX__ - 1)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIG_ATOMIC_WIDTH__ 32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT8_MAX__ 0x7f
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT16_MAX__ 0x7fff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT32_MAX__ 0x7fffffff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT64_MAX__ 0x7fffffffffffffffL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT8_MAX__ 0xff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT16_MAX__ 0xffff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT32_MAX__ 0xffffffffU
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT64_MAX__ 0xffffffffffffffffUL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST8_MAX__ 0x7f
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT8_C(c) c
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST8_WIDTH__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST16_MAX__ 0x7fff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT16_C(c) c
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST16_WIDTH__ 16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST32_MAX__ 0x7fffffff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT32_C(c) c
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST32_WIDTH__ 32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST64_MAX__ 0x7fffffffffffffffL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT64_C(c) c ## L
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_LEAST64_WIDTH__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_LEAST8_MAX__ 0xff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT8_C(c) c
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_LEAST16_MAX__ 0xffff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT16_C(c) c
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_LEAST32_MAX__ 0xffffffffU
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT32_C(c) c ## U
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_LEAST64_MAX__ 0xffffffffffffffffUL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT64_C(c) c ## UL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST8_MAX__ 0x7f
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST8_WIDTH__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST16_MAX__ 0x7fffffffffffffffL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST16_WIDTH__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST32_MAX__ 0x7fffffffffffffffL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST32_WIDTH__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST64_MAX__ 0x7fffffffffffffffL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INT_FAST64_WIDTH__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_FAST8_MAX__ 0xff
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_FAST16_MAX__ 0xffffffffffffffffUL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_FAST32_MAX__ 0xffffffffffffffffUL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINT_FAST64_MAX__ 0xffffffffffffffffUL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INTPTR_MAX__ 0x7fffffffffffffffL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __INTPTR_WIDTH__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __UINTPTR_MAX__ 0xffffffffffffffffUL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_IEC_559 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_IEC_559_COMPLEX 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_EVAL_METHOD__ 0
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_EVAL_METHOD_TS_18661_3__ 0
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC_EVAL_METHOD__ 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_RADIX__ 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_MANT_DIG__ 24
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_DIG__ 6
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_MIN_EXP__ (-125)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_MIN_10_EXP__ (-37)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_MAX_EXP__ 128
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_MAX_10_EXP__ 38
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_DECIMAL_DIG__ 9
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_MAX__ 3.40282346638528859811704183484516925e+38F
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_NORM_MAX__ 3.40282346638528859811704183484516925e+38F
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_MIN__ 1.17549435082228750796873653722224568e-38F
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_EPSILON__ 1.19209289550781250000000000000000000e-7F
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_DENORM_MIN__ 1.40129846432481707092372958328991613e-45F
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_HAS_DENORM__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_HAS_INFINITY__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_HAS_QUIET_NAN__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT_IS_IEC_60559__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_MANT_DIG__ 53
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_DIG__ 15
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_MIN_EXP__ (-1021)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_MIN_10_EXP__ (-307)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_MAX_EXP__ 1024
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_MAX_10_EXP__ 308
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_DECIMAL_DIG__ 17
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_MAX__ ((double)1.79769313486231570814527423731704357e+308L)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_NORM_MAX__ ((double)1.79769313486231570814527423731704357e+308L)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_MIN__ ((double)2.22507385850720138309023271733240406e-308L)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_EPSILON__ ((double)2.22044604925031308084726333618164062e-16L)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_DENORM_MIN__ ((double)4.94065645841246544176568792868221372e-324L)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_HAS_DENORM__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_HAS_INFINITY__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_HAS_QUIET_NAN__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DBL_IS_IEC_60559__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_MANT_DIG__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_DIG__ 18
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_MIN_EXP__ (-16381)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_MIN_10_EXP__ (-4931)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_MAX_EXP__ 16384
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_MAX_10_EXP__ 4932
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DECIMAL_DIG__ 21
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_DECIMAL_DIG__ 21
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_MAX__ 1.18973149535723176502126385303097021e+4932L
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_NORM_MAX__ 1.18973149535723176502126385303097021e+4932L
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_MIN__ 3.36210314311209350626267781732175260e-4932L
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_EPSILON__ 1.08420217248550443400745280086994171e-19L
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_DENORM_MIN__ 3.64519953188247460252840593361941982e-4951L
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_HAS_DENORM__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_HAS_INFINITY__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_HAS_QUIET_NAN__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __LDBL_IS_IEC_60559__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_MANT_DIG__ 11
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_DIG__ 3
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_MIN_EXP__ (-13)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_MIN_10_EXP__ (-4)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_MAX_EXP__ 16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_MAX_10_EXP__ 4
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_DECIMAL_DIG__ 5
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_MAX__ 6.55040000000000000000000000000000000e+4F16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_NORM_MAX__ 6.55040000000000000000000000000000000e+4F16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_MIN__ 6.10351562500000000000000000000000000e-5F16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_EPSILON__ 9.76562500000000000000000000000000000e-4F16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_DENORM_MIN__ 5.96046447753906250000000000000000000e-8F16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_HAS_DENORM__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_HAS_INFINITY__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_HAS_QUIET_NAN__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT16_IS_IEC_60559__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_MANT_DIG__ 24
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_DIG__ 6
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_MIN_EXP__ (-125)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_MIN_10_EXP__ (-37)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_MAX_EXP__ 128
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_MAX_10_EXP__ 38
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_DECIMAL_DIG__ 9
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_MAX__ 3.40282346638528859811704183484516925e+38F32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_NORM_MAX__ 3.40282346638528859811704183484516925e+38F32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_MIN__ 1.17549435082228750796873653722224568e-38F32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_EPSILON__ 1.19209289550781250000000000000000000e-7F32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_DENORM_MIN__ 1.40129846432481707092372958328991613e-45F32
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_HAS_DENORM__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_HAS_INFINITY__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_HAS_QUIET_NAN__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32_IS_IEC_60559__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_MANT_DIG__ 53
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_DIG__ 15
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_MIN_EXP__ (-1021)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_MIN_10_EXP__ (-307)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_MAX_EXP__ 1024
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_MAX_10_EXP__ 308
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_DECIMAL_DIG__ 17
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_MAX__ 1.79769313486231570814527423731704357e+308F64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_NORM_MAX__ 1.79769313486231570814527423731704357e+308F64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_MIN__ 2.22507385850720138309023271733240406e-308F64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_EPSILON__ 2.22044604925031308084726333618164062e-16F64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_DENORM_MIN__ 4.94065645841246544176568792868221372e-324F64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_HAS_DENORM__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_HAS_INFINITY__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_HAS_QUIET_NAN__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64_IS_IEC_60559__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_MANT_DIG__ 113
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_DIG__ 33
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_MIN_EXP__ (-16381)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_MIN_10_EXP__ (-4931)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_MAX_EXP__ 16384
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_MAX_10_EXP__ 4932
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_DECIMAL_DIG__ 36
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_MAX__ 1.18973149535723176508575932662800702e+4932F128
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_NORM_MAX__ 1.18973149535723176508575932662800702e+4932F128
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_MIN__ 3.36210314311209350626267781732175260e-4932F128
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_EPSILON__ 1.92592994438723585305597794258492732e-34F128
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_DENORM_MIN__ 6.47517511943802511092443895822764655e-4966F128
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_HAS_DENORM__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_HAS_INFINITY__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_HAS_QUIET_NAN__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT128_IS_IEC_60559__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_MANT_DIG__ 53
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_DIG__ 15
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_MIN_EXP__ (-1021)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_MIN_10_EXP__ (-307)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_MAX_EXP__ 1024
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_MAX_10_EXP__ 308
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_DECIMAL_DIG__ 17
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_MAX__ 1.79769313486231570814527423731704357e+308F32x
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_NORM_MAX__ 1.79769313486231570814527423731704357e+308F32x
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_MIN__ 2.22507385850720138309023271733240406e-308F32x
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_EPSILON__ 2.22044604925031308084726333618164062e-16F32x
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_DENORM_MIN__ 4.94065645841246544176568792868221372e-324F32x
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_HAS_DENORM__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_HAS_INFINITY__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_HAS_QUIET_NAN__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT32X_IS_IEC_60559__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_MANT_DIG__ 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_DIG__ 18
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_MIN_EXP__ (-16381)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_MIN_10_EXP__ (-4931)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_MAX_EXP__ 16384
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_MAX_10_EXP__ 4932
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_DECIMAL_DIG__ 21
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_MAX__ 1.18973149535723176502126385303097021e+4932F64x
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_NORM_MAX__ 1.18973149535723176502126385303097021e+4932F64x
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_MIN__ 3.36210314311209350626267781732175260e-4932F64x
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_EPSILON__ 1.08420217248550443400745280086994171e-19F64x
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_DENORM_MIN__ 3.64519953188247460252840593361941982e-4951F64x
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_HAS_DENORM__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_HAS_INFINITY__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_HAS_QUIET_NAN__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FLT64X_IS_IEC_60559__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_MANT_DIG__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_DIG__ 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_MIN_EXP__ (-125)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_MIN_10_EXP__ (-37)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_MAX_EXP__ 128
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_MAX_10_EXP__ 38
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_DECIMAL_DIG__ 4
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_MAX__ 3.38953138925153547590470800371487867e+38BF16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_NORM_MAX__ 3.38953138925153547590470800371487867e+38BF16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_MIN__ 1.17549435082228750796873653722224568e-38BF16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_EPSILON__ 7.81250000000000000000000000000000000e-3BF16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_DENORM_MIN__ 9.18354961579912115600575419704879436e-41BF16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_HAS_DENORM__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_HAS_INFINITY__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_HAS_QUIET_NAN__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __BFLT16_IS_IEC_60559__ 0
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC32_MANT_DIG__ 7
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC32_MIN_EXP__ (-94)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC32_MAX_EXP__ 97
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC32_MIN__ 1E-95DF
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC32_MAX__ 9.999999E96DF
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC32_EPSILON__ 1E-6DF
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC32_SUBNORMAL_MIN__ 0.000001E-95DF
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC64_MANT_DIG__ 16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC64_MIN_EXP__ (-382)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC64_MAX_EXP__ 385
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC64_MIN__ 1E-383DD
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC64_MAX__ 9.999999999999999E384DD
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC64_EPSILON__ 1E-15DD
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC64_SUBNORMAL_MIN__ 0.000000000000001E-383DD
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC128_MANT_DIG__ 34
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC128_MIN_EXP__ (-6142)
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC128_MAX_EXP__ 6145
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC128_MIN__ 1E-6143DL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC128_MAX__ 9.999999999999999999999999999999999E6144DL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC128_EPSILON__ 1E-33DL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DEC128_SUBNORMAL_MIN__ 0.000000000000000000000000000000001E-6143DL
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __REGISTER_PREFIX__ 
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __USER_LABEL_PREFIX__ 
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GNUC_STDC_INLINE__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __NO_INLINE__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_HAVE_SYNC_COMPARE_AND_SWAP_1 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_HAVE_SYNC_COMPARE_AND_SWAP_2 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_HAVE_SYNC_COMPARE_AND_SWAP_4 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_BOOL_LOCK_FREE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_CHAR_LOCK_FREE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_CHAR16_T_LOCK_FREE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_CHAR32_T_LOCK_FREE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_WCHAR_T_LOCK_FREE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_SHORT_LOCK_FREE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_INT_LOCK_FREE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_LONG_LOCK_FREE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_LLONG_LOCK_FREE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_TEST_AND_SET_TRUEVAL 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_DESTRUCTIVE_SIZE 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_CONSTRUCTIVE_SIZE 64
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ATOMIC_POINTER_LOCK_FREE 2
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __HAVE_SPECULATION_SAFE_VALUE 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_HAVE_DWARF2_CFI_ASM 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __PRAGMA_REDEFINE_EXTNAME 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SSP_STRONG__ 3
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_INT128__ 16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_WCHAR_T__ 4
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_WINT_T__ 4
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_PTRDIFF_T__ 8
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __amd64 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __amd64__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __x86_64 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __x86_64__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_FLOAT80__ 16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SIZEOF_FLOAT128__ 16
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ATOMIC_HLE_ACQUIRE 65536
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ATOMIC_HLE_RELEASE 131072
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __GCC_ASM_FLAG_OUTPUTS__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __k8 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __k8__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __code_model_small__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __MMX__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SSE__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SSE2__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __FXSR__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SSE_MATH__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SSE2_MATH__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __MMX_WITH_SSE__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SEG_FS 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __SEG_GS 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __gnu_linux__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __linux 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __linux__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: linux 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __unix 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __unix__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: unix 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __ELF__ 1
DW_MACRO_GNU_define_indirect - lineno: 0 macro: __DECIMAL_BID_FORMAT__ 1

0x00000960:
macro header: version = 0x0004, flags = 0x00, format = DWARF32
DW_MACRO_GNU_define_indirect - lineno: 19 macro: _STDC_PREDEF_H 1
DW_MACRO_GNU_define_indirect - lineno: 38 macro: __STDC_IEC_559__ 1
DW_MACRO_GNU_define_indirect - lineno: 39 macro: __STDC_IEC_60559_BFP__ 201404L
DW_MACRO_GNU_define_indirect - lineno: 48 macro: __STDC_IEC_559_COMPLEX__ 1
DW_MACRO_GNU_define_indirect - lineno: 49 macro: __STDC_IEC_60559_COMPLEX__ 201404L
DW_MACRO_GNU_define_indirect - lineno: 62 macro: __STDC_ISO_10646__ 201706L


.debug_aranges contents:
Address Range Header: length = 0x0000002c, format = DWARF32, version = 0x0002, cu_offset = 0x00000000, addr_size = 0x08, seg_size = 0x00
[0x0000000000001139, 0x00000000000011eb)

.debug_line contents:
debug_line[0x00000000]
Line table prologue:
    total_length: 0x00000089
          format: DWARF32
         version: 4
 prologue_length: 0x0000003c
 min_inst_length: 1
max_ops_per_inst: 1
 default_is_stmt: 1
       line_base: -5
      line_range: 14
     opcode_base: 13
standard_opcode_lengths[DW_LNS_copy] = 0
standard_opcode_lengths[DW_LNS_advance_pc] = 1
standard_opcode_lengths[DW_LNS_advance_line] = 1
standard_opcode_lengths[DW_LNS_set_file] = 1
standard_opcode_lengths[DW_LNS_set_column] = 1
standard_opcode_lengths[DW_LNS_negate_stmt] = 0
standard_opcode_lengths[DW_LNS_set_basic_block] = 0
standard_opcode_lengths[DW_LNS_const_add_pc] = 0
standard_opcode_lengths[DW_LNS_fixed_advance_pc] = 1
standard_opcode_lengths[DW_LNS_set_prologue_end] = 0
standard_opcode_lengths[DW_LNS_set_epilogue_begin] = 0
standard_opcode_lengths[DW_LNS_set_isa] = 1
include_directories[  1] = "/usr/include"
file_names[  1]:
           name: "test.c"
      dir_index: 0
       mod_time: 0x00000000
         length: 0x00000000
file_names[  2]:
           name: "stdc-predef.h"
      dir_index: 1
       mod_time: 0x00000000
         length: 0x00000000

Address            Line   Column File   ISA Discriminator OpIndex Flags
------------------ ------ ------ ------ --- ------------- ------- -------------
0x0000000000001139     27     33      1   0             0       0  is_stmt
0x0000000000001148     27     33      1   0             0       0  is_stmt
0x0000000000001157     28      9      1   0             0       0  is_stmt
0x000000000000115e     29     14      1   0             0       0  is_stmt
0x0000000000001165     29      5      1   0             0       0  is_stmt
0x0000000000001167     30     27      1   0             0       0  is_stmt
0x000000000000116c     30     13      1   0             0       0  is_stmt
0x0000000000001181     30     27      1   0             0       0  is_stmt
0x00000000000011b4     30     17      1   0             1       0  is_stmt
0x00000000000011b7     29     32      1   0             3       0  is_stmt
0x00000000000011bb     29     23      1   0             1       0  is_stmt
0x00000000000011c3     32     12      1   0             0       0  is_stmt
0x00000000000011d5     33      1      1   0             0       0  is_stmt
0x00000000000011eb     33      1      1   0             0       0  is_stmt end_sequence


.debug_str contents:
0x00000000: "__SIG_ATOMIC_MAX__ 0x7fffffff"
0x0000001e: "__FLT64_HAS_QUIET_NAN__ 1"
0x00000038: "__DEC64_SUBNORMAL_MIN__ 0.000000000000001E-383DD"
0x00000069: "__FLT16_MIN_10_EXP__ (-4)"
0x00000083: "__FLT32_HAS_INFINITY__ 1"
0x0000009c: "__FLT64_MAX_EXP__ 1024"
0x000000b3: "__FLT_MIN_10_EXP__ (-37)"
0x000000cc: "__FLT64X_EPSILON__ 1.08420217248550443400745280086994171e-19F64x"
0x0000010d: "__FLT32X_MAX_EXP__ 1024"
0x00000125: "__GCC_ATOMIC_TEST_AND_SET_TRUEVAL 1"
0x00000149: "__DEC64_EPSILON__ 1E-15DD"
0x00000163: "__DBL_DENORM_MIN__ ((double)4.94065645841246544176568792868221372e-324L)"
0x000001ac: "__INTPTR_MAX__ 0x7fffffffffffffffL"
0x000001cf: "__FLT32_MANT_DIG__ 24"
0x000001e5: "test.c"
0x000001ec: "__ATOMIC_RELEASE 3"
0x000001ff: "__DECIMAL_BID_FORMAT__ 1"
0x00000218: "__FLT32X_DECIMAL_DIG__ 17"
0x00000232: "__k8__ 1"
0x0000023b: "__DBL_MIN_EXP__ (-1021)"
0x00000253: "__GCC_ATOMIC_CHAR16_T_LOCK_FREE 2"
0x00000275: "__FLT32X_MAX__ 1.79769313486231570814527423731704357e+308F32x"
0x000002b3: "__SIZEOF_WINT_T__ 4"
0x000002c7: "__FLT128_NORM_MAX__ 1.18973149535723176508575932662800702e+4932F128"
0x0000030b: "__GNUC_MINOR__ 2"
0x0000031c: "__FLT32_NORM_MAX__ 3.40282346638528859811704183484516925e+38F32"
0x0000035c: "__UINT64_MAX__ 0xffffffffffffffffUL"
0x00000380: "__ATOMIC_HLE_ACQUIRE 65536"
0x0000039b: "__GNUC__ 14"
0x000003a7: "__FLT64_MIN__ 2.22507385850720138309023271733240406e-308F64"
0x000003e3: "__LONG_LONG_WIDTH__ 64"
0x000003fa: "__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8 1"
0x0000041f: "__FLT_DENORM_MIN__ 1.40129846432481707092372958328991613e-45F"
0x0000045d: "__BFLT16_MIN_EXP__ (-125)"
0x00000477: "__SIZEOF_SIZE_T__ 8"
0x0000048b: "argc"
0x00000490: "__ORDER_BIG_ENDIAN__ 4321"
0x000004aa: "__GCC_CONSTRUCTIVE_SIZE 64"
0x000004c5: "__DEC128_MIN__ 1E-6143DL"
0x000004de: "__UINT64_C(c) c ## UL"
0x000004f4: "__UINT8_C(c) c"
0x00000503: "__DBL_MANT_DIG__ 53"
0x00000517: "__INT_MAX__ 0x7fffffff"
0x0000052e: "__FLT_IS_IEC_60559__ 1"
0x00000545: "__FLT16_DIG__ 3"
0x00000555: "__INT16_TYPE__ short int"
0x0000056e: "__FLT16_IS_IEC_60559__ 1"
0x00000587: "__DEC32_EPSILON__ 1E-6DF"
0x000005a0: "__BFLT16_DENORM_MIN__ 9.18354961579912115600575419704879436e-41BF16"
0x000005e4: "__LDBL_DIG__ 18"
0x000005f4: "__FLT64X_MAX_EXP__ 16384"
0x0000060d: "__ATOMIC_SEQ_CST 5"
0x00000620: "__SIZEOF_SHORT__ 2"
0x00000633: "__UINT64_TYPE__ long unsigned int"
0x00000655: "__INT_FAST32_MAX__ 0x7fffffffffffffffL"
0x0000067c: "__INT_LEAST8_TYPE__ signed char"
0x0000069c: "__UINT_LEAST32_TYPE__ unsigned int"
0x000006bf: "__UINT_FAST32_TYPE__ long unsigned int"
0x000006e6: "__BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__"
0x0000070d: "__LDBL_MIN__ 3.36210314311209350626267781732175260e-4932L"
0x00000747: "__FLT32_MIN_10_EXP__ (-37)"
0x00000762: "__DBL_HAS_DENORM__ 1"
0x00000777: "__INT_LEAST64_TYPE__ long int"
0x00000795: "__WCHAR_MIN__ (-__WCHAR_MAX__ - 1)"
0x000007b8: "__STDC_UTF_32__ 1"
0x000007ca: "__INT_LEAST16_MAX__ 0x7fff"
0x000007e5: "__SCHAR_MAX__ 0x7f"
0x000007f8: "__GNUC_EXECUTION_CHARSET_NAME \"UTF-8\""
0x0000081e: "__FLT64_DIG__ 15"
0x0000082f: "__INT_FAST8_TYPE__ signed char"
0x0000084e: "__PIE__ 2"
0x00000858: "__LDBL_IS_IEC_60559__ 1"
0x00000870: "__FLT32X_HAS_INFINITY__ 1"
0x0000088a: "__MMX_WITH_SSE__ 1"
0x0000089d: "__UINT_LEAST8_TYPE__ unsigned char"
0x000008c0: "__SIZEOF_INT128__ 16"
0x000008d5: "__INT8_C(c) c"
0x000008e3: "__FLT128_MAX__ 1.18973149535723176508575932662800702e+4932F128"
0x00000922: "__UINTMAX_MAX__ 0xffffffffffffffffUL"
0x00000947: "__INT_LEAST32_TYPE__ int"
0x00000960: "__INT_LEAST16_WIDTH__ 16"
0x00000979: "__FLT64_IS_IEC_60559__ 1"
0x00000992: "__VERSION__ \"14.2.1 20240805\""
0x000009b0: "__FLT32_HAS_DENORM__ 1"
0x000009c7: "__unix__ 1"
0x000009d2: "__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1 1"
0x000009f7: "__INT_FAST32_TYPE__ long int"
0x00000a14: "__FLT_DIG__ 6"
0x00000a22: "__INT_FAST16_WIDTH__ 64"
0x00000a3a: "__pie__ 2"
0x00000a44: "__FLT16_MANT_DIG__ 11"
0x00000a5a: "__BFLT16_MAX__ 3.38953138925153547590470800371487867e+38BF16"
0x00000a97: "__UINTPTR_MAX__ 0xffffffffffffffffUL"
0x00000abc: "__INTMAX_MAX__ 0x7fffffffffffffffL"
0x00000adf: "__STDC_IEC_60559_COMPLEX__ 201404L"
0x00000b02: "__GCC_IEC_559 2"
0x00000b12: "__FLT128_MIN_EXP__ (-16381)"
0x00000b2e: "__FLT32_HAS_QUIET_NAN__ 1"
0x00000b48: "__UINT_LEAST16_MAX__ 0xffff"
0x00000b64: "__UINT_FAST64_MAX__ 0xffffffffffffffffUL"
0x00000b8d: "__LDBL_NORM_MAX__ 1.18973149535723176502126385303097021e+4932L"
0x00000bcc: "/home/unvariant/code/tooling/pwnc/dwarf"
0x00000bf4: "__UINT_LEAST8_MAX__ 0xff"
0x00000c0d: "__DEC128_MIN_EXP__ (-6142)"
0x00000c28: "__WCHAR_TYPE__ int"
0x00000c3b: "__INT8_MAX__ 0x7f"
0x00000c4d: "__DEC128_EPSILON__ 1E-33DL"
0x00000c68: "__BFLT16_IS_IEC_60559__ 0"
0x00000c82: "__FLT128_MAX_EXP__ 16384"
0x00000c9b: "__FLT_RADIX__ 2"
0x00000cab: "__FLT32X_DENORM_MIN__ 4.94065645841246544176568792868221372e-324F32x"
0x00000cf0: "__BFLT16_DECIMAL_DIG__ 4"
0x00000d09: "__SIZEOF_LONG_DOUBLE__ 16"
0x00000d23: "__DBL_HAS_QUIET_NAN__ 1"
0x00000d3b: "__FLT64X_IS_IEC_60559__ 1"
0x00000d55: "__LDBL_DENORM_MIN__ 3.64519953188247460252840593361941982e-4951L"
0x00000d96: "__FLT64_HAS_INFINITY__ 1"
0x00000daf: "__UINT_FAST8_MAX__ 0xff"
0x00000dc7: "__ATOMIC_HLE_RELEASE 131072"
0x00000de3: "__LDBL_MAX_EXP__ 16384"
0x00000dfa: "__INTMAX_TYPE__ long int"
0x00000e13: "__INTPTR_TYPE__ long int"
0x00000e2c: "__DEC64_MAX__ 9.999999999999999E384DD"
0x00000e52: "__GCC_ATOMIC_INT_LOCK_FREE 2"
0x00000e6f: "__MMX__ 1"
0x00000e79: "__FLT64X_DIG__ 18"
0x00000e8b: "__INT_LEAST64_WIDTH__ 64"
0x00000ea4: "__FLT128_MANT_DIG__ 113"
0x00000ebc: "__ORDER_LITTLE_ENDIAN__ 1234"
0x00000ed9: "__SIZEOF_PTRDIFF_T__ 8"
0x00000ef0: "__DEC128_MANT_DIG__ 34"
0x00000f07: "__INT32_TYPE__ int"
0x00000f1a: "__code_model_small__ 1"
0x00000f31: "__FLT64X_HAS_DENORM__ 1"
0x00000f49: "__x86_64 1"
0x00000f54: "__FLT16_DENORM_MIN__ 5.96046447753906250000000000000000000e-8F16"
0x00000f95: "__BFLT16_DIG__ 2"
0x00000fa6: "__STDC_IEC_559_COMPLEX__ 1"
0x00000fc1: "__FLT64X_MIN_10_EXP__ (-4931)"
0x00000fdf: "__STDC_ISO_10646__ 201706L"
0x00000ffa: "__HAVE_SPECULATION_SAFE_VALUE 1"
0x0000101a: "__FLT128_MAX_10_EXP__ 4932"
0x00001035: "__FLT128_MIN__ 3.36210314311209350626267781732175260e-4932F128"
0x00001074: "__INT_FAST8_WIDTH__ 8"
0x0000108a: "__FLT64_MIN_10_EXP__ (-307)"
0x000010a6: "__DBL_MAX__ ((double)1.79769313486231570814527423731704357e+308L)"
0x000010e8: "__amd64__ 1"
0x000010f4: "__FLT16_MIN_EXP__ (-13)"
0x0000110c: "__FLT32_DECIMAL_DIG__ 9"
0x00001124: "__FLT128_DIG__ 33"
0x00001136: "__UINT16_TYPE__ short unsigned int"
0x00001159: "__WCHAR_WIDTH__ 32"
0x0000116c: "__GCC_ATOMIC_CHAR_LOCK_FREE 2"
0x0000118a: "__BIGGEST_ALIGNMENT__ 16"
0x000011a3: "__LONG_LONG_MAX__ 0x7fffffffffffffffLL"
0x000011ca: "__UINT_LEAST16_TYPE__ short unsigned int"
0x000011f3: "__FLT_MAX_10_EXP__ 38"
0x00001209: "__LONG_MAX__ 0x7fffffffffffffffL"
0x0000122a: "__FLT32X_EPSILON__ 2.22044604925031308084726333618164062e-16F32x"
0x0000126b: "__FLT16_MAX_EXP__ 16"
0x00001280: "argv"
0x00001285: "__NO_INLINE__ 1"
0x00001295: "__FLT_MANT_DIG__ 24"
0x000012a9: "__FLT64_DECIMAL_DIG__ 17"
0x000012c2: "__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4 1"
0x000012e7: "__FLT32_MIN_EXP__ (-125)"
0x00001300: "__SIZE_TYPE__ long unsigned int"
0x00001320: "__LDBL_MAX__ 1.18973149535723176502126385303097021e+4932L"
0x0000135a: "__DEC_EVAL_METHOD__ 2"
0x00001370: "__FLT_MAX__ 3.40282346638528859811704183484516925e+38F"
0x000013a7: "__DBL_MIN_10_EXP__ (-307)"
0x000013c1: "__FLT128_HAS_INFINITY__ 1"
0x000013db: "__FLT32_DIG__ 6"
0x000013eb: "__GXX_ABI_VERSION 1019"
0x00001402: "__FLT64_HAS_DENORM__ 1"
0x00001419: "__FLT_EVAL_METHOD__ 0"
0x0000142f: "__FLT64X_NORM_MAX__ 1.18973149535723176502126385303097021e+4932F64x"
0x00001473: "__FLT32X_HAS_DENORM__ 1"
0x0000148b: "__x86_64__ 1"
0x00001498: "__INTMAX_C(c) c ## L"
0x000014ad: "__FLT64X_MAX__ 1.18973149535723176502126385303097021e+4932F64x"
0x000014ec: "__GCC_ATOMIC_WCHAR_T_LOCK_FREE 2"
0x0000150d: "__INT_LEAST64_MAX__ 0x7fffffffffffffffL"
0x00001535: "__INT_LEAST8_WIDTH__ 8"
0x0000154c: "__UINT8_MAX__ 0xff"
0x0000155f: "__UINT16_MAX__ 0xffff"
0x00001575: "__INT_FAST64_TYPE__ long int"
0x00001592: "__FLT16_MIN__ 6.10351562500000000000000000000000000e-5F16"
0x000015cc: "__UINT32_MAX__ 0xffffffffU"
0x000015e7: "__INTMAX_WIDTH__ 64"
0x000015fb: "__DEC32_MAX__ 9.999999E96DF"
0x00001617: "__DBL_IS_IEC_60559__ 1"
0x0000162e: "__PTRDIFF_MAX__ 0x7fffffffffffffffL"
0x00001652: "__INT_LEAST16_TYPE__ short int"
0x00001671: "__FLT32_MAX_EXP__ 128"
0x00001687: "__gnu_linux__ 1"
0x00001697: "__SIZEOF_FLOAT128__ 16"
0x000016ae: "__DBL_DIG__ 15"
0x000016bd: "__INT_LEAST8_MAX__ 0x7f"
0x000016d5: "__LP64__ 1"
0x000016e0: "__GCC_ATOMIC_LONG_LOCK_FREE 2"
0x000016fe: "__FLT32X_DIG__ 15"
0x00001710: "__FLT32X_MANT_DIG__ 53"
0x00001727: "_LP64 1"
0x0000172f: "__FLT64X_MAX_10_EXP__ 4932"
0x0000174a: "__DBL_MIN__ ((double)2.22507385850720138309023271733240406e-308L)"
0x0000178c: "__GCC_ATOMIC_BOOL_LOCK_FREE 2"
0x000017aa: "__UINT_FAST32_MAX__ 0xffffffffffffffffUL"
0x000017d3: "__FINITE_MATH_ONLY__ 0"
0x000017ea: "__FLT64_MAX__ 1.79769313486231570814527423731704357e+308F64"
0x00001826: "GNU C17 14.2.1 20240805 -mtune=generic -march=x86-64 -g3 -gdwarf-4 -fno-eliminate-unused-debug-types"
0x0000188b: "__GCC_ASM_FLAG_OUTPUTS__ 1"
0x000018a6: "__UINT_LEAST64_MAX__ 0xffffffffffffffffUL"
0x000018d0: "__ELF__ 1"
0x000018da: "__FLT32X_MIN__ 2.22507385850720138309023271733240406e-308F32x"
0x00001918: "__UINTPTR_TYPE__ long unsigned int"
0x0000193b: "__INT16_C(c) c"
0x0000194a: "__GCC_HAVE_DWARF2_CFI_ASM 1"
0x00001966: "__SIZEOF_FLOAT__ 4"
0x00001979: "__DEC32_SUBNORMAL_MIN__ 0.000001E-95DF"
0x000019a0: "__FLT64X_HAS_QUIET_NAN__ 1"
0x000019bb: "__FLT_HAS_INFINITY__ 1"
0x000019d2: "__BFLT16_MAX_10_EXP__ 38"
0x000019eb: "__FLT16_HAS_INFINITY__ 1"
0x00001a04: "__STDC__ 1"
0x00001a0f: "__SSE2__ 1"
0x00001a1a: "__DBL_MAX_EXP__ 1024"
0x00001a2f: "__SIZEOF_LONG__ 8"
0x00001a41: "__ATOMIC_CONSUME 1"
0x00001a54: "__BFLT16_EPSILON__ 7.81250000000000000000000000000000000e-3BF16"
0x00001a94: "__FLT32_MIN__ 1.17549435082228750796873653722224568e-38F32"
0x00001acf: "__WINT_TYPE__ unsigned int"
0x00001aea: "__INT16_MAX__ 0x7fff"
0x00001aff: "__SCHAR_WIDTH__ 8"
0x00001b11: "__UINT32_C(c) c ## U"
0x00001b26: "__LDBL_MIN_10_EXP__ (-4931)"
0x00001b42: "__BFLT16_NORM_MAX__ 3.38953138925153547590470800371487867e+38BF16"
0x00001b84: "__SIZEOF_DOUBLE__ 8"
0x00001b98: "__GNUC_PATCHLEVEL__ 1"
0x00001bae: "__BFLT16_HAS_QUIET_NAN__ 1"
0x00001bc9: "__FLT16_DECIMAL_DIG__ 5"
0x00001be1: "__WINT_MIN__ 0U"
0x00001bf1: "__LDBL_MANT_DIG__ 64"
0x00001c06: "__FLT32_IS_IEC_60559__ 1"
0x00001c1f: "__FLT_NORM_MAX__ 3.40282346638528859811704183484516925e+38F"
0x00001c5b: "__STDC_UTF_16__ 1"
0x00001c6d: "__LDBL_EPSILON__ 1.08420217248550443400745280086994171e-19L"
0x00001ca9: "__LDBL_HAS_INFINITY__ 1"
0x00001cc1: "__GCC_IEC_559_COMPLEX 2"
0x00001cd9: "__SIG_ATOMIC_MIN__ (-__SIG_ATOMIC_MAX__ - 1)"
0x00001d06: "__SIZEOF_WCHAR_T__ 4"
0x00001d1b: "__FLT128_MIN_10_EXP__ (-4931)"
0x00001d39: "__FLOAT_WORD_ORDER__ __ORDER_LITTLE_ENDIAN__"
0x00001d66: "__GCC_HAVE_SYNC_COMPARE_AND_SWAP_2 1"
0x00001d8b: "__DEC32_MANT_DIG__ 7"
0x00001da0: "__FLT32_DENORM_MIN__ 1.40129846432481707092372958328991613e-45F32"
0x00001de2: "__DEC64_MIN_EXP__ (-382)"
0x00001dfb: "__UINT_FAST16_MAX__ 0xffffffffffffffffUL"
0x00001e24: "__INT32_MAX__ 0x7fffffff"
0x00001e3d: "__ATOMIC_ACQUIRE 2"
0x00001e50: "__UINT16_C(c) c"
0x00001e60: "__INT64_MAX__ 0x7fffffffffffffffL"
0x00001e82: "__SEG_GS 1"
0x00001e8d: "__SSE_MATH__ 1"
0x00001e9c: "__USER_LABEL_PREFIX__ "
0x00001eb3: "__FLT16_HAS_DENORM__ 1"
0x00001eca: "__SIG_ATOMIC_WIDTH__ 32"
0x00001ee2: "__SHRT_MAX__ 0x7fff"
0x00001ef6: "__BFLT16_MANT_DIG__ 8"
0x00001f0c: "__ORDER_PDP_ENDIAN__ 3412"
0x00001f26: "__UINTMAX_TYPE__ long unsigned int"
0x00001f49: "__FLT_DECIMAL_DIG__ 9"
0x00001f5f: "__FLT64_MAX_10_EXP__ 308"
0x00001f78: "__LDBL_MIN_EXP__ (-16381)"
0x00001f92: "__WINT_WIDTH__ 32"
0x00001fa4: "__FLT64X_MIN__ 3.36210314311209350626267781732175260e-4932F64x"
0x00001fe3: "__INT_FAST8_MAX__ 0x7f"
0x00001ffa: "__SIZEOF_INT__ 4"
0x0000200b: "__FLT32_EPSILON__ 1.19209289550781250000000000000000000e-7F32"
0x00002049: "__INT_FAST64_MAX__ 0x7fffffffffffffffL"
0x00002070: "__FLT128_HAS_QUIET_NAN__ 1"
0x0000208b: "__DEC64_MAX_EXP__ 385"
0x000020a1: "__FLT32X_MIN_10_EXP__ (-307)"
0x000020be: "__BFLT16_HAS_INFINITY__ 1"
0x000020d8: "__UINTMAX_C(c) c ## UL"
0x000020ef: "__CHAR32_TYPE__ unsigned int"
0x0000210c: "__BFLT16_MIN__ 1.17549435082228750796873653722224568e-38BF16"
0x00002149: "__FLT64X_HAS_INFINITY__ 1"
0x00002163: "__DEC128_MAX_EXP__ 6145"
0x0000217b: "__FLT32X_MIN_EXP__ (-1021)"
0x00002196: "__INTPTR_WIDTH__ 64"
0x000021aa: "__GCC_DESTRUCTIVE_SIZE 64"
0x000021c4: "__BFLT16_MAX_EXP__ 128"
0x000021db: "__UINT_FAST8_TYPE__ unsigned char"
0x000021fd: "__INT32_C(c) c"
0x0000220c: "__LDBL_HAS_QUIET_NAN__ 1"
0x00002225: "__INT8_TYPE__ signed char"
0x0000223f: "__WINT_MAX__ 0xffffffffU"
0x00002258: "__linux 1"
0x00002262: "__FLT64X_MIN_EXP__ (-16381)"
0x0000227e: "__UINT32_TYPE__ unsigned int"
0x0000229b: "__DEC32_MIN__ 1E-95DF"
0x000022b1: "__FLT128_EPSILON__ 1.92592994438723585305597794258492732e-34F128"
0x000022f2: "__SIZEOF_LONG_LONG__ 8"
0x00002309: "__FLT16_EPSILON__ 9.76562500000000000000000000000000000e-4F16"
0x00002347: "__UINT8_TYPE__ unsigned char"
0x00002364: "__SHRT_WIDTH__ 16"
0x00002376: "__SSE2_MATH__ 1"
0x00002386: "__STDC_IEC_559__ 1"
0x00002399: "__FLT64_NORM_MAX__ 1.79769313486231570814527423731704357e+308F64"
0x000023da: "__INT_FAST32_WIDTH__ 64"
0x000023f2: "__BFLT16_MIN_10_EXP__ (-37)"
0x0000240e: "__SIZEOF_POINTER__ 8"
0x00002423: "__FLT64_EPSILON__ 2.22044604925031308084726333618164062e-16F64"
0x00002462: "__FLT64X_MANT_DIG__ 64"
0x00002479: "__WCHAR_MAX__ 0x7fffffff"
0x00002492: "__INT_WIDTH__ 32"
0x000024a3: "__LDBL_DECIMAL_DIG__ 21"
0x000024bb: "__GCC_ATOMIC_POINTER_LOCK_FREE 2"
0x000024dc: "__SEG_FS 1"
0x000024e7: "__UINT_FAST16_TYPE__ long unsigned int"
0x0000250e: "__STDC_VERSION__ 201710L"
0x00002527: "__GCC_ATOMIC_CHAR32_T_LOCK_FREE 2"
0x00002549: "__unix 1"
0x00002552: "__CHAR_BIT__ 8"
0x00002561: "__ATOMIC_RELAXED 0"
0x00002574: "__STDC_HOSTED__ 1"
0x00002586: "__SIZE_WIDTH__ 64"
0x00002598: "__STDC_IEC_60559_BFP__ 201404L"
0x000025b7: "__FLT16_HAS_QUIET_NAN__ 1"
0x000025d1: "__LONG_WIDTH__ 64"
0x000025e3: "__k8 1"
0x000025ea: "__CHAR16_TYPE__ short unsigned int"
0x0000260d: "__GCC_ATOMIC_LLONG_LOCK_FREE 2"
0x0000262c: "__FLT_MAX_EXP__ 128"
0x00002640: "__ATOMIC_ACQ_REL 4"
0x00002653: "__DEC32_MIN_EXP__ (-94)"
0x0000266b: "__DEC32_MAX_EXP__ 97"
0x00002680: "__INT64_TYPE__ long int"
0x00002698: "__FLT_MIN__ 1.17549435082228750796873653722224568e-38F"
0x000026cf: "__BITINT_MAXWIDTH__ 65535"
0x000026e9: "__FXSR__ 1"
0x000026f4: "__INT_LEAST32_WIDTH__ 32"
0x0000270d: "__GNUC_WIDE_EXECUTION_CHARSET_NAME \"UTF-32LE\""
0x0000273b: "__linux__ 1"
0x00002747: "__PIC__ 2"
0x00002751: "__UINT_LEAST64_TYPE__ long unsigned int"
0x00002779: "__SIZE_MAX__ 0xffffffffffffffffUL"
0x0000279b: "__FLT64_MIN_EXP__ (-1021)"
0x000027b5: "__GCC_ATOMIC_SHORT_LOCK_FREE 2"
0x000027d4: "__FLT64X_DECIMAL_DIG__ 21"
0x000027ee: "__INT_FAST16_MAX__ 0x7fffffffffffffffL"
0x00002815: "__FLT32X_IS_IEC_60559__ 1"
0x0000282f: "__FLT_EPSILON__ 1.19209289550781250000000000000000000e-7F"
0x00002869: "__BFLT16_HAS_DENORM__ 1"
0x00002881: "__FLT_EVAL_METHOD_TS_18661_3__ 0"
0x000028a2: "__DBL_HAS_INFINITY__ 1"
0x000028b9: "__INT64_C(c) c ## L"
0x000028cd: "__FLT_HAS_QUIET_NAN__ 1"
0x000028e5: "__PTRDIFF_TYPE__ long int"
0x000028ff: "__INT_FAST16_TYPE__ long int"
0x0000291c: "__DBL_NORM_MAX__ ((double)1.79769313486231570814527423731704357e+308L)"
0x00002963: "__DEC128_SUBNORMAL_MIN__ 0.000000000000000000000000000000001E-6143DL"
0x000029a8: "_STDC_PREDEF_H 1"
0x000029b9: "__FLT16_NORM_MAX__ 6.55040000000000000000000000000000000e+4F16"
0x000029f8: "__SIZEOF_FLOAT80__ 16"
0x00002a0e: "__FLT32X_HAS_QUIET_NAN__ 1"
0x00002a29: "__DBL_MAX_10_EXP__ 308"
0x00002a40: "__pic__ 2"
0x00002a4a: "__GNUC_STDC_INLINE__ 1"
0x00002a61: "__SSE__ 1"
0x00002a6b: "main"
0x00002a70: "__FLT128_DENORM_MIN__ 6.47517511943802511092443895822764655e-4966F128"
0x00002ab6: "__FLT_MIN_EXP__ (-125)"
0x00002acd: "__SSP_STRONG__ 3"
0x00002ade: "__DEC128_MAX__ 9.999999999999999999999999999999999E6144DL"
0x00002b18: "__REGISTER_PREFIX__ "
0x00002b2d: "double"
0x00002b34: "__FLT16_MAX__ 6.55040000000000000000000000000000000e+4F16"
0x00002b6e: "__UINT_LEAST32_MAX__ 0xffffffffU"
0x00002b8f: "__FLT32X_MAX_10_EXP__ 308"
0x00002ba9: "__amd64 1"
0x00002bb3: "__FLT16_MAX_10_EXP__ 4"
0x00002bca: "__FLT32X_NORM_MAX__ 1.79769313486231570814527423731704357e+308F32x"
0x00002c0d: "__FLT64_DENORM_MIN__ 4.94065645841246544176568792868221372e-324F64"
0x00002c50: "__FLT32_MAX_10_EXP__ 38"
0x00002c68: "__FLT128_DECIMAL_DIG__ 36"
0x00002c82: "__PTRDIFF_WIDTH__ 64"
0x00002c97: "__INT_LEAST32_MAX__ 0x7fffffff"
0x00002cb6: "__UINT_FAST64_TYPE__ long unsigned int"
0x00002cdd: "__LDBL_MAX_10_EXP__ 4932"
0x00002cf6: "__DEC64_MIN__ 1E-383DD"
0x00002d0d: "__FLT32_MAX__ 3.40282346638528859811704183484516925e+38F32"
0x00002d48: "__DBL_EPSILON__ ((double)2.22044604925031308084726333618164062e-16L)"
0x00002d8d: "__PRAGMA_REDEFINE_EXTNAME 1"
0x00002da9: "__SIG_ATOMIC_TYPE__ int"
0x00002dc1: "__FLT64X_DENORM_MIN__ 3.64519953188247460252840593361941982e-4951F64x"
0x00002e07: "__FLT128_HAS_DENORM__ 1"
0x00002e1f: "__FLT128_IS_IEC_60559__ 1"
0x00002e39: "__DBL_DECIMAL_DIG__ 17"
0x00002e50: "__LDBL_HAS_DENORM__ 1"
0x00002e66: "__FLT64_MANT_DIG__ 53"
0x00002e7c: "__DEC64_MANT_DIG__ 16"
0x00002e92: "__FLT_HAS_DENORM__ 1"
0x00002ea7: "__INT_FAST64_WIDTH__ 64"
0x00002ebf: "__DECIMAL_DIG__ 21"
