test.o:	file format elf64-x86-64

.debug_abbrev contents:
Abbrev table for offset: 0x00000000
[1] DW_TAG_compile_unit	DW_CHILDREN_yes
	DW_AT_comp_dir	DW_FORM_strp
	DW_AT_name	DW_FORM_strp
	DW_AT_language	DW_FORM_udata
	DW_AT_producer	DW_FORM_strp

[2] DW_TAG_base_type	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_byte_size	DW_FORM_udata
	DW_AT_encoding	DW_FORM_udata

[3] DW_TAG_structure_type	DW_CHILDREN_yes
	DW_AT_name	DW_FORM_strp
	DW_AT_byte_size	DW_FORM_udata

[4] DW_TAG_member	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_type	DW_FORM_ref4
	DW_AT_data_member_location	DW_FORM_udata

[5] DW_TAG_enumeration_type	DW_CHILDREN_yes
	DW_AT_name	DW_FORM_strp
	DW_AT_byte_size	DW_FORM_udata
	DW_AT_encoding	DW_FORM_udata
	DW_AT_type	DW_FORM_ref4

[6] DW_TAG_enumerator	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_const_value	DW_FORM_udata

[7] DW_TAG_array_type	DW_CHILDREN_yes
	DW_AT_type	DW_FORM_ref4

[8] DW_TAG_subrange_type	DW_CHILDREN_no
	DW_AT_type	DW_FORM_ref4
	DW_AT_upper_bound	DW_FORM_udata

[9] DW_TAG_pointer_type	DW_CHILDREN_no
	DW_AT_byte_size	DW_FORM_udata
	DW_AT_type	DW_FORM_ref4

[10] DW_TAG_subroutine_type	DW_CHILDREN_no
	DW_AT_prototyped	DW_FORM_flag

[11] DW_TAG_typedef	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_type	DW_FORM_ref4

[12] DW_TAG_pointer_type	DW_CHILDREN_no
	DW_AT_byte_size	DW_FORM_udata

[13] DW_TAG_member	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_data_member_location	DW_FORM_udata

[14] DW_TAG_subroutine_type	DW_CHILDREN_yes
	DW_AT_prototyped	DW_FORM_flag
	DW_AT_type	DW_FORM_ref4

[15] DW_TAG_formal_parameter	DW_CHILDREN_no
	DW_AT_type	DW_FORM_ref4

[16] DW_TAG_union_type	DW_CHILDREN_yes
	DW_AT_byte_size	DW_FORM_udata

[17] DW_TAG_subroutine_type	DW_CHILDREN_yes
	DW_AT_prototyped	DW_FORM_flag

[18] DW_TAG_variable	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_type	DW_FORM_ref4
	DW_AT_external	DW_FORM_flag
	DW_AT_location	DW_FORM_exprloc

[19] DW_TAG_variable	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_external	DW_FORM_flag
	DW_AT_location	DW_FORM_exprloc

[20] DW_TAG_subprogram	DW_CHILDREN_yes
	DW_AT_external	DW_FORM_flag
	DW_AT_name	DW_FORM_strp
	DW_AT_prototyped	DW_FORM_flag
	DW_AT_low_pc	DW_FORM_udata
	DW_AT_high_pc	DW_FORM_udata
	DW_AT_frame_base	DW_FORM_exprloc

[21] DW_TAG_variable	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_location	DW_FORM_exprloc

[22] DW_TAG_variable	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_type	DW_FORM_ref4
	DW_AT_location	DW_FORM_exprloc

[23] DW_TAG_subprogram	DW_CHILDREN_yes
	DW_AT_external	DW_FORM_flag
	DW_AT_name	DW_FORM_strp
	DW_AT_prototyped	DW_FORM_flag
	DW_AT_type	DW_FORM_ref4
	DW_AT_low_pc	DW_FORM_udata
	DW_AT_high_pc	DW_FORM_udata
	DW_AT_frame_base	DW_FORM_exprloc

[24] DW_TAG_formal_parameter	DW_CHILDREN_no
	DW_AT_name	DW_FORM_strp
	DW_AT_type	DW_FORM_ref4


.debug_info contents:
0x00000000: Compile Unit: length = 0x00001611, format = DWARF32, version = 0x0004, abbr_offset = 0x0000, addr_size = 0x08 (next unit at 0x00001615)

0x0000000b: DW_TAG_compile_unit
              DW_AT_comp_dir	("llvm-dwarf")
              DW_AT_name	("debuginfo.c")
              DW_AT_language	(DW_LANG_C)
              DW_AT_producer	(":3")

0x00000019:   DW_TAG_base_type
                DW_AT_name	("uint64_t")
                DW_AT_byte_size	(8)
                DW_AT_encoding	(DW_ATE_unsigned)

0x00000020:   DW_TAG_base_type
                DW_AT_name	("char")
                DW_AT_byte_size	(1)
                DW_AT_encoding	(DW_ATE_signed)

0x00000027:   DW_TAG_base_type
                DW_AT_name	("uint8_t")
                DW_AT_byte_size	(1)
                DW_AT_encoding	(DW_ATE_unsigned)

0x0000002e:   DW_TAG_base_type
                DW_AT_name	("uint32_t")
                DW_AT_byte_size	(4)
                DW_AT_encoding	(DW_ATE_unsigned)

0x00000035:   DW_TAG_base_type
                DW_AT_name	("uint16_t")
                DW_AT_byte_size	(2)
                DW_AT_encoding	(DW_ATE_unsigned)

0x0000003c:   DW_TAG_base_type
                DW_AT_name	("int64_t")
                DW_AT_byte_size	(8)
                DW_AT_encoding	(DW_ATE_signed)

0x00000043:   DW_TAG_base_type
                DW_AT_name	("int32_t")
                DW_AT_byte_size	(4)
                DW_AT_encoding	(DW_ATE_signed)

0x0000004a:   DW_TAG_base_type
                DW_AT_name	("char const")
                DW_AT_byte_size	(1)
                DW_AT_encoding	(DW_ATE_signed)

0x00000051:   DW_TAG_base_type
                DW_AT_name	("uint8_t const")
                DW_AT_byte_size	(1)
                DW_AT_encoding	(DW_ATE_unsigned)

0x00000058:   DW_TAG_structure_type
                DW_AT_name	("Elf64_Dyn")
                DW_AT_byte_size	(16)

0x0000005e:     DW_TAG_member
                  DW_AT_name	("d_tag")
                  DW_AT_type	(0x00000073 "e_dyn_tag")
                  DW_AT_data_member_location	(0)

0x00000068:     DW_TAG_member
                  DW_AT_name	("d_val")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(8)

0x00000072:     NULL

0x00000073:   DW_TAG_enumeration_type
                DW_AT_name	("e_dyn_tag")
                DW_AT_byte_size	(8)
                DW_AT_encoding	(DW_ATE_unsigned)
                DW_AT_type	(0x00000019 "uint64_t")

0x0000007e:     DW_TAG_enumerator
                  DW_AT_name	("DT_NULL")
                  DW_AT_const_value	(0)

0x00000084:     DW_TAG_enumerator
                  DW_AT_name	("DT_NEEDED")
                  DW_AT_const_value	(1)

0x0000008a:     DW_TAG_enumerator
                  DW_AT_name	("DT_PLTRELSZ")
                  DW_AT_const_value	(2)

0x00000090:     DW_TAG_enumerator
                  DW_AT_name	("DT_PLTGOT")
                  DW_AT_const_value	(3)

0x00000096:     DW_TAG_enumerator
                  DW_AT_name	("DT_HASH")
                  DW_AT_const_value	(4)

0x0000009c:     DW_TAG_enumerator
                  DW_AT_name	("DT_STRTAB")
                  DW_AT_const_value	(5)

0x000000a2:     DW_TAG_enumerator
                  DW_AT_name	("DT_SYMTAB")
                  DW_AT_const_value	(6)

0x000000a8:     DW_TAG_enumerator
                  DW_AT_name	("DT_RELA")
                  DW_AT_const_value	(7)

0x000000ae:     DW_TAG_enumerator
                  DW_AT_name	("DT_RELASZ")
                  DW_AT_const_value	(8)

0x000000b4:     DW_TAG_enumerator
                  DW_AT_name	("DT_RELAENT")
                  DW_AT_const_value	(9)

0x000000ba:     DW_TAG_enumerator
                  DW_AT_name	("DT_STRSZ")
                  DW_AT_const_value	(10)

0x000000c0:     DW_TAG_enumerator
                  DW_AT_name	("DT_SYMENT")
                  DW_AT_const_value	(11)

0x000000c6:     DW_TAG_enumerator
                  DW_AT_name	("DT_INIT")
                  DW_AT_const_value	(12)

0x000000cc:     DW_TAG_enumerator
                  DW_AT_name	("DT_FINI")
                  DW_AT_const_value	(13)

0x000000d2:     DW_TAG_enumerator
                  DW_AT_name	("DT_SONAME")
                  DW_AT_const_value	(14)

0x000000d8:     DW_TAG_enumerator
                  DW_AT_name	("DT_RPATH")
                  DW_AT_const_value	(15)

0x000000de:     DW_TAG_enumerator
                  DW_AT_name	("DT_SYMBOLIC")
                  DW_AT_const_value	(16)

0x000000e4:     DW_TAG_enumerator
                  DW_AT_name	("DT_REL")
                  DW_AT_const_value	(17)

0x000000ea:     DW_TAG_enumerator
                  DW_AT_name	("DT_RELSZ")
                  DW_AT_const_value	(18)

0x000000f0:     DW_TAG_enumerator
                  DW_AT_name	("DT_RELENT")
                  DW_AT_const_value	(19)

0x000000f6:     DW_TAG_enumerator
                  DW_AT_name	("DT_PLTREL")
                  DW_AT_const_value	(20)

0x000000fc:     DW_TAG_enumerator
                  DW_AT_name	("DT_DEBUG")
                  DW_AT_const_value	(21)

0x00000102:     DW_TAG_enumerator
                  DW_AT_name	("DT_TEXTREL")
                  DW_AT_const_value	(22)

0x00000108:     DW_TAG_enumerator
                  DW_AT_name	("DT_JMPREL")
                  DW_AT_const_value	(23)

0x0000010e:     DW_TAG_enumerator
                  DW_AT_name	("DT_BIND_NOW")
                  DW_AT_const_value	(24)

0x00000114:     DW_TAG_enumerator
                  DW_AT_name	("DT_INIT_ARRAY")
                  DW_AT_const_value	(25)

0x0000011a:     DW_TAG_enumerator
                  DW_AT_name	("DT_FINI_ARRAY")
                  DW_AT_const_value	(26)

0x00000120:     DW_TAG_enumerator
                  DW_AT_name	("DT_INIT_ARRAYSZ")
                  DW_AT_const_value	(27)

0x00000126:     DW_TAG_enumerator
                  DW_AT_name	("DT_FINI_ARRAYSZ")
                  DW_AT_const_value	(28)

0x0000012c:     DW_TAG_enumerator
                  DW_AT_name	("DT_RUNPATH")
                  DW_AT_const_value	(29)

0x00000132:     DW_TAG_enumerator
                  DW_AT_name	("DT_FLAGS")
                  DW_AT_const_value	(30)

0x00000138:     DW_TAG_enumerator
                  DW_AT_name	("DT_ENCODING")
                  DW_AT_const_value	(31)

0x0000013e:     DW_TAG_enumerator
                  DW_AT_name	("DT_PREINIT_ARRAY")
                  DW_AT_const_value	(32)

0x00000144:     DW_TAG_enumerator
                  DW_AT_name	("DT_PREINIT_ARRAYSZ")
                  DW_AT_const_value	(33)

0x0000014a:     DW_TAG_enumerator
                  DW_AT_name	("DT_LOOS")
                  DW_AT_const_value	(1610612749)

0x00000154:     DW_TAG_enumerator
                  DW_AT_name	("DT_SUNW_RTLDINF")
                  DW_AT_const_value	(1610612750)

0x0000015e:     DW_TAG_enumerator
                  DW_AT_name	("DT_HIOS")
                  DW_AT_const_value	(1879044096)

0x00000168:     DW_TAG_enumerator
                  DW_AT_name	("DT_VALRNGLO")
                  DW_AT_const_value	(1879047424)

0x00000172:     DW_TAG_enumerator
                  DW_AT_name	("DT_CHECKSUM")
                  DW_AT_const_value	(1879047672)

0x0000017c:     DW_TAG_enumerator
                  DW_AT_name	("DT_PLTPADSZ")
                  DW_AT_const_value	(1879047673)

0x00000186:     DW_TAG_enumerator
                  DW_AT_name	("DT_MOVEENT")
                  DW_AT_const_value	(1879047674)

0x00000190:     DW_TAG_enumerator
                  DW_AT_name	("DT_MOVESZ")
                  DW_AT_const_value	(1879047675)

0x0000019a:     DW_TAG_enumerator
                  DW_AT_name	("DT_FEATURE_1")
                  DW_AT_const_value	(1879047676)

0x000001a4:     DW_TAG_enumerator
                  DW_AT_name	("DT_POSFLAG_1")
                  DW_AT_const_value	(1879047677)

0x000001ae:     DW_TAG_enumerator
                  DW_AT_name	("DT_SYMINSZ")
                  DW_AT_const_value	(1879047678)

0x000001b8:     DW_TAG_enumerator
                  DW_AT_name	("DT_SYMINENT")
                  DW_AT_const_value	(1879047679)

0x000001c2:     DW_TAG_enumerator
                  DW_AT_name	("DT_VALRNGHI")
                  DW_AT_const_value	(1879047679)

0x000001cc:     DW_TAG_enumerator
                  DW_AT_name	("DT_ADDRRNGLO")
                  DW_AT_const_value	(1879047680)

0x000001d6:     DW_TAG_enumerator
                  DW_AT_name	("DT_GNU_HASH")
                  DW_AT_const_value	(1879047925)

0x000001e0:     DW_TAG_enumerator
                  DW_AT_name	("DT_CONFIG")
                  DW_AT_const_value	(1879047930)

0x000001ea:     DW_TAG_enumerator
                  DW_AT_name	("DT_DEPAUDIT")
                  DW_AT_const_value	(1879047931)

0x000001f4:     DW_TAG_enumerator
                  DW_AT_name	("DT_AUDIT")
                  DW_AT_const_value	(1879047932)

0x000001fe:     DW_TAG_enumerator
                  DW_AT_name	("DT_PLTPAD")
                  DW_AT_const_value	(1879047933)

0x00000208:     DW_TAG_enumerator
                  DW_AT_name	("DT_MOVETAB")
                  DW_AT_const_value	(1879047934)

0x00000212:     DW_TAG_enumerator
                  DW_AT_name	("DT_SYMINFO")
                  DW_AT_const_value	(1879047935)

0x0000021c:     DW_TAG_enumerator
                  DW_AT_name	("DT_ADDRRNGHI")
                  DW_AT_const_value	(1879047935)

0x00000226:     DW_TAG_enumerator
                  DW_AT_name	("DT_RELACOUNT")
                  DW_AT_const_value	(1879048185)

0x00000230:     DW_TAG_enumerator
                  DW_AT_name	("DT_RELCOUNT")
                  DW_AT_const_value	(1879048186)

0x0000023a:     DW_TAG_enumerator
                  DW_AT_name	("DT_FLAGS_1")
                  DW_AT_const_value	(1879048187)

0x00000244:     DW_TAG_enumerator
                  DW_AT_name	("DT_VERDEF")
                  DW_AT_const_value	(1879048188)

0x0000024e:     DW_TAG_enumerator
                  DW_AT_name	("DT_VERDEFNUM")
                  DW_AT_const_value	(1879048189)

0x00000258:     DW_TAG_enumerator
                  DW_AT_name	("DT_VERNEED")
                  DW_AT_const_value	(1879048190)

0x00000262:     DW_TAG_enumerator
                  DW_AT_name	("DT_VERNEEDNUM")
                  DW_AT_const_value	(1879048191)

0x0000026c:     DW_TAG_enumerator
                  DW_AT_name	("DT_VERSYM")
                  DW_AT_const_value	(1879048176)

0x00000276:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_RLD_VERSION")
                  DW_AT_const_value	(1879048193)

0x00000280:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_TIME_STAMP")
                  DW_AT_const_value	(1879048194)

0x0000028a:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_ICHECKSUM")
                  DW_AT_const_value	(1879048195)

0x00000294:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_IVERSION")
                  DW_AT_const_value	(1879048196)

0x0000029e:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_FLAGS")
                  DW_AT_const_value	(1879048197)

0x000002a8:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_BASE_ADDRESS")
                  DW_AT_const_value	(1879048198)

0x000002b2:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_CONFLICT")
                  DW_AT_const_value	(1879048200)

0x000002bc:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_LIBLIST")
                  DW_AT_const_value	(1879048201)

0x000002c6:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_LOCAL_GOTNO")
                  DW_AT_const_value	(1879048202)

0x000002d0:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_CONFLICTNO")
                  DW_AT_const_value	(1879048203)

0x000002da:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_LIBLISTNO")
                  DW_AT_const_value	(1879048208)

0x000002e4:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_SYMTABNO")
                  DW_AT_const_value	(1879048209)

0x000002ee:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_UNREFEXTNO")
                  DW_AT_const_value	(1879048210)

0x000002f8:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_GOTSYM")
                  DW_AT_const_value	(1879048211)

0x00000302:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_HIPAGENO")
                  DW_AT_const_value	(1879048212)

0x0000030c:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_RLD_MAP")
                  DW_AT_const_value	(1879048214)

0x00000316:     DW_TAG_enumerator
                  DW_AT_name	("DT_MIPS_RLD_MAP_REL")
                  DW_AT_const_value	(1879048245)

0x00000320:     NULL

0x00000321:   DW_TAG_array_type
                DW_AT_type	(0x00000058 "Elf64_Dyn")

0x00000326:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(23)

0x0000032c:     NULL

0x0000032d:   DW_TAG_structure_type
                DW_AT_name	("Elf64_Header")
                DW_AT_byte_size	(64)

0x00000333:     DW_TAG_member
                  DW_AT_name	("ident")
                  DW_AT_type	(0x000003c0 "Elf64_Ident")
                  DW_AT_data_member_location	(0)

0x0000033d:     DW_TAG_member
                  DW_AT_name	("type")
                  DW_AT_type	(0x00000425 "e_type")
                  DW_AT_data_member_location	(16)

0x00000347:     DW_TAG_member
                  DW_AT_name	("machine")
                  DW_AT_type	(0x00000455 "e_machine")
                  DW_AT_data_member_location	(18)

0x00000351:     DW_TAG_member
                  DW_AT_name	("version")
                  DW_AT_type	(0x0000002e "uint32_t")
                  DW_AT_data_member_location	(20)

0x0000035b:     DW_TAG_member
                  DW_AT_name	("entry")
                  DW_AT_type	(0x00000646 "void (*)()")
                  DW_AT_data_member_location	(24)

0x00000365:     DW_TAG_member
                  DW_AT_name	("program_header_offset")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(32)

0x0000036f:     DW_TAG_member
                  DW_AT_name	("section_header_offset")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(40)

0x00000379:     DW_TAG_member
                  DW_AT_name	("flags")
                  DW_AT_type	(0x0000002e "uint32_t")
                  DW_AT_data_member_location	(48)

0x00000383:     DW_TAG_member
                  DW_AT_name	("header_size")
                  DW_AT_type	(0x00000035 "uint16_t")
                  DW_AT_data_member_location	(52)

0x0000038d:     DW_TAG_member
                  DW_AT_name	("program_header_size")
                  DW_AT_type	(0x00000035 "uint16_t")
                  DW_AT_data_member_location	(54)

0x00000397:     DW_TAG_member
                  DW_AT_name	("program_header_count")
                  DW_AT_type	(0x00000035 "uint16_t")
                  DW_AT_data_member_location	(56)

0x000003a1:     DW_TAG_member
                  DW_AT_name	("section_header_size")
                  DW_AT_type	(0x00000035 "uint16_t")
                  DW_AT_data_member_location	(58)

0x000003ab:     DW_TAG_member
                  DW_AT_name	("section_header_count")
                  DW_AT_type	(0x00000035 "uint16_t")
                  DW_AT_data_member_location	(60)

0x000003b5:     DW_TAG_member
                  DW_AT_name	("string_table")
                  DW_AT_type	(0x00000035 "uint16_t")
                  DW_AT_data_member_location	(62)

0x000003bf:     NULL

0x000003c0:   DW_TAG_structure_type
                DW_AT_name	("Elf64_Ident")
                DW_AT_byte_size	(16)

0x000003c6:     DW_TAG_member
                  DW_AT_name	("signature")
                  DW_AT_type	(0x0000040d "char[4]")
                  DW_AT_data_member_location	(0)

0x000003d0:     DW_TAG_member
                  DW_AT_name	("file_class")
                  DW_AT_type	(0x00000027 "uint8_t")
                  DW_AT_data_member_location	(4)

0x000003da:     DW_TAG_member
                  DW_AT_name	("encoding")
                  DW_AT_type	(0x00000027 "uint8_t")
                  DW_AT_data_member_location	(5)

0x000003e4:     DW_TAG_member
                  DW_AT_name	("version")
                  DW_AT_type	(0x00000027 "uint8_t")
                  DW_AT_data_member_location	(6)

0x000003ee:     DW_TAG_member
                  DW_AT_name	("os")
                  DW_AT_type	(0x00000027 "uint8_t")
                  DW_AT_data_member_location	(7)

0x000003f8:     DW_TAG_member
                  DW_AT_name	("abi_version")
                  DW_AT_type	(0x00000027 "uint8_t")
                  DW_AT_data_member_location	(8)

0x00000402:     DW_TAG_member
                  DW_AT_name	("pad")
                  DW_AT_type	(0x00000419 "char[7]")
                  DW_AT_data_member_location	(9)

0x0000040c:     NULL

0x0000040d:   DW_TAG_array_type
                DW_AT_type	(0x00000020 "char")

0x00000412:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(3)

0x00000418:     NULL

0x00000419:   DW_TAG_array_type
                DW_AT_type	(0x00000020 "char")

0x0000041e:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(6)

0x00000424:     NULL

0x00000425:   DW_TAG_enumeration_type
                DW_AT_name	("e_type")
                DW_AT_byte_size	(2)
                DW_AT_encoding	(DW_ATE_unsigned)
                DW_AT_type	(0x00000035 "uint16_t")

0x00000430:     DW_TAG_enumerator
                  DW_AT_name	("ET_NONE")
                  DW_AT_const_value	(0)

0x00000436:     DW_TAG_enumerator
                  DW_AT_name	("ET_REL")
                  DW_AT_const_value	(1)

0x0000043c:     DW_TAG_enumerator
                  DW_AT_name	("ET_EXEC")
                  DW_AT_const_value	(2)

0x00000442:     DW_TAG_enumerator
                  DW_AT_name	("ET_DYN")
                  DW_AT_const_value	(3)

0x00000448:     DW_TAG_enumerator
                  DW_AT_name	("ET_CORE")
                  DW_AT_const_value	(4)

0x0000044e:     DW_TAG_enumerator
                  DW_AT_name	("ET_NUM")
                  DW_AT_const_value	(5)

0x00000454:     NULL

0x00000455:   DW_TAG_enumeration_type
                DW_AT_name	("e_machine")
                DW_AT_byte_size	(2)
                DW_AT_encoding	(DW_ATE_unsigned)
                DW_AT_type	(0x00000035 "uint16_t")

0x00000460:     DW_TAG_enumerator
                  DW_AT_name	("EM_NONE")
                  DW_AT_const_value	(0)

0x00000466:     DW_TAG_enumerator
                  DW_AT_name	("EM_M32")
                  DW_AT_const_value	(1)

0x0000046c:     DW_TAG_enumerator
                  DW_AT_name	("EM_SPARC")
                  DW_AT_const_value	(2)

0x00000472:     DW_TAG_enumerator
                  DW_AT_name	("EM_386")
                  DW_AT_const_value	(3)

0x00000478:     DW_TAG_enumerator
                  DW_AT_name	("EM_68K")
                  DW_AT_const_value	(4)

0x0000047e:     DW_TAG_enumerator
                  DW_AT_name	("EM_88K")
                  DW_AT_const_value	(5)

0x00000484:     DW_TAG_enumerator
                  DW_AT_name	("EM_860")
                  DW_AT_const_value	(7)

0x0000048a:     DW_TAG_enumerator
                  DW_AT_name	("EM_MIPS")
                  DW_AT_const_value	(8)

0x00000490:     DW_TAG_enumerator
                  DW_AT_name	("EM_S370")
                  DW_AT_const_value	(9)

0x00000496:     DW_TAG_enumerator
                  DW_AT_name	("EM_MIPS_RS3_LE")
                  DW_AT_const_value	(10)

0x0000049c:     DW_TAG_enumerator
                  DW_AT_name	("EM_PARISC")
                  DW_AT_const_value	(15)

0x000004a2:     DW_TAG_enumerator
                  DW_AT_name	("EM_VPP500")
                  DW_AT_const_value	(17)

0x000004a8:     DW_TAG_enumerator
                  DW_AT_name	("EM_SPARC32PLUS")
                  DW_AT_const_value	(18)

0x000004ae:     DW_TAG_enumerator
                  DW_AT_name	("EM_960")
                  DW_AT_const_value	(19)

0x000004b4:     DW_TAG_enumerator
                  DW_AT_name	("EM_PPC")
                  DW_AT_const_value	(20)

0x000004ba:     DW_TAG_enumerator
                  DW_AT_name	("EM_PPC64")
                  DW_AT_const_value	(21)

0x000004c0:     DW_TAG_enumerator
                  DW_AT_name	("EM_S390")
                  DW_AT_const_value	(22)

0x000004c6:     DW_TAG_enumerator
                  DW_AT_name	("EM_V800")
                  DW_AT_const_value	(36)

0x000004cc:     DW_TAG_enumerator
                  DW_AT_name	("EM_FR20")
                  DW_AT_const_value	(37)

0x000004d2:     DW_TAG_enumerator
                  DW_AT_name	("EM_RH32")
                  DW_AT_const_value	(38)

0x000004d8:     DW_TAG_enumerator
                  DW_AT_name	("EM_RCE")
                  DW_AT_const_value	(39)

0x000004de:     DW_TAG_enumerator
                  DW_AT_name	("EM_ARM")
                  DW_AT_const_value	(40)

0x000004e4:     DW_TAG_enumerator
                  DW_AT_name	("EM_FAKE_ALPHA")
                  DW_AT_const_value	(41)

0x000004ea:     DW_TAG_enumerator
                  DW_AT_name	("EM_SH")
                  DW_AT_const_value	(42)

0x000004f0:     DW_TAG_enumerator
                  DW_AT_name	("EM_SPARCV9")
                  DW_AT_const_value	(43)

0x000004f6:     DW_TAG_enumerator
                  DW_AT_name	("EM_TRICORE")
                  DW_AT_const_value	(44)

0x000004fc:     DW_TAG_enumerator
                  DW_AT_name	("EM_ARC")
                  DW_AT_const_value	(45)

0x00000502:     DW_TAG_enumerator
                  DW_AT_name	("EM_H8_300")
                  DW_AT_const_value	(46)

0x00000508:     DW_TAG_enumerator
                  DW_AT_name	("EM_H8_300H")
                  DW_AT_const_value	(47)

0x0000050e:     DW_TAG_enumerator
                  DW_AT_name	("EM_H8S")
                  DW_AT_const_value	(48)

0x00000514:     DW_TAG_enumerator
                  DW_AT_name	("EM_H8_500")
                  DW_AT_const_value	(49)

0x0000051a:     DW_TAG_enumerator
                  DW_AT_name	("EM_IA_64")
                  DW_AT_const_value	(50)

0x00000520:     DW_TAG_enumerator
                  DW_AT_name	("EM_MIPS_X")
                  DW_AT_const_value	(51)

0x00000526:     DW_TAG_enumerator
                  DW_AT_name	("EM_COLDFIRE")
                  DW_AT_const_value	(52)

0x0000052c:     DW_TAG_enumerator
                  DW_AT_name	("EM_68HC12")
                  DW_AT_const_value	(53)

0x00000532:     DW_TAG_enumerator
                  DW_AT_name	("EM_MMA")
                  DW_AT_const_value	(54)

0x00000538:     DW_TAG_enumerator
                  DW_AT_name	("EM_PCP")
                  DW_AT_const_value	(55)

0x0000053e:     DW_TAG_enumerator
                  DW_AT_name	("EM_NCPU")
                  DW_AT_const_value	(56)

0x00000544:     DW_TAG_enumerator
                  DW_AT_name	("EM_NDR1")
                  DW_AT_const_value	(57)

0x0000054a:     DW_TAG_enumerator
                  DW_AT_name	("EM_STARCORE")
                  DW_AT_const_value	(58)

0x00000550:     DW_TAG_enumerator
                  DW_AT_name	("EM_ME16")
                  DW_AT_const_value	(59)

0x00000556:     DW_TAG_enumerator
                  DW_AT_name	("EM_ST100")
                  DW_AT_const_value	(60)

0x0000055c:     DW_TAG_enumerator
                  DW_AT_name	("EM_TINYJ")
                  DW_AT_const_value	(61)

0x00000562:     DW_TAG_enumerator
                  DW_AT_name	("EM_X86_64")
                  DW_AT_const_value	(62)

0x00000568:     DW_TAG_enumerator
                  DW_AT_name	("EM_PDSP")
                  DW_AT_const_value	(63)

0x0000056e:     DW_TAG_enumerator
                  DW_AT_name	("EM_FX66")
                  DW_AT_const_value	(66)

0x00000574:     DW_TAG_enumerator
                  DW_AT_name	("EM_ST9PLUS")
                  DW_AT_const_value	(67)

0x0000057a:     DW_TAG_enumerator
                  DW_AT_name	("EM_ST7")
                  DW_AT_const_value	(68)

0x00000580:     DW_TAG_enumerator
                  DW_AT_name	("EM_68HC16")
                  DW_AT_const_value	(69)

0x00000586:     DW_TAG_enumerator
                  DW_AT_name	("EM_68HC11")
                  DW_AT_const_value	(70)

0x0000058c:     DW_TAG_enumerator
                  DW_AT_name	("EM_68HC08")
                  DW_AT_const_value	(71)

0x00000592:     DW_TAG_enumerator
                  DW_AT_name	("EM_68HC05")
                  DW_AT_const_value	(72)

0x00000598:     DW_TAG_enumerator
                  DW_AT_name	("EM_SVX")
                  DW_AT_const_value	(73)

0x0000059e:     DW_TAG_enumerator
                  DW_AT_name	("EM_ST19")
                  DW_AT_const_value	(74)

0x000005a4:     DW_TAG_enumerator
                  DW_AT_name	("EM_VAX")
                  DW_AT_const_value	(75)

0x000005aa:     DW_TAG_enumerator
                  DW_AT_name	("EM_CRIS")
                  DW_AT_const_value	(76)

0x000005b0:     DW_TAG_enumerator
                  DW_AT_name	("EM_JAVELIN")
                  DW_AT_const_value	(77)

0x000005b6:     DW_TAG_enumerator
                  DW_AT_name	("EM_FIREPATH")
                  DW_AT_const_value	(78)

0x000005bc:     DW_TAG_enumerator
                  DW_AT_name	("EM_ZSP")
                  DW_AT_const_value	(79)

0x000005c2:     DW_TAG_enumerator
                  DW_AT_name	("EM_MMIX")
                  DW_AT_const_value	(80)

0x000005c8:     DW_TAG_enumerator
                  DW_AT_name	("EM_HUANY")
                  DW_AT_const_value	(81)

0x000005ce:     DW_TAG_enumerator
                  DW_AT_name	("EM_PRISM")
                  DW_AT_const_value	(82)

0x000005d4:     DW_TAG_enumerator
                  DW_AT_name	("EM_AVR")
                  DW_AT_const_value	(83)

0x000005da:     DW_TAG_enumerator
                  DW_AT_name	("EM_FR30")
                  DW_AT_const_value	(84)

0x000005e0:     DW_TAG_enumerator
                  DW_AT_name	("EM_D10V")
                  DW_AT_const_value	(85)

0x000005e6:     DW_TAG_enumerator
                  DW_AT_name	("EM_D30V")
                  DW_AT_const_value	(86)

0x000005ec:     DW_TAG_enumerator
                  DW_AT_name	("EM_V850")
                  DW_AT_const_value	(87)

0x000005f2:     DW_TAG_enumerator
                  DW_AT_name	("EM_M32R")
                  DW_AT_const_value	(88)

0x000005f8:     DW_TAG_enumerator
                  DW_AT_name	("EM_MN10300")
                  DW_AT_const_value	(89)

0x000005fe:     DW_TAG_enumerator
                  DW_AT_name	("EM_MN10200")
                  DW_AT_const_value	(90)

0x00000604:     DW_TAG_enumerator
                  DW_AT_name	("EM_PJ")
                  DW_AT_const_value	(91)

0x0000060a:     DW_TAG_enumerator
                  DW_AT_name	("EM_OPENRISC")
                  DW_AT_const_value	(92)

0x00000610:     DW_TAG_enumerator
                  DW_AT_name	("EM_ARC_A5")
                  DW_AT_const_value	(93)

0x00000616:     DW_TAG_enumerator
                  DW_AT_name	("EM_XTENSA")
                  DW_AT_const_value	(94)

0x0000061c:     DW_TAG_enumerator
                  DW_AT_name	("EM_ALTERA_NIOS2")
                  DW_AT_const_value	(113)

0x00000622:     DW_TAG_enumerator
                  DW_AT_name	("EM_AARCH64")
                  DW_AT_const_value	(183)

0x00000629:     DW_TAG_enumerator
                  DW_AT_name	("EM_TILEPRO")
                  DW_AT_const_value	(188)

0x00000630:     DW_TAG_enumerator
                  DW_AT_name	("EM_MICROBLAZE")
                  DW_AT_const_value	(189)

0x00000637:     DW_TAG_enumerator
                  DW_AT_name	("EM_TILEGX")
                  DW_AT_const_value	(191)

0x0000063e:     DW_TAG_enumerator
                  DW_AT_name	("EM_NUM")
                  DW_AT_const_value	(192)

0x00000645:     NULL

0x00000646:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x0000064c "void ()")

0x0000064c:   DW_TAG_subroutine_type
                DW_AT_prototyped	(0x01)

0x0000064e:   DW_TAG_structure_type
                DW_AT_name	("Elf64_ProgramHeader")
                DW_AT_byte_size	(56)

0x00000654:     DW_TAG_member
                  DW_AT_name	("type")
                  DW_AT_type	(0x000006a5 "p_type")
                  DW_AT_data_member_location	(0)

0x0000065e:     DW_TAG_member
                  DW_AT_name	("flags")
                  DW_AT_type	(0x0000075f "p_flags")
                  DW_AT_data_member_location	(4)

0x00000668:     DW_TAG_member
                  DW_AT_name	("offset")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(8)

0x00000672:     DW_TAG_member
                  DW_AT_name	("virtual_address")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(16)

0x0000067c:     DW_TAG_member
                  DW_AT_name	("physical_address")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(24)

0x00000686:     DW_TAG_member
                  DW_AT_name	("file_size")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(32)

0x00000690:     DW_TAG_member
                  DW_AT_name	("memory_size")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(40)

0x0000069a:     DW_TAG_member
                  DW_AT_name	("align")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(48)

0x000006a4:     NULL

0x000006a5:   DW_TAG_enumeration_type
                DW_AT_name	("p_type")
                DW_AT_byte_size	(4)
                DW_AT_encoding	(DW_ATE_unsigned)
                DW_AT_type	(0x0000002e "uint32_t")

0x000006b0:     DW_TAG_enumerator
                  DW_AT_name	("PT_NULL")
                  DW_AT_const_value	(0)

0x000006b6:     DW_TAG_enumerator
                  DW_AT_name	("PT_LOAD")
                  DW_AT_const_value	(1)

0x000006bc:     DW_TAG_enumerator
                  DW_AT_name	("PT_DYNAMIC")
                  DW_AT_const_value	(2)

0x000006c2:     DW_TAG_enumerator
                  DW_AT_name	("PT_INTERP")
                  DW_AT_const_value	(3)

0x000006c8:     DW_TAG_enumerator
                  DW_AT_name	("PT_NOTE")
                  DW_AT_const_value	(4)

0x000006ce:     DW_TAG_enumerator
                  DW_AT_name	("PT_SHLIB")
                  DW_AT_const_value	(5)

0x000006d4:     DW_TAG_enumerator
                  DW_AT_name	("PT_PHDR")
                  DW_AT_const_value	(6)

0x000006da:     DW_TAG_enumerator
                  DW_AT_name	("PT_TLS")
                  DW_AT_const_value	(7)

0x000006e0:     DW_TAG_enumerator
                  DW_AT_name	("PT_NUM")
                  DW_AT_const_value	(8)

0x000006e6:     DW_TAG_enumerator
                  DW_AT_name	("PT_LOOS")
                  DW_AT_const_value	(1610612736)

0x000006f0:     DW_TAG_enumerator
                  DW_AT_name	("PT_GNU_EH_FRAME")
                  DW_AT_const_value	(1685382480)

0x000006fa:     DW_TAG_enumerator
                  DW_AT_name	("PT_GNU_STACK")
                  DW_AT_const_value	(1685382481)

0x00000704:     DW_TAG_enumerator
                  DW_AT_name	("PT_GNU_RELRO")
                  DW_AT_const_value	(1685382482)

0x0000070e:     DW_TAG_enumerator
                  DW_AT_name	("PT_GNU_PROPERTY")
                  DW_AT_const_value	(1685382483)

0x00000718:     DW_TAG_enumerator
                  DW_AT_name	("PT_LOSUNW")
                  DW_AT_const_value	(1879048186)

0x00000722:     DW_TAG_enumerator
                  DW_AT_name	("PT_SUNWBSS")
                  DW_AT_const_value	(1879048187)

0x0000072c:     DW_TAG_enumerator
                  DW_AT_name	("PT_SUNWSTACK")
                  DW_AT_const_value	(1879048186)

0x00000736:     DW_TAG_enumerator
                  DW_AT_name	("PT_MIPS_REGINFO")
                  DW_AT_const_value	(1879048192)

0x00000740:     DW_TAG_enumerator
                  DW_AT_name	("PT_MIPS_RTPROC")
                  DW_AT_const_value	(1879048193)

0x0000074a:     DW_TAG_enumerator
                  DW_AT_name	("PT_MIPS_OPTIONS")
                  DW_AT_const_value	(1879048194)

0x00000754:     DW_TAG_enumerator
                  DW_AT_name	("PT_MIPS_ABIFLAGS")
                  DW_AT_const_value	(1879048195)

0x0000075e:     NULL

0x0000075f:   DW_TAG_enumeration_type
                DW_AT_name	("p_flags")
                DW_AT_byte_size	(4)
                DW_AT_encoding	(DW_ATE_unsigned)
                DW_AT_type	(0x0000002e "uint32_t")

0x0000076a:     DW_TAG_enumerator
                  DW_AT_name	("PF_X")
                  DW_AT_const_value	(1)

0x00000770:     DW_TAG_enumerator
                  DW_AT_name	("PF_W")
                  DW_AT_const_value	(2)

0x00000776:     DW_TAG_enumerator
                  DW_AT_name	("PF_R")
                  DW_AT_const_value	(4)

0x0000077c:     NULL

0x0000077d:   DW_TAG_array_type
                DW_AT_type	(0x0000064e "Elf64_ProgramHeader")

0x00000782:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(12)

0x00000788:     NULL

0x00000789:   DW_TAG_structure_type
                DW_AT_name	("Elf64_Rela")
                DW_AT_byte_size	(24)

0x0000078f:     DW_TAG_member
                  DW_AT_name	("r_offset")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(0)

0x00000799:     DW_TAG_member
                  DW_AT_name	("r_info")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(8)

0x000007a3:     DW_TAG_member
                  DW_AT_name	("r_addend")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_data_member_location	(16)

0x000007ad:     NULL

0x000007ae:   DW_TAG_array_type
                DW_AT_type	(0x00000789 "Elf64_Rela")

0x000007b3:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(3)

0x000007b9:     NULL

0x000007ba:   DW_TAG_structure_type
                DW_AT_name	("Elf64_SectionHeader")
                DW_AT_byte_size	(64)

0x000007c0:     DW_TAG_member
                  DW_AT_name	("name")
                  DW_AT_type	(0x0000002e "uint32_t")
                  DW_AT_data_member_location	(0)

0x000007ca:     DW_TAG_member
                  DW_AT_name	("type")
                  DW_AT_type	(0x00000825 "sh_type")
                  DW_AT_data_member_location	(4)

0x000007d4:     DW_TAG_member
                  DW_AT_name	("flags")
                  DW_AT_type	(0x00000897 "sh_flags")
                  DW_AT_data_member_location	(8)

0x000007de:     DW_TAG_member
                  DW_AT_name	("address")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(16)

0x000007e8:     DW_TAG_member
                  DW_AT_name	("offset")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(24)

0x000007f2:     DW_TAG_member
                  DW_AT_name	("size")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(32)

0x000007fc:     DW_TAG_member
                  DW_AT_name	("link")
                  DW_AT_type	(0x0000002e "uint32_t")
                  DW_AT_data_member_location	(40)

0x00000806:     DW_TAG_member
                  DW_AT_name	("info")
                  DW_AT_type	(0x0000002e "uint32_t")
                  DW_AT_data_member_location	(44)

0x00000810:     DW_TAG_member
                  DW_AT_name	("align")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(48)

0x0000081a:     DW_TAG_member
                  DW_AT_name	("entry_size")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(56)

0x00000824:     NULL

0x00000825:   DW_TAG_enumeration_type
                DW_AT_name	("sh_type")
                DW_AT_byte_size	(4)
                DW_AT_encoding	(DW_ATE_unsigned)
                DW_AT_type	(0x0000002e "uint32_t")

0x00000830:     DW_TAG_enumerator
                  DW_AT_name	("SHT_NULL")
                  DW_AT_const_value	(0)

0x00000836:     DW_TAG_enumerator
                  DW_AT_name	("SHT_PROGBITS")
                  DW_AT_const_value	(1)

0x0000083c:     DW_TAG_enumerator
                  DW_AT_name	("SHT_SYMTAB")
                  DW_AT_const_value	(2)

0x00000842:     DW_TAG_enumerator
                  DW_AT_name	("SHT_STRTAB")
                  DW_AT_const_value	(3)

0x00000848:     DW_TAG_enumerator
                  DW_AT_name	("SHT_RELA")
                  DW_AT_const_value	(4)

0x0000084e:     DW_TAG_enumerator
                  DW_AT_name	("SHT_HASH")
                  DW_AT_const_value	(5)

0x00000854:     DW_TAG_enumerator
                  DW_AT_name	("SHT_DYNAMIC")
                  DW_AT_const_value	(6)

0x0000085a:     DW_TAG_enumerator
                  DW_AT_name	("SHT_NOTE")
                  DW_AT_const_value	(7)

0x00000860:     DW_TAG_enumerator
                  DW_AT_name	("SHT_NOBITS")
                  DW_AT_const_value	(8)

0x00000866:     DW_TAG_enumerator
                  DW_AT_name	("SHT_REL")
                  DW_AT_const_value	(9)

0x0000086c:     DW_TAG_enumerator
                  DW_AT_name	("SHT_SHLIB")
                  DW_AT_const_value	(10)

0x00000872:     DW_TAG_enumerator
                  DW_AT_name	("SHT_DYNSYM")
                  DW_AT_const_value	(11)

0x00000878:     DW_TAG_enumerator
                  DW_AT_name	("SHT_LOUSER")
                  DW_AT_const_value	(2147483648)

0x00000882:     DW_TAG_enumerator
                  DW_AT_name	("SHT_HIUSER")
                  DW_AT_const_value	(4294967295)

0x0000088c:     DW_TAG_enumerator
                  DW_AT_name	("SHT_AMD64_UNWIND")
                  DW_AT_const_value	(1879048193)

0x00000896:     NULL

0x00000897:   DW_TAG_enumeration_type
                DW_AT_name	("sh_flags")
                DW_AT_byte_size	(8)
                DW_AT_encoding	(DW_ATE_unsigned)
                DW_AT_type	(0x00000019 "uint64_t")

0x000008a2:     DW_TAG_enumerator
                  DW_AT_name	("SHF_WRITE")
                  DW_AT_const_value	(1)

0x000008a8:     DW_TAG_enumerator
                  DW_AT_name	("SHF_ALLOC")
                  DW_AT_const_value	(2)

0x000008ae:     DW_TAG_enumerator
                  DW_AT_name	("SHF_EXECINSTR")
                  DW_AT_const_value	(4)

0x000008b4:     DW_TAG_enumerator
                  DW_AT_name	("SHF_MERGE")
                  DW_AT_const_value	(16)

0x000008ba:     DW_TAG_enumerator
                  DW_AT_name	("SHF_STRINGS")
                  DW_AT_const_value	(32)

0x000008c0:     DW_TAG_enumerator
                  DW_AT_name	("SHF_INFO_LINK")
                  DW_AT_const_value	(64)

0x000008c6:     DW_TAG_enumerator
                  DW_AT_name	("SHF_LINK_ORDER")
                  DW_AT_const_value	(128)

0x000008cd:     DW_TAG_enumerator
                  DW_AT_name	("SHF_OS_NONCONFORMING")
                  DW_AT_const_value	(256)

0x000008d4:     DW_TAG_enumerator
                  DW_AT_name	("SHF_GROUP")
                  DW_AT_const_value	(512)

0x000008db:     DW_TAG_enumerator
                  DW_AT_name	("SHF_TLS")
                  DW_AT_const_value	(1024)

0x000008e2:     DW_TAG_enumerator
                  DW_AT_name	("SHF_COMPRESSED")
                  DW_AT_const_value	(2048)

0x000008e9:     DW_TAG_enumerator
                  DW_AT_name	("SHF_MASKOS")
                  DW_AT_const_value	(267386880)

0x000008f2:     DW_TAG_enumerator
                  DW_AT_name	("SHF_AMD64_LARGE")
                  DW_AT_const_value	(268435456)

0x000008fc:     NULL

0x000008fd:   DW_TAG_structure_type
                DW_AT_name	("Elf64_Sym")
                DW_AT_byte_size	(24)

0x00000903:     DW_TAG_member
                  DW_AT_name	("st_name")
                  DW_AT_type	(0x0000002e "uint32_t")
                  DW_AT_data_member_location	(0)

0x0000090d:     DW_TAG_member
                  DW_AT_name	("st_info")
                  DW_AT_type	(0x00000027 "uint8_t")
                  DW_AT_data_member_location	(4)

0x00000917:     DW_TAG_member
                  DW_AT_name	("st_other")
                  DW_AT_type	(0x00000027 "uint8_t")
                  DW_AT_data_member_location	(5)

0x00000921:     DW_TAG_member
                  DW_AT_name	("st_shndx")
                  DW_AT_type	(0x00000035 "uint16_t")
                  DW_AT_data_member_location	(6)

0x0000092b:     DW_TAG_member
                  DW_AT_name	("st_value")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(8)

0x00000935:     DW_TAG_member
                  DW_AT_name	("st_size")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(16)

0x0000093f:     NULL

0x00000940:   DW_TAG_array_type
                DW_AT_type	(0x000008fd "Elf64_Sym")

0x00000945:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(14)

0x0000094b:     NULL

0x0000094c:   DW_TAG_typedef
                DW_AT_name	("FILE")
                DW_AT_type	(0x00000955 "_IO_FILE")

0x00000955:   DW_TAG_structure_type
                DW_AT_name	("_IO_FILE")
                DW_AT_byte_size	(216)

0x0000095c:     DW_TAG_member
                  DW_AT_name	("_flags")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(0)

0x00000966:     DW_TAG_member
                  DW_AT_name	("_IO_read_ptr")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(8)

0x00000970:     DW_TAG_member
                  DW_AT_name	("_IO_read_end")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(16)

0x0000097a:     DW_TAG_member
                  DW_AT_name	("_IO_read_base")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(24)

0x00000984:     DW_TAG_member
                  DW_AT_name	("_IO_write_base")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(32)

0x0000098e:     DW_TAG_member
                  DW_AT_name	("_IO_write_ptr")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(40)

0x00000998:     DW_TAG_member
                  DW_AT_name	("_IO_write_end")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(48)

0x000009a2:     DW_TAG_member
                  DW_AT_name	("_IO_buf_base")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(56)

0x000009ac:     DW_TAG_member
                  DW_AT_name	("_IO_buf_end")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(64)

0x000009b6:     DW_TAG_member
                  DW_AT_name	("_IO_save_base")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(72)

0x000009c0:     DW_TAG_member
                  DW_AT_name	("_IO_backup_base")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(80)

0x000009ca:     DW_TAG_member
                  DW_AT_name	("_IO_save_end")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(88)

0x000009d4:     DW_TAG_member
                  DW_AT_name	("_markers")
                  DW_AT_type	(0x00000a91 "_IO_marker *")
                  DW_AT_data_member_location	(96)

0x000009de:     DW_TAG_member
                  DW_AT_name	("_chain")
                  DW_AT_type	(0x00000abe "_IO_FILE *")
                  DW_AT_data_member_location	(104)

0x000009e8:     DW_TAG_member
                  DW_AT_name	("_fileno")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(112)

0x000009f2:     DW_TAG_member
                  DW_AT_name	("_flags2")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(116)

0x000009fc:     DW_TAG_member
                  DW_AT_name	("_old_offset")
                  DW_AT_type	(0x00000ac4 "__off_t")
                  DW_AT_data_member_location	(120)

0x00000a06:     DW_TAG_member
                  DW_AT_name	("_cur_column")
                  DW_AT_type	(0x00000035 "uint16_t")
                  DW_AT_data_member_location	(128)

0x00000a11:     DW_TAG_member
                  DW_AT_name	("_vtable_offset")
                  DW_AT_type	(0x00000020 "char")
                  DW_AT_data_member_location	(130)

0x00000a1c:     DW_TAG_member
                  DW_AT_name	("_shortbuf")
                  DW_AT_type	(0x00000acd "char[1]")
                  DW_AT_data_member_location	(131)

0x00000a27:     DW_TAG_member
                  DW_AT_name	("_lock")
                  DW_AT_type	(0x00000ad9 "_IO_lock_t *")
                  DW_AT_data_member_location	(136)

0x00000a32:     DW_TAG_member
                  DW_AT_name	("_offset")
                  DW_AT_type	(0x00000b04 "__off64_t")
                  DW_AT_data_member_location	(144)

0x00000a3d:     DW_TAG_member
                  DW_AT_name	("_codecvt")
                  DW_AT_type	(0x00000b0d "_IO_codecvt *")
                  DW_AT_data_member_location	(152)

0x00000a48:     DW_TAG_member
                  DW_AT_name	("_wide_data")
                  DW_AT_type	(0x00000d40 "_IO_wide_data *")
                  DW_AT_data_member_location	(160)

0x00000a53:     DW_TAG_member
                  DW_AT_name	("_freeres_list")
                  DW_AT_type	(0x00000abe "_IO_FILE *")
                  DW_AT_data_member_location	(168)

0x00000a5e:     DW_TAG_member
                  DW_AT_name	("_freeres_buf")
                  DW_AT_type	(0x00000abc "void *")
                  DW_AT_data_member_location	(176)

0x00000a69:     DW_TAG_member
                  DW_AT_name	("__pad5")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_data_member_location	(184)

0x00000a74:     DW_TAG_member
                  DW_AT_name	("_mode")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(192)

0x00000a7f:     DW_TAG_member
                  DW_AT_name	("_unused2")
                  DW_AT_type	(0x00000e0b "char[20]")
                  DW_AT_data_member_location	(196)

0x00000a8a:     NULL

0x00000a8b:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000020 "char")

0x00000a91:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000a97 "_IO_marker")

0x00000a97:   DW_TAG_structure_type
                DW_AT_name	("_IO_marker")
                DW_AT_byte_size	(24)

0x00000a9d:     DW_TAG_member
                  DW_AT_name	("_next")
                  DW_AT_type	(0x00000abc "void *")
                  DW_AT_data_member_location	(0)

0x00000aa7:     DW_TAG_member
                  DW_AT_name	("_sbuf")
                  DW_AT_type	(0x00000abc "void *")
                  DW_AT_data_member_location	(8)

0x00000ab1:     DW_TAG_member
                  DW_AT_name	("_pos")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(16)

0x00000abb:     NULL

0x00000abc:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)

0x00000abe:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000955 "_IO_FILE")

0x00000ac4:   DW_TAG_typedef
                DW_AT_name	("__off_t")
                DW_AT_type	(0x0000003c "int64_t")

0x00000acd:   DW_TAG_array_type
                DW_AT_type	(0x00000020 "char")

0x00000ad2:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(0)

0x00000ad8:     NULL

0x00000ad9:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000adf "_IO_lock_t")

0x00000adf:   DW_TAG_structure_type
                DW_AT_name	("_IO_lock_t")
                DW_AT_byte_size	(16)

0x00000ae5:     DW_TAG_member
                  DW_AT_name	("lock")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(0)

0x00000aef:     DW_TAG_member
                  DW_AT_name	("cnt")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(4)

0x00000af9:     DW_TAG_member
                  DW_AT_name	("owner")
                  DW_AT_type	(0x00000abc "void *")
                  DW_AT_data_member_location	(8)

0x00000b03:     NULL

0x00000b04:   DW_TAG_typedef
                DW_AT_name	("__off64_t")
                DW_AT_type	(0x0000003c "int64_t")

0x00000b0d:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000b13 "_IO_codecvt")

0x00000b13:   DW_TAG_structure_type
                DW_AT_name	("_IO_codecvt")
                DW_AT_byte_size	(112)

0x00000b19:     DW_TAG_member
                  DW_AT_name	("__cd_in")
                  DW_AT_type	(0x00000b2e "_IO_iconv_t")
                  DW_AT_data_member_location	(0)

0x00000b23:     DW_TAG_member
                  DW_AT_name	("__cd_out")
                  DW_AT_type	(0x00000b2e "_IO_iconv_t")
                  DW_AT_data_member_location	(56)

0x00000b2d:     NULL

0x00000b2e:   DW_TAG_structure_type
                DW_AT_name	("_IO_iconv_t")
                DW_AT_byte_size	(56)

0x00000b34:     DW_TAG_member
                  DW_AT_name	("step")
                  DW_AT_type	(0x00000b49 "__gconv_step *")
                  DW_AT_data_member_location	(0)

0x00000b3e:     DW_TAG_member
                  DW_AT_name	("step_data")
                  DW_AT_type	(0x00000c42 "__gconv_step_data")
                  DW_AT_data_member_location	(8)

0x00000b48:     NULL

0x00000b49:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000b4f "__gconv_step")

0x00000b4f:   DW_TAG_structure_type
                DW_AT_name	("__gconv_step")
                DW_AT_byte_size	(104)

0x00000b55:     DW_TAG_member
                  DW_AT_name	("__shlib_handle")
                  DW_AT_type	(0x00000abc "void *")
                  DW_AT_data_member_location	(0)

0x00000b5f:     DW_TAG_member
                  DW_AT_name	("__modname")
                  DW_AT_type	(0x00000bf8 "char const *")
                  DW_AT_data_member_location	(8)

0x00000b69:     DW_TAG_member
                  DW_AT_name	("__counter")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(16)

0x00000b73:     DW_TAG_member
                  DW_AT_name	("__from_name")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(24)

0x00000b7d:     DW_TAG_member
                  DW_AT_name	("__to_name")
                  DW_AT_type	(0x00000a8b "char *")
                  DW_AT_data_member_location	(32)

0x00000b87:     DW_TAG_member
                  DW_AT_name	("__fct")
                  DW_AT_type	(0x00000bfe "__gconv_fct")
                  DW_AT_data_member_location	(40)

0x00000b91:     DW_TAG_member
                  DW_AT_name	("__fct")
                  DW_AT_data_member_location	(40)

0x00000b97:     DW_TAG_member
                  DW_AT_name	("__fct")
                  DW_AT_data_member_location	(40)

0x00000b9d:     DW_TAG_member
                  DW_AT_name	("__btowc_fct")
                  DW_AT_type	(0x00000ce5 "__gconv_btowc_fct")
                  DW_AT_data_member_location	(48)

0x00000ba7:     DW_TAG_member
                  DW_AT_name	("__init_fct")
                  DW_AT_type	(0x00000d0e "__gconv_init_fct")
                  DW_AT_data_member_location	(56)

0x00000bb1:     DW_TAG_member
                  DW_AT_name	("__end_fct")
                  DW_AT_type	(0x00000d29 "__gconv_end_fct")
                  DW_AT_data_member_location	(64)

0x00000bbb:     DW_TAG_member
                  DW_AT_name	("__min_needed_from")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(72)

0x00000bc5:     DW_TAG_member
                  DW_AT_name	("__max_needed_from")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(76)

0x00000bcf:     DW_TAG_member
                  DW_AT_name	("__min_needed_to")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(80)

0x00000bd9:     DW_TAG_member
                  DW_AT_name	("__max_needed_to")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(84)

0x00000be3:     DW_TAG_member
                  DW_AT_name	("__stateful")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(88)

0x00000bed:     DW_TAG_member
                  DW_AT_name	("__data")
                  DW_AT_type	(0x00000abc "void *")
                  DW_AT_data_member_location	(96)

0x00000bf7:     NULL

0x00000bf8:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x0000004a "char const")

0x00000bfe:   DW_TAG_typedef
                DW_AT_name	("__gconv_fct")
                DW_AT_type	(0x00000c07 "int32_t (*)(void *, __gconv_step_data *, uint8_t const **, uint8_t const *, uint8_t **, uint64_t *, int32_t, int32_t)")

0x00000c07:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000c0d "int32_t (void *, __gconv_step_data *, uint8_t const **, uint8_t const *, uint8_t **, uint64_t *, int32_t, int32_t)")

0x00000c0d:   DW_TAG_subroutine_type
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x00000043 "int32_t")

0x00000c13:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000abc "void *")

0x00000c18:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000c3c "__gconv_step_data *")

0x00000c1d:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000ccd "uint8_t const **")

0x00000c22:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000cd3 "uint8_t const *")

0x00000c27:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000cd9 "uint8_t **")

0x00000c2c:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000cdf "uint64_t *")

0x00000c31:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000043 "int32_t")

0x00000c36:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000043 "int32_t")

0x00000c3b:     NULL

0x00000c3c:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000c42 "__gconv_step_data")

0x00000c42:   DW_TAG_structure_type
                DW_AT_name	("__gconv_step_data")
                DW_AT_byte_size	(48)

0x00000c48:     DW_TAG_member
                  DW_AT_name	("__outbuf")
                  DW_AT_type	(0x00000c8f "uint8_t *")
                  DW_AT_data_member_location	(0)

0x00000c52:     DW_TAG_member
                  DW_AT_name	("__outbufend")
                  DW_AT_type	(0x00000c8f "uint8_t *")
                  DW_AT_data_member_location	(8)

0x00000c5c:     DW_TAG_member
                  DW_AT_name	("__flags")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(16)

0x00000c66:     DW_TAG_member
                  DW_AT_name	("__invocation_counter")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(20)

0x00000c70:     DW_TAG_member
                  DW_AT_name	("__internal_use")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(24)

0x00000c7a:     DW_TAG_member
                  DW_AT_name	("__statep")
                  DW_AT_type	(0x00000c95 "__mbstate_t *")
                  DW_AT_data_member_location	(32)

0x00000c84:     DW_TAG_member
                  DW_AT_name	("__state")
                  DW_AT_type	(0x00000c9b "__mbstate_t")
                  DW_AT_data_member_location	(40)

0x00000c8e:     NULL

0x00000c8f:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000027 "uint8_t")

0x00000c95:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000c9b "__mbstate_t")

0x00000c9b:   DW_TAG_structure_type
                DW_AT_name	("__mbstate_t")
                DW_AT_byte_size	(8)

0x00000ca1:     DW_TAG_member
                  DW_AT_name	("__count")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_data_member_location	(0)

0x00000cab:     DW_TAG_member
                  DW_AT_name	("__value")
                  DW_AT_type	(0x00000cb6 "union ")
                  DW_AT_data_member_location	(4)

0x00000cb5:     NULL

0x00000cb6:   DW_TAG_union_type
                DW_AT_byte_size	(4)

0x00000cb8:     DW_TAG_member
                  DW_AT_name	("__wch")
                  DW_AT_type	(0x0000002e "uint32_t")
                  DW_AT_data_member_location	(0)

0x00000cc2:     DW_TAG_member
                  DW_AT_name	("__wchb")
                  DW_AT_type	(0x0000040d "char[4]")
                  DW_AT_data_member_location	(0)

0x00000ccc:     NULL

0x00000ccd:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000cd3 "uint8_t const *")

0x00000cd3:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000051 "uint8_t const")

0x00000cd9:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000c8f "uint8_t *")

0x00000cdf:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000019 "uint64_t")

0x00000ce5:   DW_TAG_typedef
                DW_AT_name	("__gconv_btowc_fct")
                DW_AT_type	(0x00000cee "wint_t (*)(void *, uint8_t)")

0x00000cee:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000cf4 "wint_t (void *, uint8_t)")

0x00000cf4:   DW_TAG_subroutine_type
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x00000d05 "wint_t")

0x00000cfa:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000abc "void *")

0x00000cff:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000027 "uint8_t")

0x00000d04:     NULL

0x00000d05:   DW_TAG_typedef
                DW_AT_name	("wint_t")
                DW_AT_type	(0x0000002e "uint32_t")

0x00000d0e:   DW_TAG_typedef
                DW_AT_name	("__gconv_init_fct")
                DW_AT_type	(0x00000d17 "int32_t (*)(void *)")

0x00000d17:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000d1d "int32_t (void *)")

0x00000d1d:   DW_TAG_subroutine_type
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x00000043 "int32_t")

0x00000d23:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000abc "void *")

0x00000d28:     NULL

0x00000d29:   DW_TAG_typedef
                DW_AT_name	("__gconv_end_fct")
                DW_AT_type	(0x00000d32 "void (*)(void *)")

0x00000d32:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000d38 "void (void *)")

0x00000d38:   DW_TAG_subroutine_type
                DW_AT_prototyped	(0x01)

0x00000d3a:     DW_TAG_formal_parameter
                  DW_AT_type	(0x00000abc "void *")

0x00000d3f:     NULL

0x00000d40:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000d46 "_IO_wide_data")

0x00000d46:   DW_TAG_structure_type
                DW_AT_name	("_IO_wide_data")
                DW_AT_byte_size	(232)

0x00000d4d:     DW_TAG_member
                  DW_AT_name	("_IO_read_ptr")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(0)

0x00000d57:     DW_TAG_member
                  DW_AT_name	("_IO_read_end")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(8)

0x00000d61:     DW_TAG_member
                  DW_AT_name	("_IO_read_base")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(16)

0x00000d6b:     DW_TAG_member
                  DW_AT_name	("_IO_write_base")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(24)

0x00000d75:     DW_TAG_member
                  DW_AT_name	("_IO_write_ptr")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(32)

0x00000d7f:     DW_TAG_member
                  DW_AT_name	("_IO_write_end")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(40)

0x00000d89:     DW_TAG_member
                  DW_AT_name	("_IO_buf_base")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(48)

0x00000d93:     DW_TAG_member
                  DW_AT_name	("_IO_buf_end")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(56)

0x00000d9d:     DW_TAG_member
                  DW_AT_name	("_IO_save_base")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(64)

0x00000da7:     DW_TAG_member
                  DW_AT_name	("_IO_backup_base")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(72)

0x00000db1:     DW_TAG_member
                  DW_AT_name	("_IO_save_end")
                  DW_AT_type	(0x00000df0 "wchar_t *")
                  DW_AT_data_member_location	(80)

0x00000dbb:     DW_TAG_member
                  DW_AT_name	("_IO_state")
                  DW_AT_type	(0x00000c9b "__mbstate_t")
                  DW_AT_data_member_location	(88)

0x00000dc5:     DW_TAG_member
                  DW_AT_name	("_IO_last_state")
                  DW_AT_type	(0x00000c9b "__mbstate_t")
                  DW_AT_data_member_location	(96)

0x00000dcf:     DW_TAG_member
                  DW_AT_name	("_codecvt")
                  DW_AT_type	(0x00000b13 "_IO_codecvt")
                  DW_AT_data_member_location	(104)

0x00000dd9:     DW_TAG_member
                  DW_AT_name	("_shortbuf")
                  DW_AT_type	(0x00000dff "wchar_t[1]")
                  DW_AT_data_member_location	(216)

0x00000de4:     DW_TAG_member
                  DW_AT_name	("_wide_vtable")
                  DW_AT_type	(0x00000abc "void *")
                  DW_AT_data_member_location	(224)

0x00000def:     NULL

0x00000df0:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000df6 "wchar_t")

0x00000df6:   DW_TAG_typedef
                DW_AT_name	("wchar_t")
                DW_AT_type	(0x00000043 "int32_t")

0x00000dff:   DW_TAG_array_type
                DW_AT_type	(0x00000df6 "wchar_t")

0x00000e04:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(0)

0x00000e0a:     NULL

0x00000e0b:   DW_TAG_array_type
                DW_AT_type	(0x00000020 "char")

0x00000e10:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(19)

0x00000e16:     NULL

0x00000e17:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x0000094c "FILE")

0x00000e1d:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000a8b "char *")

0x00000e23:   DW_TAG_array_type
                DW_AT_type	(0x00000020 "char")

0x00000e28:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(27)

0x00000e2e:     NULL

0x00000e2f:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)
                DW_AT_type	(0x00000019 "uint64_t")

0x00000e35:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)

0x00000e37:   DW_TAG_array_type
                DW_AT_type	(0x00000646 "void (*)()")

0x00000e3c:     DW_TAG_subrange_type
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_upper_bound	(0)

0x00000e42:     NULL

0x00000e43:   DW_TAG_pointer_type
                DW_AT_byte_size	(8)

0x00000e45:   DW_TAG_variable
                DW_AT_name	("__elf_header")
                DW_AT_type	(0x0000032d "Elf64_Header")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x400000)

0x00000e59:   DW_TAG_variable
                DW_AT_name	("__elf_program_headers")
                DW_AT_type	(0x0000077d "Elf64_ProgramHeader[13]")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x400040)

0x00000e6d:   DW_TAG_variable
                DW_AT_name	("__elf_interp")
                DW_AT_type	(0x00000e23 "char[28]")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x400318)

0x00000e81:   DW_TAG_variable
                DW_AT_name	("__abi_tag")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x40038c)

0x00000e91:   DW_TAG_variable
                DW_AT_name	("__elf_symbol_table")
                DW_AT_type	(0x00000940 "Elf64_Sym[15]")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x4003d8)

0x00000ea5:   DW_TAG_variable
                DW_AT_name	("__elf_rela_table")
                DW_AT_type	(0x000007ae "Elf64_Rela[4]")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x400660)

0x00000eb9:   DW_TAG_variable
                DW_AT_name	("_IO_stdin_used")
                DW_AT_type	(0x0000002e "uint32_t")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x402000)

0x00000ecd:   DW_TAG_variable
                DW_AT_name	("__GNU_EH_FRAME_HDR")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x402108)

0x00000edd:   DW_TAG_variable
                DW_AT_name	("__FRAME_END__")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x40233c)

0x00000eed:   DW_TAG_variable
                DW_AT_name	("__frame_dummy_init_array_entry")
                DW_AT_type	(0x00000e37 "void (*[1]")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x403df8)

0x00000f01:   DW_TAG_variable
                DW_AT_name	("__do_global_dtors_aux_fini_array_entry")
                DW_AT_type	(0x00000e37 "void (*[1]")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x403e00)

0x00000f15:   DW_TAG_variable
                DW_AT_name	("_DYNAMIC")
                DW_AT_type	(0x00000321 "Elf64_Dyn[24]")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x403e08)

0x00000f29:   DW_TAG_variable
                DW_AT_name	("_GLOBAL_OFFSET_TABLE_")
                DW_AT_type	(0x00000abc "void *")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x403fe8)

0x00000f3d:   DW_TAG_variable
                DW_AT_name	("data_start")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x404050)

0x00000f4d:   DW_TAG_variable
                DW_AT_name	("__dso_handle")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x404058)

0x00000f5d:   DW_TAG_variable
                DW_AT_name	("stdout@GLIBC_2.2.5")
                DW_AT_type	(0x00000e2f "uint64_t *")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x404060)

0x00000f71:   DW_TAG_variable
                DW_AT_name	("stdin@GLIBC_2.2.5")
                DW_AT_type	(0x00000e2f "uint64_t *")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x404070)

0x00000f85:   DW_TAG_variable
                DW_AT_name	("completed.0")
                DW_AT_type	(0x00000027 "uint8_t")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x404078)

0x00000f99:   DW_TAG_variable
                DW_AT_name	("number_of_games")
                DW_AT_type	(0x00000019 "uint64_t")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x404080)

0x00000fad:   DW_TAG_variable
                DW_AT_name	("game_history")
                DW_AT_type	(0x00000019 "uint64_t")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x404088)

0x00000fc1:   DW_TAG_variable
                DW_AT_name	("seed")
                DW_AT_type	(0x00000019 "uint64_t")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x404090)

0x00000fd5:   DW_TAG_variable
                DW_AT_name	("seed_generator")
                DW_AT_type	(0x00000019 "uint64_t")
                DW_AT_external	(0x01)
                DW_AT_location	(DW_OP_addr 0x404098)

0x00000fe9:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("_init")
                DW_AT_prototyped	(0x01)
                DW_AT_low_pc	(4198400)
                DW_AT_high_pc	(4198427)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00000ffa:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_location	(DW_OP_fbreg -8)

0x00001002:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x0000100e:     NULL

0x0000100f:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_401020")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198432)
                DW_AT_high_pc	(4198444)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001024:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x00001030:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x0000103c:     NULL

0x0000103d:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_401030")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198448)
                DW_AT_high_pc	(4198462)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001052:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x0000105e:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x0000106a:     NULL

0x0000106b:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_401040")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198464)
                DW_AT_high_pc	(4198478)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001080:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x0000108c:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001098:     NULL

0x00001099:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_401050")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198480)
                DW_AT_high_pc	(4198494)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000010ae:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x000010ba:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000010c6:     NULL

0x000010c7:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_401060")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198496)
                DW_AT_high_pc	(4198510)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000010dc:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x000010e8:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000010f4:     NULL

0x000010f5:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_401070")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198512)
                DW_AT_high_pc	(4198526)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x0000110a:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x00001116:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001122:     NULL

0x00001123:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_401080")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198528)
                DW_AT_high_pc	(4198542)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001138:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x00001144:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001150:     NULL

0x00001151:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_401090")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198544)
                DW_AT_high_pc	(4198558)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001166:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x00001172:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x0000117e:     NULL

0x0000117f:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_4010a0")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198560)
                DW_AT_high_pc	(4198574)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001194:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x000011a0:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000011ac:     NULL

0x000011ad:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_4010b0")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198576)
                DW_AT_high_pc	(4198590)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000011c2:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x000011ce:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000011da:     NULL

0x000011db:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("sub_4010c0")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198592)
                DW_AT_high_pc	(4198606)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000011f0:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x000011fc:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001208:     NULL

0x00001209:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("_start")
                DW_AT_prototyped	(0x01)
                DW_AT_low_pc	(4198768)
                DW_AT_high_pc	(4198805)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x0000121a:     DW_TAG_formal_parameter
                  DW_AT_name	("arg1")
                  DW_AT_type	(0x0000003c "int64_t")

0x00001223:     DW_TAG_formal_parameter
                  DW_AT_name	("arg2")
                  DW_AT_type	(0x0000003c "int64_t")

0x0000122c:     DW_TAG_formal_parameter
                  DW_AT_name	("arg3")
                  DW_AT_type	(0x00000646 "void (*)()")

0x00001235:     DW_TAG_variable
                  DW_AT_name	("var_10")
                  DW_AT_type	(0x00000abc "void *")
                  DW_AT_location	(DW_OP_fbreg -16)

0x00001241:     DW_TAG_variable
                  DW_AT_name	("stack_end")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x0000124d:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001259:     DW_TAG_variable
                  DW_AT_name	("ubp_av")
                  DW_AT_location	(DW_OP_fbreg +8)

0x00001261:     NULL

0x00001262:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("_dl_relocate_static_pie")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4198816)
                DW_AT_high_pc	(4198821)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001277:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001283:     NULL

0x00001284:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("deregister_tm_clones")
                DW_AT_prototyped	(0x01)
                DW_AT_low_pc	(4198832)
                DW_AT_high_pc	(4198865)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001295:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000012a1:     NULL

0x000012a2:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("register_tm_clones")
                DW_AT_prototyped	(0x01)
                DW_AT_low_pc	(4198880)
                DW_AT_high_pc	(4198929)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000012b3:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000012bf:     NULL

0x000012c0:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("__do_global_dtors_aux")
                DW_AT_prototyped	(0x01)
                DW_AT_low_pc	(4198944)
                DW_AT_high_pc	(4198977)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000012d1:     DW_TAG_variable
                  DW_AT_name	("__saved_rbp")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x000012dd:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000012e9:     NULL

0x000012ea:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("frame_dummy")
                DW_AT_prototyped	(0x01)
                DW_AT_low_pc	(4198992)
                DW_AT_high_pc	(4198998)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000012fb:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001307:     NULL

0x00001308:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("cmp")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x00000019 "uint64_t")
                DW_AT_low_pc	(4198998)
                DW_AT_high_pc	(4199139)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x0000131d:     DW_TAG_formal_parameter
                  DW_AT_name	("arg1")
                  DW_AT_type	(0x00000019 "uint64_t")

0x00001326:     DW_TAG_formal_parameter
                  DW_AT_name	("arg2")
                  DW_AT_type	(0x00000019 "uint64_t")

0x0000132f:     DW_TAG_variable
                  DW_AT_name	("var_38")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_location	(DW_OP_fbreg -56)

0x0000133b:     DW_TAG_variable
                  DW_AT_name	("var_30")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_location	(DW_OP_fbreg -48)

0x00001347:     DW_TAG_variable
                  DW_AT_name	("var_20")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -32)

0x00001353:     DW_TAG_variable
                  DW_AT_name	("var_20_1")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -32)

0x0000135f:     DW_TAG_variable
                  DW_AT_name	("__saved_rbx")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -16)

0x0000136b:     DW_TAG_variable
                  DW_AT_name	("__saved_rbp")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x00001377:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001383:     NULL

0x00001384:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("print_menu")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4199139)
                DW_AT_high_pc	(4199230)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001399:     DW_TAG_variable
                  DW_AT_name	("__saved_rbp")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x000013a5:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000013b1:     NULL

0x000013b2:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("get_random_ull")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4199230)
                DW_AT_high_pc	(4199273)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000013c7:     DW_TAG_variable
                  DW_AT_name	("var_18")
                  DW_AT_location	(DW_OP_fbreg -24)

0x000013cf:     DW_TAG_variable
                  DW_AT_name	("__saved_rbx")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -16)

0x000013db:     DW_TAG_variable
                  DW_AT_name	("__saved_rbp")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x000013e7:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000013f3:     NULL

0x000013f4:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("fight_bot")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4199273)
                DW_AT_high_pc	(4199629)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001409:     DW_TAG_variable
                  DW_AT_name	("var_28")
                  DW_AT_location	(DW_OP_fbreg -40)

0x00001411:     DW_TAG_variable
                  DW_AT_name	("var_20")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_location	(DW_OP_fbreg -32)

0x0000141d:     DW_TAG_variable
                  DW_AT_name	("var_18")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -24)

0x00001429:     DW_TAG_variable
                  DW_AT_name	("var_10")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -16)

0x00001435:     DW_TAG_variable
                  DW_AT_name	("__saved_rbp")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x00001441:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x0000144d:     NULL

0x0000144e:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("simulate")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4199629)
                DW_AT_high_pc	(4199848)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x00001463:     DW_TAG_variable
                  DW_AT_name	("var_28")
                  DW_AT_location	(DW_OP_fbreg -40)

0x0000146b:     DW_TAG_variable
                  DW_AT_name	("var_20")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_location	(DW_OP_fbreg -32)

0x00001477:     DW_TAG_variable
                  DW_AT_name	("var_18")
                  DW_AT_type	(0x00000019 "uint64_t")
                  DW_AT_location	(DW_OP_fbreg -24)

0x00001483:     DW_TAG_variable
                  DW_AT_name	("var_10")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -16)

0x0000148f:     DW_TAG_variable
                  DW_AT_name	("__saved_rbp")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x0000149b:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000014a7:     NULL

0x000014a8:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("print_game_history")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x00000019 "uint64_t")
                DW_AT_low_pc	(4199848)
                DW_AT_high_pc	(4200000)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000014bd:     DW_TAG_variable
                  DW_AT_name	("var_18")
                  DW_AT_location	(DW_OP_fbreg -24)

0x000014c5:     DW_TAG_variable
                  DW_AT_name	("var_10")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -16)

0x000014d1:     DW_TAG_variable
                  DW_AT_name	("__saved_rbp")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x000014dd:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000014e9:     NULL

0x000014ea:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("reseed")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4200000)
                DW_AT_high_pc	(4200075)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000014ff:     DW_TAG_variable
                  DW_AT_name	("__saved_rbp")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x0000150b:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001517:     NULL

0x00001518:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("init")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x00000e17 "FILE *")
                DW_AT_low_pc	(4200075)
                DW_AT_high_pc	(4200148)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x0000152d:     DW_TAG_variable
                  DW_AT_name	("__saved_rbp")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x00001539:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001545:     NULL

0x00001546:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("main")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x00000043 "int32_t")
                DW_AT_low_pc	(4200148)
                DW_AT_high_pc	(4200327)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x0000155b:     DW_TAG_formal_parameter
                  DW_AT_name	("argc")
                  DW_AT_type	(0x00000043 "int32_t")

0x00001564:     DW_TAG_formal_parameter
                  DW_AT_name	("argv")
                  DW_AT_type	(0x00000e1d "char **")

0x0000156d:     DW_TAG_formal_parameter
                  DW_AT_name	("envp")
                  DW_AT_type	(0x00000e1d "char **")

0x00001576:     DW_TAG_variable
                  DW_AT_name	("argv_1")
                  DW_AT_type	(0x00000e1d "char **")
                  DW_AT_location	(DW_OP_fbreg -40)

0x00001582:     DW_TAG_variable
                  DW_AT_name	("argc_1")
                  DW_AT_type	(0x00000043 "int32_t")
                  DW_AT_location	(DW_OP_fbreg -28)

0x0000158e:     DW_TAG_variable
                  DW_AT_name	("var_9")
                  DW_AT_type	(0x00000020 "char")
                  DW_AT_location	(DW_OP_fbreg -9)

0x0000159a:     DW_TAG_variable
                  DW_AT_name	("var_9_1")
                  DW_AT_type	(0x00000020 "char")
                  DW_AT_location	(DW_OP_fbreg -9)

0x000015a6:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_type	(0x0000003c "int64_t")
                  DW_AT_location	(DW_OP_fbreg -8)

0x000015b2:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000015be:     NULL

0x000015bf:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("__popcountdi2")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x00000019 "uint64_t")
                DW_AT_low_pc	(4200336)
                DW_AT_high_pc	(4200430)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000015d4:     DW_TAG_formal_parameter
                  DW_AT_name	("arg1")
                  DW_AT_type	(0x0000003c "int64_t")

0x000015dd:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x000015e9:     NULL

0x000015ea:   DW_TAG_subprogram
                DW_AT_external	(0x01)
                DW_AT_name	("_fini")
                DW_AT_prototyped	(0x01)
                DW_AT_type	(0x0000003c "int64_t")
                DW_AT_low_pc	(4200432)
                DW_AT_high_pc	(4200445)
                DW_AT_frame_base	(DW_OP_call_frame_cfa)

0x000015ff:     DW_TAG_variable
                  DW_AT_name	("var_8")
                  DW_AT_location	(DW_OP_fbreg -8)

0x00001607:     DW_TAG_variable
                  DW_AT_name	("__return_addr")
                  DW_AT_type	(0x00000e43 "void *")
                  DW_AT_location	(DW_OP_fbreg +0)

0x00001613:     NULL

0x00001614:   NULL

.eh_frame contents:

00000000 0000000c 00000000 CIE
  Format:                DWARF32
  Version:               1
  Augmentation:          ""
  Code alignment factor: 1
  Data alignment factor: 1
  Return address column: 7

  DW_CFA_offset_extended_sf: RIP -8

  CFA=unspecified: RIP=[CFA-8]

00000010 00000024 00000014 FDE cie=00000000 pc=00401000...0040101b
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 16
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 2
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:

  0x401000: CFA=RSP+8: RIP=[CFA-8]
  0x401004: CFA=RSP+16: RIP=[CFA-8]
  0x401014: CFA=RSP+16: RIP=[CFA-8]
  0x401016: CFA=RSP+8: RIP=[CFA-8]

00000038 0000001c 0000003c FDE cie=00000000 pc=00401020...0040102c
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:
  DW_CFA_nop:

  0x401020: CFA=RSP+16: RIP=[CFA-8]

00000058 0000001c 0000005c FDE cie=00000000 pc=00401030...0040103e
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:

  0x401030: CFA=RSP+8: RIP=[CFA-8]
  0x401034: CFA=RSP+16: RIP=[CFA-8]

00000078 0000001c 0000007c FDE cie=00000000 pc=00401040...0040104e
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:

  0x401040: CFA=RSP+8: RIP=[CFA-8]
  0x401044: CFA=RSP+16: RIP=[CFA-8]

00000098 0000001c 0000009c FDE cie=00000000 pc=00401050...0040105e
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:

  0x401050: CFA=RSP+8: RIP=[CFA-8]
  0x401054: CFA=RSP+16: RIP=[CFA-8]

000000b8 0000001c 000000bc FDE cie=00000000 pc=00401060...0040106e
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:

  0x401060: CFA=RSP+8: RIP=[CFA-8]
  0x401064: CFA=RSP+16: RIP=[CFA-8]

000000d8 0000001c 000000dc FDE cie=00000000 pc=00401070...0040107e
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:

  0x401070: CFA=RSP+8: RIP=[CFA-8]
  0x401074: CFA=RSP+16: RIP=[CFA-8]

000000f8 0000001c 000000fc FDE cie=00000000 pc=00401080...0040108e
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:

  0x401080: CFA=RSP+8: RIP=[CFA-8]
  0x401084: CFA=RSP+16: RIP=[CFA-8]

00000118 0000001c 0000011c FDE cie=00000000 pc=00401090...0040109e
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:

  0x401090: CFA=RSP+8: RIP=[CFA-8]
  0x401094: CFA=RSP+16: RIP=[CFA-8]

00000138 0000001c 0000013c FDE cie=00000000 pc=004010a0...004010ae
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:

  0x4010a0: CFA=RSP+8: RIP=[CFA-8]
  0x4010a4: CFA=RSP+16: RIP=[CFA-8]

00000158 0000001c 0000015c FDE cie=00000000 pc=004010b0...004010be
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:

  0x4010b0: CFA=RSP+8: RIP=[CFA-8]
  0x4010b4: CFA=RSP+16: RIP=[CFA-8]

00000178 0000001c 0000017c FDE cie=00000000 pc=004010c0...004010ce
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_nop:

  0x4010c0: CFA=RSP+8: RIP=[CFA-8]
  0x4010c4: CFA=RSP+16: RIP=[CFA-8]

00000198 0000002c 0000019c FDE cie=00000000 pc=00401170...00401195
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 9
  DW_CFA_def_cfa: RSP +0
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 1
  DW_CFA_def_cfa: RSP +24
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x401170: CFA=RSP+8: RIP=[CFA-8]
  0x401179: CFA=RSP: RIP=[CFA-8]
  0x40117d: CFA=RSP+8: RIP=[CFA-8]
  0x401181: CFA=RSP+16: RIP=[CFA-8]
  0x401182: CFA=RSP+24: RIP=[CFA-8]

000001c8 0000001c 000001cc FDE cie=00000000 pc=004011a0...004011a5
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x4011a0: CFA=RSP+8: RIP=[CFA-8]

000001e8 0000001c 000001ec FDE cie=00000000 pc=004011b0...004011d1
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x4011b0: CFA=RSP+8: RIP=[CFA-8]

00000208 0000001c 0000020c FDE cie=00000000 pc=004011e0...00401211
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x4011e0: CFA=RSP+8: RIP=[CFA-8]

00000228 00000024 0000022c FDE cie=00000000 pc=00401220...00401241
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 13
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 16
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x401220: CFA=RSP+8: RIP=[CFA-8]
  0x40122d: CFA=RSP+16: RIP=[CFA-8]
  0x40123d: CFA=RSP+8: RIP=[CFA-8]

00000250 0000001c 00000254 FDE cie=00000000 pc=00401250...00401256
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x401250: CFA=RSP+8: RIP=[CFA-8]

00000270 00000034 00000274 FDE cie=00000000 pc=00401256...004012e3
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +24
  DW_CFA_advance_loc: 1
  DW_CFA_def_cfa: RSP +64
  DW_CFA_advance_loc1: 76
  DW_CFA_def_cfa: RSP +64
  DW_CFA_advance_loc: 54
  DW_CFA_def_cfa: RSP +16
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x401256: CFA=RSP+8: RIP=[CFA-8]
  0x40125a: CFA=RSP+16: RIP=[CFA-8]
  0x40125e: CFA=RSP+24: RIP=[CFA-8]
  0x40125f: CFA=RSP+64: RIP=[CFA-8]
  0x4012ab: CFA=RSP+64: RIP=[CFA-8]
  0x4012e1: CFA=RSP+8: RIP=[CFA-8]

000002a8 00000024 000002ac FDE cie=00000000 pc=004012e3...0040133e
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc1: 85
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x4012e3: CFA=RSP+8: RIP=[CFA-8]
  0x4012e7: CFA=RSP+16: RIP=[CFA-8]
  0x40133c: CFA=RSP+8: RIP=[CFA-8]

000002d0 0000002c 000002d4 FDE cie=00000000 pc=0040133e...00401369
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +24
  DW_CFA_advance_loc: 1
  DW_CFA_def_cfa: RSP +32
  DW_CFA_advance_loc: 32
  DW_CFA_def_cfa: RSP +16
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:

  0x40133e: CFA=RSP+8: RIP=[CFA-8]
  0x401342: CFA=RSP+16: RIP=[CFA-8]
  0x401346: CFA=RSP+24: RIP=[CFA-8]
  0x401347: CFA=RSP+32: RIP=[CFA-8]
  0x401367: CFA=RSP+8: RIP=[CFA-8]

00000300 0000002c 00000304 FDE cie=00000000 pc=00401369...004014cd
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +48
  DW_CFA_advance_loc2: 341
  DW_CFA_def_cfa: RSP +48
  DW_CFA_advance_loc: 5
  DW_CFA_def_cfa: RSP +16
  DW_CFA_def_cfa: RSP +8

  0x401369: CFA=RSP+8: RIP=[CFA-8]
  0x40136d: CFA=RSP+16: RIP=[CFA-8]
  0x401371: CFA=RSP+48: RIP=[CFA-8]
  0x4014c6: CFA=RSP+48: RIP=[CFA-8]
  0x4014cb: CFA=RSP+8: RIP=[CFA-8]

00000330 0000002c 00000334 FDE cie=00000000 pc=004014cd...004015a8
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +48
  DW_CFA_advance_loc1: 204
  DW_CFA_def_cfa: RSP +48
  DW_CFA_advance_loc: 5
  DW_CFA_def_cfa: RSP +16
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:

  0x4014cd: CFA=RSP+8: RIP=[CFA-8]
  0x4014d1: CFA=RSP+16: RIP=[CFA-8]
  0x4014d5: CFA=RSP+48: RIP=[CFA-8]
  0x4015a1: CFA=RSP+48: RIP=[CFA-8]
  0x4015a6: CFA=RSP+8: RIP=[CFA-8]

00000360 0000002c 00000364 FDE cie=00000000 pc=004015a8...00401640
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +32
  DW_CFA_advance_loc1: 84
  DW_CFA_def_cfa: RSP +32
  DW_CFA_advance_loc: 58
  DW_CFA_def_cfa: RSP +16
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:

  0x4015a8: CFA=RSP+8: RIP=[CFA-8]
  0x4015ac: CFA=RSP+16: RIP=[CFA-8]
  0x4015b0: CFA=RSP+32: RIP=[CFA-8]
  0x401604: CFA=RSP+32: RIP=[CFA-8]
  0x40163e: CFA=RSP+8: RIP=[CFA-8]

00000390 00000024 00000394 FDE cie=00000000 pc=00401640...0040168b
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc1: 69
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x401640: CFA=RSP+8: RIP=[CFA-8]
  0x401644: CFA=RSP+16: RIP=[CFA-8]
  0x401689: CFA=RSP+8: RIP=[CFA-8]

000003b8 00000024 000003bc FDE cie=00000000 pc=0040168b...004016d4
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc1: 67
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x40168b: CFA=RSP+8: RIP=[CFA-8]
  0x40168f: CFA=RSP+16: RIP=[CFA-8]
  0x4016d2: CFA=RSP+8: RIP=[CFA-8]

000003e0 00000024 000003e4 FDE cie=00000000 pc=004016d4...00401787
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +48
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x4016d4: CFA=RSP+8: RIP=[CFA-8]
  0x4016d8: CFA=RSP+16: RIP=[CFA-8]
  0x4016dc: CFA=RSP+48: RIP=[CFA-8]

00000408 0000001c 0000040c FDE cie=00000000 pc=00401790...004017ee
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x401790: CFA=RSP+8: RIP=[CFA-8]

00000428 00000024 0000042c FDE cie=00000000 pc=004017f0...004017fd
  Format:       DWARF32
  DW_CFA_def_cfa: RSP +8
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +16
  DW_CFA_advance_loc: 4
  DW_CFA_def_cfa: RSP +8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x4017f0: CFA=RSP+8: RIP=[CFA-8]
  0x4017f4: CFA=RSP+16: RIP=[CFA-8]
  0x4017f8: CFA=RSP+8: RIP=[CFA-8]


.debug_str contents:
0x00000000: "Elf64_Dyn"
0x0000000a: "d_tag"
0x00000010: "d_val"
0x00000016: "Elf64_Header"
0x00000023: "ident"
0x00000029: "type"
0x0000002e: "machine"
0x00000036: "version"
0x0000003e: "entry"
0x00000044: "program_header_offset"
0x0000005a: "section_header_offset"
0x00000070: "flags"
0x00000076: "header_size"
0x00000082: "program_header_size"
0x00000096: "program_header_count"
0x000000ab: "section_header_size"
0x000000bf: "section_header_count"
0x000000d4: "string_table"
0x000000e1: "Elf64_Ident"
0x000000ed: "signature"
0x000000f7: "file_class"
0x00000102: "encoding"
0x0000010b: "os"
0x0000010e: "abi_version"
0x0000011a: "pad"
0x0000011e: "Elf64_ProgramHeader"
0x00000132: "offset"
0x00000139: "virtual_address"
0x00000149: "physical_address"
0x0000015a: "file_size"
0x00000164: "memory_size"
0x00000170: "align"
0x00000176: "Elf64_Rela"
0x00000181: "r_offset"
0x0000018a: "r_info"
0x00000191: "r_addend"
0x0000019a: "Elf64_SectionHeader"
0x000001ae: "name"
0x000001b3: "address"
0x000001bb: "size"
0x000001c0: "link"
0x000001c5: "info"
0x000001ca: "entry_size"
0x000001d5: "Elf64_Sym"
0x000001df: "st_name"
0x000001e7: "st_info"
0x000001ef: "st_other"
0x000001f8: "st_shndx"
0x00000201: "st_value"
0x0000020a: "st_size"
0x00000212: "FILE"
0x00000217: "_IO_FILE"
0x00000220: "_flags"
0x00000227: "_IO_read_ptr"
0x00000234: "_IO_read_end"
0x00000241: "_IO_read_base"
0x0000024f: "_IO_write_base"
0x0000025e: "_IO_write_ptr"
0x0000026c: "_IO_write_end"
0x0000027a: "_IO_buf_base"
0x00000287: "_IO_buf_end"
0x00000293: "_IO_save_base"
0x000002a1: "_IO_backup_base"
0x000002b1: "_IO_save_end"
0x000002be: "_markers"
0x000002c7: "_chain"
0x000002ce: "_fileno"
0x000002d6: "_flags2"
0x000002de: "_old_offset"
0x000002ea: "_cur_column"
0x000002f6: "_vtable_offset"
0x00000305: "_shortbuf"
0x0000030f: "_lock"
0x00000315: "_offset"
0x0000031d: "_codecvt"
0x00000326: "_wide_data"
0x00000331: "_freeres_list"
0x0000033f: "_freeres_buf"
0x0000034c: "__pad5"
0x00000353: "_mode"
0x00000359: "_unused2"
0x00000362: "_IO_codecvt"
0x0000036e: "__cd_in"
0x00000376: "__cd_out"
0x0000037f: "_IO_iconv_t"
0x0000038b: "step"
0x00000390: "step_data"
0x0000039a: "_IO_lock_t"
0x000003a5: "lock"
0x000003aa: "cnt"
0x000003ae: "owner"
0x000003b4: "_IO_marker"
0x000003bf: "_next"
0x000003c5: "_sbuf"
0x000003cb: "_pos"
0x000003d0: "_IO_wide_data"
0x000003de: "_IO_state"
0x000003e8: "_IO_last_state"
0x000003f7: "_wide_vtable"
0x00000404: "__gconv_btowc_fct"
0x00000416: "__gconv_end_fct"
0x00000426: "__gconv_fct"
0x00000432: "__gconv_init_fct"
0x00000443: "__gconv_step"
0x00000450: "__shlib_handle"
0x0000045f: "__modname"
0x00000469: "__counter"
0x00000473: "__from_name"
0x0000047f: "__to_name"
0x00000489: "__fct"
0x0000048f: "__btowc_fct"
0x0000049b: "__init_fct"
0x000004a6: "__end_fct"
0x000004b0: "__min_needed_from"
0x000004c2: "__max_needed_from"
0x000004d4: "__min_needed_to"
0x000004e4: "__max_needed_to"
0x000004f4: "__stateful"
0x000004ff: "__data"
0x00000506: "__gconv_step_data"
0x00000518: "__outbuf"
0x00000521: "__outbufend"
0x0000052d: "__flags"
0x00000535: "__invocation_counter"
0x0000054a: "__internal_use"
0x00000559: "__statep"
0x00000562: "__state"
0x0000056a: "__mbstate_t"
0x00000576: "__count"
0x0000057e: "__value"
0x00000586: "__off64_t"
0x00000590: "__off_t"
0x00000598: "__wch"
0x0000059e: "__wchb"
0x000005a5: "char"
0x000005aa: "char const"
0x000005b5: "e_dyn_tag"
0x000005bf: "DT_NULL"
0x000005c7: "DT_NEEDED"
0x000005d1: "DT_PLTRELSZ"
0x000005dd: "DT_PLTGOT"
0x000005e7: "DT_HASH"
0x000005ef: "DT_STRTAB"
0x000005f9: "DT_SYMTAB"
0x00000603: "DT_RELA"
0x0000060b: "DT_RELASZ"
0x00000615: "DT_RELAENT"
0x00000620: "DT_STRSZ"
0x00000629: "DT_SYMENT"
0x00000633: "DT_INIT"
0x0000063b: "DT_FINI"
0x00000643: "DT_SONAME"
0x0000064d: "DT_RPATH"
0x00000656: "DT_SYMBOLIC"
0x00000662: "DT_REL"
0x00000669: "DT_RELSZ"
0x00000672: "DT_RELENT"
0x0000067c: "DT_PLTREL"
0x00000686: "DT_DEBUG"
0x0000068f: "DT_TEXTREL"
0x0000069a: "DT_JMPREL"
0x000006a4: "DT_BIND_NOW"
0x000006b0: "DT_INIT_ARRAY"
0x000006be: "DT_FINI_ARRAY"
0x000006cc: "DT_INIT_ARRAYSZ"
0x000006dc: "DT_FINI_ARRAYSZ"
0x000006ec: "DT_RUNPATH"
0x000006f7: "DT_FLAGS"
0x00000700: "DT_ENCODING"
0x0000070c: "DT_PREINIT_ARRAY"
0x0000071d: "DT_PREINIT_ARRAYSZ"
0x00000730: "DT_LOOS"
0x00000738: "DT_SUNW_RTLDINF"
0x00000748: "DT_HIOS"
0x00000750: "DT_VALRNGLO"
0x0000075c: "DT_CHECKSUM"
0x00000768: "DT_PLTPADSZ"
0x00000774: "DT_MOVEENT"
0x0000077f: "DT_MOVESZ"
0x00000789: "DT_FEATURE_1"
0x00000796: "DT_POSFLAG_1"
0x000007a3: "DT_SYMINSZ"
0x000007ae: "DT_SYMINENT"
0x000007ba: "DT_VALRNGHI"
0x000007c6: "DT_ADDRRNGLO"
0x000007d3: "DT_GNU_HASH"
0x000007df: "DT_CONFIG"
0x000007e9: "DT_DEPAUDIT"
0x000007f5: "DT_AUDIT"
0x000007fe: "DT_PLTPAD"
0x00000808: "DT_MOVETAB"
0x00000813: "DT_SYMINFO"
0x0000081e: "DT_ADDRRNGHI"
0x0000082b: "DT_RELACOUNT"
0x00000838: "DT_RELCOUNT"
0x00000844: "DT_FLAGS_1"
0x0000084f: "DT_VERDEF"
0x00000859: "DT_VERDEFNUM"
0x00000866: "DT_VERNEED"
0x00000871: "DT_VERNEEDNUM"
0x0000087f: "DT_VERSYM"
0x00000889: "DT_MIPS_RLD_VERSION"
0x0000089d: "DT_MIPS_TIME_STAMP"
0x000008b0: "DT_MIPS_ICHECKSUM"
0x000008c2: "DT_MIPS_IVERSION"
0x000008d3: "DT_MIPS_FLAGS"
0x000008e1: "DT_MIPS_BASE_ADDRESS"
0x000008f6: "DT_MIPS_CONFLICT"
0x00000907: "DT_MIPS_LIBLIST"
0x00000917: "DT_MIPS_LOCAL_GOTNO"
0x0000092b: "DT_MIPS_CONFLICTNO"
0x0000093e: "DT_MIPS_LIBLISTNO"
0x00000950: "DT_MIPS_SYMTABNO"
0x00000961: "DT_MIPS_UNREFEXTNO"
0x00000974: "DT_MIPS_GOTSYM"
0x00000983: "DT_MIPS_HIPAGENO"
0x00000994: "DT_MIPS_RLD_MAP"
0x000009a4: "DT_MIPS_RLD_MAP_REL"
0x000009b8: "e_machine"
0x000009c2: "EM_NONE"
0x000009ca: "EM_M32"
0x000009d1: "EM_SPARC"
0x000009da: "EM_386"
0x000009e1: "EM_68K"
0x000009e8: "EM_88K"
0x000009ef: "EM_860"
0x000009f6: "EM_MIPS"
0x000009fe: "EM_S370"
0x00000a06: "EM_MIPS_RS3_LE"
0x00000a15: "EM_PARISC"
0x00000a1f: "EM_VPP500"
0x00000a29: "EM_SPARC32PLUS"
0x00000a38: "EM_960"
0x00000a3f: "EM_PPC"
0x00000a46: "EM_PPC64"
0x00000a4f: "EM_S390"
0x00000a57: "EM_V800"
0x00000a5f: "EM_FR20"
0x00000a67: "EM_RH32"
0x00000a6f: "EM_RCE"
0x00000a76: "EM_ARM"
0x00000a7d: "EM_FAKE_ALPHA"
0x00000a8b: "EM_SH"
0x00000a91: "EM_SPARCV9"
0x00000a9c: "EM_TRICORE"
0x00000aa7: "EM_ARC"
0x00000aae: "EM_H8_300"
0x00000ab8: "EM_H8_300H"
0x00000ac3: "EM_H8S"
0x00000aca: "EM_H8_500"
0x00000ad4: "EM_IA_64"
0x00000add: "EM_MIPS_X"
0x00000ae7: "EM_COLDFIRE"
0x00000af3: "EM_68HC12"
0x00000afd: "EM_MMA"
0x00000b04: "EM_PCP"
0x00000b0b: "EM_NCPU"
0x00000b13: "EM_NDR1"
0x00000b1b: "EM_STARCORE"
0x00000b27: "EM_ME16"
0x00000b2f: "EM_ST100"
0x00000b38: "EM_TINYJ"
0x00000b41: "EM_X86_64"
0x00000b4b: "EM_PDSP"
0x00000b53: "EM_FX66"
0x00000b5b: "EM_ST9PLUS"
0x00000b66: "EM_ST7"
0x00000b6d: "EM_68HC16"
0x00000b77: "EM_68HC11"
0x00000b81: "EM_68HC08"
0x00000b8b: "EM_68HC05"
0x00000b95: "EM_SVX"
0x00000b9c: "EM_ST19"
0x00000ba4: "EM_VAX"
0x00000bab: "EM_CRIS"
0x00000bb3: "EM_JAVELIN"
0x00000bbe: "EM_FIREPATH"
0x00000bca: "EM_ZSP"
0x00000bd1: "EM_MMIX"
0x00000bd9: "EM_HUANY"
0x00000be2: "EM_PRISM"
0x00000beb: "EM_AVR"
0x00000bf2: "EM_FR30"
0x00000bfa: "EM_D10V"
0x00000c02: "EM_D30V"
0x00000c0a: "EM_V850"
0x00000c12: "EM_M32R"
0x00000c1a: "EM_MN10300"
0x00000c25: "EM_MN10200"
0x00000c30: "EM_PJ"
0x00000c36: "EM_OPENRISC"
0x00000c42: "EM_ARC_A5"
0x00000c4c: "EM_XTENSA"
0x00000c56: "EM_ALTERA_NIOS2"
0x00000c66: "EM_AARCH64"
0x00000c71: "EM_TILEPRO"
0x00000c7c: "EM_MICROBLAZE"
0x00000c8a: "EM_TILEGX"
0x00000c94: "EM_NUM"
0x00000c9b: "e_type"
0x00000ca2: "ET_NONE"
0x00000caa: "ET_REL"
0x00000cb1: "ET_EXEC"
0x00000cb9: "ET_DYN"
0x00000cc0: "ET_CORE"
0x00000cc8: "ET_NUM"
0x00000ccf: "int32_t"
0x00000cd7: "int64_t"
0x00000cdf: "p_flags"
0x00000ce7: "PF_X"
0x00000cec: "PF_W"
0x00000cf1: "PF_R"
0x00000cf6: "p_type"
0x00000cfd: "PT_NULL"
0x00000d05: "PT_LOAD"
0x00000d0d: "PT_DYNAMIC"
0x00000d18: "PT_INTERP"
0x00000d22: "PT_NOTE"
0x00000d2a: "PT_SHLIB"
0x00000d33: "PT_PHDR"
0x00000d3b: "PT_TLS"
0x00000d42: "PT_NUM"
0x00000d49: "PT_LOOS"
0x00000d51: "PT_GNU_EH_FRAME"
0x00000d61: "PT_GNU_STACK"
0x00000d6e: "PT_GNU_RELRO"
0x00000d7b: "PT_GNU_PROPERTY"
0x00000d8b: "PT_LOSUNW"
0x00000d95: "PT_SUNWBSS"
0x00000da0: "PT_SUNWSTACK"
0x00000dad: "PT_MIPS_REGINFO"
0x00000dbd: "PT_MIPS_RTPROC"
0x00000dcc: "PT_MIPS_OPTIONS"
0x00000ddc: "PT_MIPS_ABIFLAGS"
0x00000ded: "sh_flags"
0x00000df6: "SHF_WRITE"
0x00000e00: "SHF_ALLOC"
0x00000e0a: "SHF_EXECINSTR"
0x00000e18: "SHF_MERGE"
0x00000e22: "SHF_STRINGS"
0x00000e2e: "SHF_INFO_LINK"
0x00000e3c: "SHF_LINK_ORDER"
0x00000e4b: "SHF_OS_NONCONFORMING"
0x00000e60: "SHF_GROUP"
0x00000e6a: "SHF_TLS"
0x00000e72: "SHF_COMPRESSED"
0x00000e81: "SHF_MASKOS"
0x00000e8c: "SHF_AMD64_LARGE"
0x00000e9c: "sh_type"
0x00000ea4: "SHT_NULL"
0x00000ead: "SHT_PROGBITS"
0x00000eba: "SHT_SYMTAB"
0x00000ec5: "SHT_STRTAB"
0x00000ed0: "SHT_RELA"
0x00000ed9: "SHT_HASH"
0x00000ee2: "SHT_DYNAMIC"
0x00000eee: "SHT_NOTE"
0x00000ef7: "SHT_NOBITS"
0x00000f02: "SHT_REL"
0x00000f0a: "SHT_SHLIB"
0x00000f14: "SHT_DYNSYM"
0x00000f1f: "SHT_LOUSER"
0x00000f2a: "SHT_HIUSER"
0x00000f35: "SHT_AMD64_UNWIND"
0x00000f46: "uint16_t"
0x00000f4f: "uint32_t"
0x00000f58: "uint64_t"
0x00000f61: "uint8_t"
0x00000f69: "uint8_t const"
0x00000f77: "wchar_t"
0x00000f7f: "wint_t"
0x00000f86: "__elf_header"
0x00000f93: "__elf_program_headers"
0x00000fa9: "__elf_interp"
0x00000fb6: "__abi_tag"
0x00000fc0: "__elf_symbol_table"
0x00000fd3: "__elf_rela_table"
0x00000fe4: "_IO_stdin_used"
0x00000ff3: "__GNU_EH_FRAME_HDR"
0x00001006: "__FRAME_END__"
0x00001014: "__frame_dummy_init_array_entry"
0x00001033: "__do_global_dtors_aux_fini_array_entry"
0x0000105a: "_DYNAMIC"
0x00001063: "_GLOBAL_OFFSET_TABLE_"
0x00001079: "data_start"
0x00001084: "__dso_handle"
0x00001091: "stdout@GLIBC_2.2.5"
0x000010a4: "stdin@GLIBC_2.2.5"
0x000010b6: "completed.0"
0x000010c2: "number_of_games"
0x000010d2: "game_history"
0x000010df: "seed"
0x000010e4: "seed_generator"
0x000010f3: "_init"
0x000010f9: "var_8"
0x000010ff: "__return_addr"
0x0000110d: "sub_401020"
0x00001118: "sub_401030"
0x00001123: "sub_401040"
0x0000112e: "sub_401050"
0x00001139: "sub_401060"
0x00001144: "sub_401070"
0x0000114f: "sub_401080"
0x0000115a: "sub_401090"
0x00001165: "sub_4010a0"
0x00001170: "sub_4010b0"
0x0000117b: "sub_4010c0"
0x00001186: "_start"
0x0000118d: "arg1"
0x00001192: "arg2"
0x00001197: "arg3"
0x0000119c: "var_10"
0x000011a3: "stack_end"
0x000011ad: "ubp_av"
0x000011b4: "_dl_relocate_static_pie"
0x000011cc: "deregister_tm_clones"
0x000011e1: "register_tm_clones"
0x000011f4: "__do_global_dtors_aux"
0x0000120a: "__saved_rbp"
0x00001216: "frame_dummy"
0x00001222: "cmp"
0x00001226: "var_38"
0x0000122d: "var_30"
0x00001234: "var_20"
0x0000123b: "var_20_1"
0x00001244: "__saved_rbx"
0x00001250: "print_menu"
0x0000125b: "get_random_ull"
0x0000126a: "var_18"
0x00001271: "fight_bot"
0x0000127b: "var_28"
0x00001282: "simulate"
0x0000128b: "print_game_history"
0x0000129e: "reseed"
0x000012a5: "init"
0x000012aa: "main"
0x000012af: "argc"
0x000012b4: "argv"
0x000012b9: "envp"
0x000012be: "argv_1"
0x000012c5: "argc_1"
0x000012cc: "var_9"
0x000012d2: "var_9_1"
0x000012da: "__popcountdi2"
0x000012e8: "_fini"
0x000012ee: "llvm-dwarf"
0x000012f9: "debuginfo.c"
0x00001305: ":3"
