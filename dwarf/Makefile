all:
	gcc test.c -fno-eliminate-unused-debug-types -o test.debug -g3 -gdwarf-4 -pie
	llvm-dwarfdump --all test.debug > dwarf.c