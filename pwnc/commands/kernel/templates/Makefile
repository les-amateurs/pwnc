build:
	zig cc exploit.c -target x86_64-linux-musl -static -Os -g -no-pie -o exploit.debug -ffunction-sections -fdata-sections -flto
	cp exploit.debug exploit
	strip exploit
	# any file copying, etc
	pwnc kernel compress