build:
	zig cc exploit.c -target x86_64-linux-musl -static -Os -s -no-pie -o exploit
	# any file copying, etc
	pwnc kernel compress