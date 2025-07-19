all: libtroll.so

MODE=release

target/$(MODE)/libtroll.a: src/lib.rs src/main.rs
	cargo build --lib --$(MODE)

libtroll.so: target/$(MODE)/libtroll.a
	gcc -static-pie -fPIE -fPIC -o libtroll.so -Ltarget/$(MODE) -ltroll -Wl,--export-dynamic-symbol=test -Wl,--export-dynamic-symbol=acquire
	python3 fixup.py