def ptr_mangle(val: int, cookie: int, addrsize: int = 64, is_x86: bool = True):
    mask = (1 << addrsize) - 1
    val ^= cookie
    if is_x86:
        rotate = addrsize // 8 * 2 + 1
        val = (val << rotate & mask) | (val >> (addrsize - rotate) & mask)
    return val


def ptr_demangle(val: int, cookie: int, addrsize: int = 64, is_x86: bool = True):
    mask = (1 << addrsize) - 1
    if is_x86:
        rotate = addrsize // 8 * 2 + 1
        val = (val >> rotate & mask) | (val << (addrsize - rotate) & mask)
    return val ^ cookie
