def ptr_mangle(val: int, cookie: int, addrsize: int = 64):
    mask = (1 << addrsize) - 1
    rotate = addrsize // 8 * 2 + 1
    val ^= cookie
    return (val << rotate & mask) | (val >> (addrsize - rotate) & mask)

def ptr_demangle(val: int, cookie: int, addrsize: int = 64):
    mask = (1 << addrsize) - 1
    rotate = addrsize // 8 * 2 + 1
    val = (val >> rotate & mask) | (val << (addrsize - rotate) & mask)
    return val ^ cookie