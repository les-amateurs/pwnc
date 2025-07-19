import ctypes

troll = ctypes.CDLL("./libtroll.so")
troll.test.restype = ctypes.c_size_t
troll.test.argtypes = [ctypes.c_int32]
troll.acquire.restype = ctypes.c_bool
troll.acquire.argtypes = [ctypes.c_size_t]

handle = troll.test(5)
print(f"handle = {handle:#x}")

print(troll.acquire(handle))
print(troll.acquire(handle))