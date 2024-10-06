import atexit
import rpyc
from pwn import log
from time import sleep

retries = 10
conn = None
while retries != 0:
    try:
        conn = rpyc.connect("0.0.0.0", 1337)
        break
    except ConnectionRefusedError:
        retries -= 1
        sleep(0.5)
else:
    log.error("failed to connect")

gdb = conn.root.gdb

try:
    import gdb
except:
    pass

def breakpoint(location: str):
    return gdb.Breakpoint(location)

def stop():
    gdb.execute("interrupt")

def cont():
    gdb.execute("continue", from_tty=True)