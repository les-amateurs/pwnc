import gzip
from pwnlib.tubes.tube import tube
from pwnlib.util.lists import group
from pwnlib.util.fiddling import b64e
from pwn import log

def remote_upload(conn: tube, contents: bytes, workdir="/tmp", shell_prefix=b"$ ", chunk_size=500):
    exploit = gzip.compress(contents)
    # context.log_level = "debug"
    conn.sendlineafter(shell_prefix, f"cd {workdir}".encode())

    with log.progress("Uploading exploit...") as p:
        for i, c in enumerate(group(chunk_size, exploit)):
            conn.sendlineafter(shell_prefix, b"echo %s | base64 -d >> pwn.gz" % b64e(c).encode())
            p.status(f"{100 * i * chunk_size // len(exploit)}%")

    conn.sendlineafter(shell_prefix, b"stty ocrnl -onlcr")
    conn.sendlineafter(shell_prefix, b"gunzip pwn.gz")
    conn.sendlineafter(shell_prefix, b"chmod +x pwn")