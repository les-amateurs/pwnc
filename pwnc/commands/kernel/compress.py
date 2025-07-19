from ...util import *


def do_compress(rootfs: Path, destination: Path, gzipped: bool, gzip_level: int = 1):
    files = []
    for path, dirlist, filelist in os.walk(rootfs):
        path = Path(path)
        files.extend([path / name for name in dirlist])
        files.extend([path / name for name in filelist])
    files = map(lambda p: p.relative_to(rootfs), files)
    files = list(files)
    delimited = b"\x00".join(map(lambda file: str(file).encode(), files))

    final_out = open(destination, "wb+")
    if gzipped:
        cpio_out = subprocess.PIPE
    else:
        cpio_out = final_out

    cpio = subprocess.Popen(
        ["cpio", "--null", "-o", "--format=newc", "--owner=root"],
        shell=False,
        stdout=cpio_out,
        stdin=subprocess.PIPE,
        encoding=None,
        cwd=rootfs,
    )
    if gzipped:
        err.info(f"gzip_level = {gzip_level}")
        gzip = subprocess.Popen(
            ["gzip", "-c", f"-{gzip_level}", "-"],
            shell=False,
            stdout=final_out,
            stdin=cpio.stdout,
        )
    cpio.communicate(delimited)
    status = cpio.wait()
    err.info(f"cpio status = {status}")
    if gzipped:
        status = gzip.wait()
        err.info(f"gzip status = {status}")


def command(args):
    config_initramfs = config.Key("kernel") / "initramfs"
    rootfs = args.rootfs or Path(config.maybe(config_initramfs / "rootfs"))
    if rootfs is None:
        err.fatal("specify rootfs to compress")
    initramfs = args.initramfs or Path(config.maybe(config_initramfs / "path"))
    if initramfs is None:
        err.fatal("specify destination initramfs file")
    gzipped = args.gzipped or config.maybe(config_initramfs / "gzipped") or False
    gzip_level = args.gzip_level

    do_compress(rootfs, initramfs, gzipped, gzip_level)
