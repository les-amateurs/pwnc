from pwnc.config import load_config
from ...util import *
import gzip


def do_compress(rootfs: Path, destination: Path, gzipped: bool, gzip_level: int = 0):
    files = []
    for path, dirlist, filelist in os.walk(rootfs):
        path = Path(path)
        files.extend([path / name for name in dirlist])
        files.extend([path / name for name in filelist])
    # files = rootfs.glob("**")
    files = map(lambda p: p.relative_to(rootfs), files)
    files = list(files)
    # print(files)
    delimited = b"\x00".join(map(lambda file: str(file).encode(), files))
    handle = run(
        "cpio --null -o --format=newc --owner=root",
        input=delimited,
        capture_output=True,
        encoding=None,
        cwd=rootfs,
    )
    archive = handle.stdout
    if gzipped:
        archive = gzip.compress(archive, gzip_level)

    with open(destination, "wb+") as fp:
        fp.write(archive)


def command(args):
    config_initramfs = config.Key("kernel") / "initramfs"
    rootfs = args.rootfs or Path(config.maybe(config_initramfs / "rootfs"))
    if rootfs is None:
        err.fatal("specify rootfs to compress")
    initramfs = args.initramfs or Path(config.maybe(config_initramfs / "path"))
    if initramfs is None:
        err.fatal("specify destination initramfs file")
    gzipped = args.gzipped or config.maybe(config_initramfs / "gzipped") or False
    gzip_level = args.gzip_level or 0

    do_compress(rootfs, initramfs, gzipped, gzip_level)
