from pwnc.config import load_config
from ...util import *
from tempfile import NamedTemporaryFile
import gzip

CONFIG_INITRAMFS = config.Key("kernel") / "initramfs"


def do_decompress(initramfs: Path, rootfs: Path):
    gzipped = False
    with NamedTemporaryFile() as tempfile:
        shutil.copyfile(initramfs, tempfile.name)
        try:
            with gzip.open(tempfile.name) as fp:
                decompressed = fp.read()
            with open(tempfile.name, "wb") as fp:
                fp.write(decompressed)
            gzipped = True
        except gzip.BadGzipFile:
            pass

        rootfs.mkdir(exist_ok=True)
        run(f"cpio -idmu < {tempfile.name}", cwd=rootfs)

    return gzipped


def save_parameters(initramfs: Path, rootfs: Path, gzipped: bool):
    config.save(CONFIG_INITRAMFS / "path", str(initramfs.absolute()))
    config.save(CONFIG_INITRAMFS / "gzipped", gzipped)
    config.save(CONFIG_INITRAMFS / "rootfs", str(rootfs.absolute()))


def command(args):
    initramfs = args.initramfs
    rootfs = args.rootfs
    save = load_config(False)

    if rootfs is None:
        if args.ignore and save is not None:
            rootfs = Path(config.load(CONFIG_INITRAMFS / "rootfs"))
        else:
            rootfs = Path(".") / "rootfs"

    if initramfs is None:
        if args.ignore and save is not None:
            initramfs = Path(config.load(CONFIG_INITRAMFS / "path"))

    if initramfs is None:
        err.fatal("specify initramfs file")

    gzipped = do_decompress(initramfs, rootfs)

    if args.save:
        save_parameters(initramfs, rootfs, gzipped)
