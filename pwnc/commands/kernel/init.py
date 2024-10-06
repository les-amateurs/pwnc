from ...util import *
from tempfile import NamedTemporaryFile
import gzip
import shutil

def command(args: Args):
    if args.initramfs is None:
        possible_initramfs = list(Path(".").glob("**/*.cpio*"))
        if len(possible_initramfs) == 0:
            err.fatal("failed to autodetect initramfs file")
        if len(possible_initramfs) != 1:
            err.fatal("more than one possible initramfs file, manually specify one")
        initramfs = possible_initramfs[0]
        err.info(f"auto-detcted initramfs file: {str(initramfs)}")
    else:
        initramfs = args.initramfs

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

        rootfs = Path(".") / "rootfs"
        rootfs.mkdir(exist_ok=True)
        run(f"cpio -idmu < {tempfile.name}", cwd=rootfs)

    config_initramfs = config.Key("kernel") / "initramfs"
    config.save(config_initramfs / "path", str(initramfs))
    config.save(config_initramfs / "gzip", gzipped)