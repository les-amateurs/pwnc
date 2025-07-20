from ...util import *
from . import decompress


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

    rootfs = config.find_or_init_config().parent / "rootfs"
    gzipped = decompress.do_decompress(initramfs, rootfs)
    decompress.save_parameters(initramfs, rootfs, gzipped)
