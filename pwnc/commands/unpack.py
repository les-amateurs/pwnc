from ..util import *
from ..minelf import ELF
from ctypes import sizeof
from tempfile import mkdtemp

# is it worth it to pull in some file type recognition library?
def command(args):
    ensure_exists(args.file)

    storage, name = unpack(args.file.absolute())
    name = args.name or name
    dest = Path(name)

    files = os.listdir(storage)
    if len(files) == 1:
        singleton = storage / files[0]
        if singleton.is_dir():
            shutil.move(singleton, dest)
            shutil.rmtree(storage)
            return

    shutil.move(storage, dest)

def unpack(file: Path):
    storage = Path(mkdtemp())
    name = file.stem
    copy = storage / file.name

    match file.suffix:
        case ".gz":
            shutil.copyfile(file, copy)
            run("gzip -d {!r}".format(str(copy)), cwd=storage)
        case ".tar" | ".tgz":
            run("tar -xf {!r}".format(str(file)), cwd=storage)
        case ".zip":
            run("unzip {!r}".format(str(file)), cwd=storage)
        case ".7z":
            run("7z e {!r}".format(str(file)), cwd=storage)
        case ".xz":
            shutil.copyfile(file, copy)
            run("unxz {!r}".format(str(copy)), cwd=storage)
        case _:
            raise NotImplementedError(f"unknown package suffix {file.suffix}")

    files = os.listdir(storage)
    if len(files) == 1:
        file = storage / files[0]
        if file.is_file():
            try:
                storage, name = unpack(file)
            except NotImplementedError:
                shutil.rmtree(storage)

    return storage, name