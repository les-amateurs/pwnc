from ...util import *
from ...config import locate_global_config_directory
import toml

FILE_KEY = '""" [config.file] """'
LIBC_KEY = '""" [config.libc] """'
PORT_KEY = '""" [config.port] """'

CONFIG   = "config.toml"

TEMPLATES = locate_global_config_directory() / "templates"

def instantiate(path: Path, args: dict):
    with open(path, "r")  as f:
        data = f.read()
    for key, value in args.items():
        if value is None:
            value = str(value)
        data = data.replace(key, value)
    return data

def command(args: Args):
    template = args.template
    file_path = None
    if args.file:
        file_path = "{!r}".format(str(args.file))
    libc_path = None
    if args.libc:
        libc_path = "{!r}".format(str(args.libc)) if args.libc else 'None'
    port = args.port

    replacements = {
        FILE_KEY: file_path,
        LIBC_KEY: libc_path,
        PORT_KEY: str(port),
    }

    source_path = TEMPLATES / template
    config_path = source_path / CONFIG
    if not source_path.exists():
        err.fatal(f"template {template} does not exist ({source_path})")
    
    exclude = [config_path]
    overwrite = args.overwrite

    try:
        with open(config_path, "r") as f:
            extra = toml.load(f)
        exclude += extra.get("exclude", [])
    except OSError:
        pass

    for path in walk_recursive(source_path):
        if path in exclude:
            continue

        target = path.relative_to(source_path)
        if not overwrite and target.exists():
            err.warn(f"{target} already exists, skipping")
            continue
        if path.is_dir():
            target.mkdir()
            continue

        data = instantiate(path, replacements)
        with open(target, "w+") as f:
            f.write(data)