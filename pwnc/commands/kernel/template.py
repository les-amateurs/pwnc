from ...util import *

COMMON = ["pwnc.h", "Makefile", "exploit.c"]
TEMPLATES = Path(__file__).parent / "templates"


def load(files: list[str]):
    for file in files:
        src = TEMPLATES / file
        if src.is_dir():
            shutil.copytree(src, file, dirs_exist_ok=True)
            err.info(f"created dir  {file}")
        else:
            shutil.copyfile(src, file)
            err.info(f"created file {file}")


def command(args: Args):
    match args.kind:
        case "common":
            load(COMMON)
        case _:
            err.fatal(f"template {args.kind} not found")

    err.info("done")
