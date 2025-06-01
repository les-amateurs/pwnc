from .. util import *
from .scrape.ubuntu import DISTRO, ROOT
from .scrape.index import Index

package = "glibc"
arch = "amd54"

def command(args: Args):
    index = Index(f"{DISTRO}-{package}-versions")
    version_sets = index.handle.values()
    versions = []

    for version_set in version_sets:
        versions.extend([version.encode() for version in version_set])

    handle = run(["fzf"], input=b"\n".join(versions), encoding=None, capture_output=True)
    if handle.returncode != 0:
        err.fatal("search cancelled")

    selection = handle.stdout.strip().decode()
    url = f"{ROOT}/ubuntu/+source/{package}/{selection}"
    err.info(url)