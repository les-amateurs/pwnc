from .. util import *
from .scrape.ubuntu import ROOT, async_setup, request_versions, request_num_published, request_build_pages
from .scrape.index import Index
import asyncio

package = "glibc"
architectures = [
    "amd64",
    "arm64",
    "armhf",
    "i386",
    "ia64",
    "powerpc",
    "sparc",
    "ppc64el",
    "riscv64",
    "s390x",
]

def extract(s: str):
    return [int(n) for n in re.findall(r"[0-9]+", s)]

def extract_major_minor(version: str):
    return extract(version)

async def async_search(args: Args):
    num_published = await request_num_published(package)
    versions = await request_versions(num_published, package)
    versions = sorted(versions, key=extract_major_minor, reverse=True)

    handle = run(["fzf", "-i"], input="\n".join(versions), capture_output=True, check=False)
    if handle.returncode != 0:
        err.fatal("search cancelled")

    version = handle.stdout.strip()
    url = f"{ROOT}/ubuntu/+source/{package}/{version}"
    err.info(f"found {url}")

    build_pages = await request_build_pages(package, version, architectures)
    for arch, page in build_pages.items():
        page = page.lstrip("/")
        err.info(f"{arch:<16} {ROOT}{page}")

def command(args: Args):
    return asyncio.get_event_loop().run_until_complete(
        async_setup(async_search, *(args,)),
    )