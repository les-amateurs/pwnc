from bs4 import BeautifulSoup
import asyncio
import aiohttp
import re
import functools
from ...util import *
from .index import Index
from ...import minelf
from .package import Package

DISTRO = "ubuntu"
ROOT = "https://launchpad.net/"
VERSION = re.compile(rb"GLIBC (\d+\.\d+.*)\)")
MAX_CONCURRENT = 5
BATCH_SIZE = 100
RETRIES = 10
# ARCHITECTURES = ["amd64", "arm64", "armel", "armhf", "i386"]
ARCHITECTURES = ["i386"]

session, sem = None, None
async def request(url):
    global session, sem
    await sem.put(None)
    retries = 0
    while True:
        try:
            err.info(f"requesting {url}")
            resp = await session.get(url)
            if resp.status == 200:
                break
        except Exception as e:
            print(f"error while requesting {url}: {e}")
            pass
        retries += 1
        if retries > RETRIES:
            print(f"maximum retry count exceeded requesting {url}")
            break
        await asyncio.sleep(1.0)
    await sem.get()
    return await resp.content.read()

async def parse(html: str):
    return BeautifulSoup(html, features="html.parser")

# cache the publishinghistory webpages, they arent too big
async def request_published_range(package: str, batch_start: int, batch_end: int):
    index = Index(f"{DISTRO}-publishinghistory")
    batch_size = batch_end - batch_start
    path = f"/ubuntu/+source/{package}/+publishinghistory?batch={batch_size}&start={batch_start}"
    if path in index:
        html = index[path]
    else:
        html = await request(f"{ROOT}/{path}")
        index[path] = html
    return await parse(html)

async def request_num_published(package: str):
    index = Index(f"{DISTRO}-num_published")
    if package in index:
        return index[package]
    
    soup = await request_published_range(package, 0, 0)
    results = soup.find("td", { "class": "batch-navigation-index" })
    num_published = int(re.search(r"\s([0-9]+)\sresults", " ".join(filter(len, results.text.split()))).group(1))
    index[package] = num_published
    return num_published

async def request_versions(package: str, batch_start: int, batch_end: int):
    index = Index(f"{DISTRO}-{package}-versions")
    key = f"{package}-{batch_start}-{batch_end}"
    if key in index:
        return index[key]

    paths = set()
    soup = await request_published_range(package, batch_start, batch_end)
    for tr in soup.find_all("tr"):
        if len(tr.find_all("td")) != 8:
            continue
        link = tr.find_all("td")[7].find_all("a")[0]
        version = link.text
        paths.add(version)
    index[key] = paths
    return paths

async def request_build_pages(package: str, version: str):
    index = Index(f"{DISTRO}-build_pages-{package}-{version}")
    url = f"{ROOT}/ubuntu/+source/{package}/{version}"
    if url in index:
        html = index[url]
    else:
        html = await request(url)
        index[url] = html
    
    soup = await parse(html)
    sources = soup.find(id="source-builds")
    builds = dict()

    ptags = list(filter(lambda tag: tag.name == "p", sources.children))
    if len(ptags) == 0:
        err.warn(f"failed to locate build pages")
        return builds
    
    links = filter(lambda tag: tag.name == "a", ptags[0].children)
    links = list(links)
    for i, tag in enumerate(links):
        architecture = tag.text
        if architecture in ARCHITECTURES:
            builds[architecture] = tag["href"]

    return builds

async def request_deb(binpackage: str, version: str, arch: str, build: str):
    debug = re.compile(rf"{binpackage}-dbg(sym)?_{version}_{arch}.d?deb$")
    # development_debug = re.compile(rf"{binpackage}-dev-dbg(sym)?_{version}_{arch}.d?deb$")
    # development = re.compile(rf"{binpackage}-dev_{version}_{arch}.d?deb$")

    soup = await parse(await request(f"{ROOT}/{build}"))
    for link in soup.find_all("a"):
        url = link["href"]
        if debug.search(url) is not None:
            deb_url = url
            break
    else:
        err.warn(f"no debs found on {build} with {debug}")
        return

    err.info(f"found deb url: {deb_url}")
    return await request(deb_url)

def parse_libc_version(elf: minelf.ELF):
    m = VERSION.search(elf.raw_elf_bytes)
    if not m.group(1):
        err.warn("failed to determine libc version")
    return m.group(1).decode()

def provides(elf: minelf.ELF):
    return DISTRO.encode("utf-8") in elf.raw_elf_bytes and (parse_libc_version(elf) != None)

async def asynchronous_locate(elf: minelf.ELF):
    global session, sem

    # packages = ["glibc", "eglibc", "dietlibc", "musl"]
    packages = ["glibc"]
    names = {
        "glibc": "libc6",
        "eglibc": "libc6",
        "dietlibc": "dietlibc",
        "musl": "musl",
    }

    sem = asyncio.Queue(maxsize=MAX_CONCURRENT)
    async with aiohttp.ClientSession() as session:
        for package in packages:

            num_published = await request_num_published(package)

            ranges = list(range(0, num_published, BATCH_SIZE)) + [num_published]
            ranges = [(package, ranges[i], ranges[i+1]) for i in range(len(ranges)-1)]
            
            versions = await asyncio.gather(*[asyncio.create_task(request_versions(*version_range)) for version_range in ranges])
            versions = functools.reduce(lambda a, b: a.union(b), versions)
            version = parse_libc_version(elf)
            if version not in versions:
                err.fatal(f"unable to find {version} in {DISTRO} snapshot")

            arch = "i386"
            builds = await request_build_pages(package, version)
            if arch not in builds:
                err.fatal(f"architecture amd64 not supported by {package} {version}")

            contents = await request_deb(names[package], version, arch, builds[arch])
            if contents is not None:
                return Package(DISTRO, package, version, contents)

def locate(elf: minelf.ELF):
    return asyncio.get_event_loop().run_until_complete(asynchronous_locate(elf))