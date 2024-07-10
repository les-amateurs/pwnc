from bs4 import BeautifulSoup
from pprint import pprint
from pathlib import Path
from urllib.parse import urlparse
import asyncio
import aiohttp
import re
import os
import functools
import itertools

MAX_CONCURRENT = 5
BATCH_SIZE = 300
RETRIES = 10
ARCHITECTURES = ["amd64", "arm64", "armel", "armhf", "i386"]

session, sem = None, None
async def must(f):
    global session, sem
    await sem.put(None)
    retries = 0
    while True:
        try:
            r = await f(session)
            if r.status == 200:
                break
            # print(f"status = {r.status}")
        except Exception as e:
            print(f"error = {e}")
            pass
        retries += 1
        if retries > RETRIES:
            print("Maximum retry count exceeded")
            break
        await asyncio.sleep(1.0)
    await sem.get()
    return r

async def get_html(url):
    async with (await must(lambda session: session.get(url))) as resp:
        return BeautifulSoup(await resp.text(), features="html.parser")

async def get_published_range(package: str, batch_start: int, batch_end: int):
    batch_size = batch_end - batch_start
    return await get_html(f"https://launchpad.net/ubuntu/+source/{package}/+publishinghistory?batch={batch_size}&start={batch_start}")

async def get_num_published(package: str):
    soup = await get_published_range(package, 0, 0)
    results = soup.find("td", { "class": "batch-navigation-index" })
    num_published = int(re.search(r"\s([0-9]+)\sresults", " ".join(filter(len, results.text.split()))).group(1))
    return num_published

async def get_versions_batched(package: str, batch_start: int, batch_end: int):
    paths = set()
    soup = await get_published_range(package, batch_start, batch_end)
    for tr in soup.find_all("tr"):
        if len(tr.find_all("td")) != 8:
            continue

        path = tr.find_all("td")[7].find_all("a")[0]["href"]
        paths.add(path)

    return paths

async def extract_build_pages(path: str):
    version = Path(path).name
    soup = await get_html(f"https://launchpad.net/{path}")
    builds = soup.find(id="source-builds")

    paths = {}

    try:
        tags = filter(lambda tag: tag.name == "p", builds.children)
        tags = next(tags).children
        tags = filter(lambda tag: tag.name is not None, tags)
        tags = list(tags)
        for i, tag in enumerate(tags):
            if i > 0 and tag.name == "a" and tags[i-1]["alt"] == "[FULLYBUILT]":
                if tag.text in ARCHITECTURES:
                    paths[tag.text] = tag["href"]
    except StopIteration:
        pass

    return version, paths

class Result:
    def __init__(self):
        self.cached = 0
        self.downloaded = 0
        self.failed = 0
        self.missing = 0

    def sum(self):
        return self.cached + self.downloaded + self.failed + self.missing

    def add(self, other: 'Result'):
        self.cached += other.cached
        self.downloaded += other.downloaded
        self.failed += other.failed
        self.missing += other.missing
        return self

async def extract_debs(cache: Path, name: str, version: str, paths: dict[str, list[str]]):
    result = Result()

    for arch, path in paths.items():
        debug = re.compile(rf"{name}-dbg(sym)?_{version}_{arch}.d?deb$")
        development_debug = re.compile(rf"{name}-dev-dbg(sym)?_{version}_{arch}.d?deb$")
        development = re.compile(rf"{name}-dev_{version}_{arch}.d?deb$")

        soup = await get_html(f"https://launchpad.net/{path}")
        for link in soup.find_all("a"):
            url = link["href"]
            if debug.search(url) is not None \
            or development_debug.search(url) is not None \
            or development.search(url) is not None:
                deb_url = url
                break
        else:
            # print(f"no debs found on {path} with {debug}")
            result.missing += 1
            continue

        file = Path(urlparse(deb_url).path).name

        filepath = cache / arch / file
        os.makedirs(cache / arch, exist_ok=True)

        if filepath.exists():
            # print(f"{path} {filepath} already exists")
            result.cached += 1
            continue

        # print(f"downloading {deb_url} from {path}")

        async with (await must(lambda session: session.get(deb_url))) as resp:
            try:
                data = await resp.read()
                if not data:
                    # print("FAILED DOWNLOAD", filepath, "from", deb_url)
                    result.failed += 1
                    continue
                with open(filepath, "wb") as f:
                    f.write(data)
                result.downloaded += 1
            except TimeoutError:
                # print(f"download for {filepath} timed out")
                result.failed += 1
                continue

    return result

async def main():
    global session

    packages = ["glibc", "eglibc", "dietlibc", "musl"]
    names = {
        "glibc": "libc6",
        "eglibc": "libc6",
        "dietlibc": "dietlibc",
        "musl": "musl",
    }

    async with aiohttp.ClientSession() as session:
        for package in packages:
            num_published = await get_num_published(package)
            ranges = list(range(0, num_published, BATCH_SIZE)) + [num_published]
            ranges = [(package, ranges[i], ranges[i+1]) for i in range(len(ranges)-1)]
            
            paths = await asyncio.gather(*[asyncio.create_task(get_versions_batched(*version_range)) for version_range in ranges])
            paths = functools.reduce(lambda a, b: a.union(b), paths)

            cache = Path("_cache") / "ubuntu" / package
            version_and_paths = await asyncio.gather(*[asyncio.create_task(extract_build_pages(path)) for path in paths])
            results = await asyncio.gather(*[asyncio.create_task(extract_debs(cache, names[package], *info)) for info in version_and_paths])
            results = functools.reduce(lambda a, b: a.add(b), results)
            print("=" * 10 + f"[ {package:<16} ]" + "=" * 10)
            print(f"cached = {results.cached}")
            print(f"downloaded = {results.downloaded}")
            print(f"missing = {results.missing}")
            print(f"failed = {results.failed}")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    sem = asyncio.Queue(maxsize=MAX_CONCURRENT)
    loop.run_until_complete(main())
    loop.close()