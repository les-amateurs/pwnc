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
ARCHITECTURES = ["arm64"]

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

async def get_versions(package: str):
    page = f"https://snapshot.debian.org/binary/{package}/"
    soup = await get_html(page)
    for item in soup.find_all("li"):
        if link := item.find("a"):
            if link["href"].startswith("../../package/"):
                yield page + link["href"]

async def extract_debs(cache: Path, package: str, page: str):
    result = Result()

    version = urlparse(page).fragment
    extract_arch = re.compile(rf"{version}_([a-zA-Z0-9]+).d?deb$")

    soup = await get_html(page)
    for link in soup.find_all("a"):
        if "href" not in link.attrs:
            continue

        path = Path(link["href"])
        arch = "_unknown"

        if path.name.startswith(version):
            deb_url = f"https://snapshot.debian.org/{path}"
            if m := extract_arch.search(path.name):
                arch = m.group(1)
        else:
            continue

        if arch not in ARCHITECTURES:
            continue

        file = path.name
        filepath = cache / arch / file
        os.makedirs(cache / arch, exist_ok=True)

        if filepath.exists():
            print(f"{path} {filepath} already exists")
            result.cached += 1
            continue

        print(f"downloading {deb_url} from {path}")

        async with (await must(lambda session: session.get(deb_url))) as resp:
            try:
                data = await resp.read()
                if not data:
                    print("FAILED DOWNLOAD", filepath, "from", deb_url)
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

    packages = ["libc6-dbg"]

    async with aiohttp.ClientSession() as session:
        for package in packages:
            cache = Path("_cache") / "debian" / package
            results = await asyncio.gather(*[asyncio.create_task(extract_debs(cache, package, page)) async for page in get_versions(package)])
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