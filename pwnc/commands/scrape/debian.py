from ...util import *
from ... import minelf
from ...minelf.types.header import Machine
from .package import Package
from .index import Index
import requests
import json
import re

DISTRO = "debian"
CACHE = cache.locate_global_cache() / "scrape" / DISTRO
ROOT = "http://snapshot.debian.org/"
VERSION = re.compile(rb"GLIBC (\d+\.\d+.*)\)")
MACHINES = [Machine.AMD64, Machine.X86, Machine.ARM64, Machine.ARM, Machine.RISCV]

def elf_to_architecture(elf: minelf.ELF):
    match elf.header.machine:
        case Machine.AMD64:
            return "amd64"
        case Machine.X86:
            return "i386"
        case Machine.ARM64:
            return "arm64"
        case Machine.ARM:
            return "armhf"
        case Machine.RISCV:
            if elf.bits == 64:
                return "riscv64"
    return None

def request(url: str):
    err.info(f"requesting {url}")
    response = requests.get(url, timeout=10)
    if response.status_code != 200:
        err.fatal(f"request {url} failed")

    return response.content

def download(hash: str):
    url = f"{ROOT}/file/{hash}"
    return request(url)

def request_versions(package: str):
    index = Index(f"{DISTRO}-{package}-versions")
    if package in index:
        return index[package]
    url = f"{ROOT}/mr/package/{package}"
    versions = [entry["version"] for entry in json.loads(request(url))["result"]]
    index[package] = versions
    return versions

def request_binpackages(package: str, version: str):
    index = Index(f"{DISTRO}-{package}-{version}-binpackages")
    if version in index:
        return index[version]
    url = f"{ROOT}/mr/package/{package}/{version}/binpackages"
    binpackages = [entry["name"] for entry in json.loads(request(url))["result"]]
    index[version] = binpackages
    return binpackages

def request_binfiles(package: str, binpackage: str, version: str):
    index = Index(f"{DISTRO}-{package}-{version}-{binpackage}-binfiles")
    if binpackage in index:
        return index[binpackage]
    url = f"{ROOT}/mr/binary/{binpackage}/{version}/binfiles"
    binfiles = [(entry["architecture"], entry["hash"]) for entry in json.loads(request(url))["result"]]
    binfiles = dict(binfiles)
    index[binpackage] = binfiles
    return binfiles

def parse_libc_version(elf: minelf.ELF):
    m = VERSION.search(elf.raw_elf_bytes)
    if not m.group(1):
        err.warn("failed to determine libc version")
    return m.group(1).decode()

def provides(elf: minelf.ELF):
    if DISTRO.encode("utf-8") not in elf.raw_elf_bytes:
        return False
    if parse_libc_version(elf) is None:
        return False
    if elf.header.machine not in MACHINES:
        return False
    return True

def locate(elf: minelf.ELF):
    package = "glibc"
    arch = elf_to_architecture(elf)
    if arch is None:
        err.fatal(f"unsupported architecture") 

    versions = request_versions(package)
    version = parse_libc_version(elf)
    if version not in versions:
        err.fatal(f"unable to find {version} in {DISTRO} snapshot")

    binpackages = request_binpackages(package, version)
    if "libc6-dbg" not in binpackages:
        err.fatal(f"unable to find libc6-dbg package for debuginfo")

    binfiles = request_binfiles(package, "libc6-dbg", version)
    if arch not in binfiles:
        err.fatal(f"architecture {arch} not supported by {package} {version}")

    contents = download(binfiles[arch])
    return Package(DISTRO, package, version, contents)