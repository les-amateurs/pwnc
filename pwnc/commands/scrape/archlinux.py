# none of this works because ARCHLINUX does not archive their debuginfo
# from ...cache import locate_cache
# from ... import err
# from ... import minelf
# from .package import Package
# from .index import Index
# import requests
# import json
# import re

# DISTRO = "debian"
# CACHE = locate_cache() / "scrape" / DISTRO
# ROOT = "http://snapshot.debian.org/"
# VERSION = re.compile(rb"GLIBC (\d+\.\d+.*)\)")

# def request(url: str):
#     err.info(f"requesting {url}")
#     response = requests.get(url, timeout=10)
#     if response.status_code != 200:
#         err.fatal(f"request {url} failed")

#     return response.content

# def download(hash: str):
#     url = f"{ROOT}/file/{hash}"
#     return request(url)

# def request_versions(package: str):
#     index = Index(f"{DISTRO}-{package}-versions")
#     if package in index:
#         return index[package]
#     url = f"{ROOT}/mr/package/{package}"
#     versions = [entry["version"] for entry in json.loads(request(url))["result"]]
#     index[package] = versions
#     return versions

# def request_binpackages(package: str, version: str):
#     index = Index(f"{DISTRO}-{package}-{version}-binpackages")
#     if version in index:
#         return index[version]
#     url = f"{ROOT}/mr/package/{package}/{version}/binpackages"
#     binpackages = [entry["name"] for entry in json.loads(request(url))["result"]]
#     index[version] = binpackages
#     return binpackages

# def request_binfiles(package: str, binpackage: str, version: str):
#     index = Index(f"{DISTRO}-{package}-{version}-{binpackage}-binfiles")
#     if binpackage in index:
#         return index[binpackage]
#     url = f"{ROOT}/mr/binary/{binpackage}/{version}/binfiles"
#     binfiles = [(entry["architecture"], entry["hash"]) for entry in json.loads(request(url))["result"]]
#     binfiles = dict(binfiles)
#     index[binpackage] = binfiles
#     return binfiles

# def parse_libc_version(elf: minelf.ELF):
#     m = VERSION.search(elf.raw_elf_bytes)
#     if not m.group(1):
#         err.warn("failed to determine libc version")
#     return m.group(1).decode()

# def provides(elf: minelf.ELF):
#     return DISTRO.encode("utf-8") in elf.raw_elf_bytes and (parse_libc_version(elf) != None)

# def locate(elf: minelf.ELF):
#     package = "glibc"

#     versions = request_versions(package)
#     version = parse_libc_version(elf)
#     if version not in versions:
#         err.fatal(f"unable to find {version} in {DISTRO} snapshot")

#     binpackages = request_binpackages(package, version)
#     if "libc6-dbg" not in binpackages:
#         err.fatal(f"unable to find libc6-dbg package for debuginfo")

#     binfiles = request_binfiles(package, "libc6-dbg", version)
#     if "amd64" not in binfiles:
#         err.fatal(f"architecture amd64 not supported by {package} {version}")

#     contents = download(binfiles["amd64"])
#     return Package(DISTRO, package, version, contents)