from ...util import *
from ... import err
from ...minelf import ELF
from typing import NamedTuple, override
import json
import time
import socket
import string
import hashlib
import os
import re
import functools


"""
TODOS:

Some challenges (this is rare) provide both a linker and a binary,
then invoke the binary with [linker] [binary]. Then the proc/[pid]/exe
will point to the linker and not the actual binary. Have some function
to detect the linker: static binary + name + elf parsing?

Handle dict.get for missing fields in docker or compose ps output.

Right now all the libs are shoved into a single directory, ideally
each binary gets its own lib folder.

Handle possibly reading a single byte from established connections,
up to a timeout. This is to guarantee that whatever is listening on
the other side has fully initialized.

Handle possible extracted binary name collisions.

Finish writing minelf content_from_vaddr so we are able to read dynamic
segment data directly instead of relying on the .dynamic section.

Allocate a random port for docker to avoid collisions.

ISSUE: docker runs in userns, but as root, so linux denies access to /proc/[pid]/root.
redpwn jail works because a nested userns with uid 1000 is created. Everything else
just breaks. Could fallback to using docker exec or experiment with uid remapping?
"""



def binary_filter(path: Path):
    if not path.is_file(follow_symlinks=False):
        return False
    with open(path, "rb") as fp:
        data = fp.read(4)
    if data != b"\x7fELF":
        return False
    return True


def hash_file(path: Path) -> str:
    with open(path, "rb") as fp:
        digest = hashlib.file_digest(fp, "md5")
    return digest.hexdigest()


@functools.cache
def possible_binaries():
    ps = find_recursive(".*", callback=binary_filter)
    err.info(f"possible binaries: {ps}")
    return ps


def establish_connection(host: str, port: int) -> None | socket.socket:
    max_connects = 10
    max_timeouts = 5
    timeouts = 0
    sock = None

    for _ in range(max_connects):
        if sock is None:
            if ":" in host:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.settimeout(0.5)
        try:
            try:
                data = sock.recv(1, socket.MSG_WAITALL)
                if data:
                    break
                sock.close()
                sock = None
            except TimeoutError:
                err.warn("timed out waiting for data")
                timeouts += 1
                if timeouts == max_timeouts:
                    err.warn("service might not send any data")
                    break
        except ConnectionRefusedError:
            err.warn(f"failed to connect to {host}:{port}")

        time.sleep(0.1)
    else:
        err.warn("failed to connect")
        return
    return sock


class Container:
    def __init__(self, id: str):
        self.id = id
        self.hostpid = Container.get_hostpid(id)
        self.root = Path("/") / "proc" / str(self.hostpid) / "root"
        try:
            (self.root / "proc").stat()
            self.direct = True
        except PermissionError:
            self.direct = False


    @staticmethod
    def get_hostpid(id: str):
        return int(run(["docker", "inspect", "--format", "{{.State.Pid}}", id], shell=False, capture_output=True).stdout)
    

    def exec(self, cmd: list[str]):
        cmd = ["docker", "exec", "-u", "0", self.id] + cmd
        err.info(f"running: {' '.join(cmd)}")
        return run(cmd, shell=False, check=False, capture_output=True, encoding=None)
    

    def read_file(self, path: Path | str, nbytes: int | None = None):
        path = Path(path)
        if self.direct:
            if path.is_absolute():
                path = path.relative_to("/")
            path = self.root / path
            with open(path, "rb") as fp:
                return fp.read(nbytes)
        else:
            out = self.exec(["cat", path.as_posix()])
            if out.returncode != 0:
                raise RuntimeError(f"Failed to read {path}")
            return out.stdout[:nbytes or len(out.stdout)]
        

    def read_link(self, path: Path | str):
        path = Path(path)
        if self.direct:
            if path.is_absolute():
                path = path.relative_to("/")
            path = self.root / path
            return path.readlink()
        else:
            out = self.exec(["readlink", path.as_posix()])
            if out.returncode != 0:
                err.fatal(f"failed to read symlink: {path}")
            return Path(out.stdout.strip().decode("ascii", errors="ignore"))
        

    def copy_file(self, src: Path | str, dst: Path | str):
        src = Path(src)
        dst = Path(dst)
        if self.direct:
            if src.is_absolute():
                src = src.relative_to("/")
            src = self.root / src
            shutil.copyfile(src, dst)
        else:
            data = self.read_file(src)
            with open(dst, "wb+") as fp:
                fp.write(data)
        

    def list_files(self, path: Path | str, options: list[str] = []):
        path = Path(path)
        if self.direct:
            if path.is_absolute():
                path = path.relative_to("/")
            path = self.root / path
            return os.listdir(path)
        else:
            out = self.exec(["ls"] + options + [path.as_posix()])
            if out.returncode != 0 and len(out.stdout) > 0:
                err.fatal(f"failed to list {path}")
            return out.stdout.strip().splitlines()
        

    @functools.cache
    def list_all_files(self, pid: int):
        root = Path("proc") / str(pid) / "root"
        if self.direct:
            def file_type_filter(path):
                return path.is_file() or path.is_symlink()
            return [p.relative_to(self.root) for p in find_recursive(".*", callback=file_type_filter, target=self.root / root)]
        else:
            root = Path("/") / root
            out = self.exec(["find", root.as_posix() + "/", "(", "-type", "f", "-o", "-type", "l", ")"])
            if out.returncode != 0 and out.stdout == b"":
                err.fatal(f"failed to list files for {pid} in container {self.id}, ret: {out.returncode}")
            return [Path(p) for p in out.stdout.decode("ascii", errors="ignore").strip().splitlines()]


    def search(self, path: Path | str, pid: int):
        path = Path(path)
        files = self.list_all_files(pid)
        for file in files:
            if file.as_posix().endswith(path.as_posix()):
                yield file


    def test_file(self, path: Path | str):
        try:
            self.list_files(path)
            return True
        except NotADirectoryError:
            return True
        except RuntimeError:
            return False
        except FileNotFoundError:
            return False
        
    
    def get_pids(self):
        lines = self.list_files("/proc")
        pids = filter(lambda line: line.isdigit(), lines)
        pids = map(int, pids)
        pids = list(pids)
        # iterate from highest to lowest to get newer processes first
        pids = sorted(pids, reverse=True)
        return pids
    

    def get_ports(self):
        ports = set()
        pids = self.get_pids()

        for pid in pids:
            lines = []
            for target in ["tcp", "tcp6"]:
                path = Path("/") / "proc" / str(pid) / "net" / target
                try:
                    content = self.read_file(path).decode("ascii", errors="ignore")
                    lines.extend(content.strip().splitlines()[1:])
                except RuntimeError as e:
                    err.warn(f"failed to read {path}")

            for line in lines:
                nr, addr, *_ = line.split()
                host, port = addr.split(":", maxsplit=1)
                host = int(host, 16)
                port = int(port, 16)
                if host != 0:
                    continue
                ports.add(port)

        return ports
    

class ContainerWithUID(Container):
    def __init__(self, id: str, uid : int):
        super().__init__(id)
        self.uid = uid
        
    @override
    def exec(self, cmd: list[str]):
        cmd = ["docker", "exec", "-u", str(self.uid), self.id] + cmd
        err.info(f"running: {' '.join(cmd)}")
        return run(cmd, shell=False, check=False, capture_output=True, encoding=None)


def from_running(container: Container, pid: int):
    exe = Path("/") / "proc" / str(pid) / "exe"
    resolved = set()
    targets = [(exe, container.read_link(exe).name)]
    while targets:
        target, dst = targets.pop()
        if target in resolved:
            continue
        if not target.is_absolute():
            found = Path("")
            matches = container.search(target, pid)
            matches = list(matches)
  
            for match in matches:
                if match.parts > found.parts:
                    found = match
            
            targets.append((found, dst))
            continue

        dst = Path(dst)
        if dst.exists():
            err.warn(f"{dst} already exists, using existing file")
        else:
            container.copy_file(target, dst)
        make_executable(dst)

        with open(dst, "rb") as fp:
            data = fp.read()
        elf = ELF(data)

        interp = elf.section_from_name(b".interp")
        if interp is None:
            err.warn(f"unable to find interp for {dst}")
        else:
            path = elf.section_content(interp).tobytes()
            path = path[:path.index(b"\0")].decode("ascii", errors="ignore")
            path = Path(path)
            targets.append((path, path.name))

        dynamic = elf.section_from_name(b".dynamic")
        dynstr = elf.section_from_name(b".dynstr")
        if dynamic and dynstr:
            tags = elf.section_content(dynamic, elf.Dyntag)
            strs = elf.section_content(dynstr)
            for tag in tags:
                if tag.tag == elf.Dyntag.Type.NEEDED:
                    name = strs[tag.val:].tobytes()
                    name = name[:name.index(b"\0")].decode("ascii", errors="ignore")
                    targets.append((Path(name), name))
        else:
            if dynamic is None:
                err.warn(f"unable to find dynamic for {dst}")
            if dynstr is None:
                err.warn(f"unable to find dynstr for {dst}")

        resolved.add(target)

def from_docker_container(id: str):
    hashes = {}
    bins = possible_binaries()
    matches = []
    tmp = random_tmpdir()
    copy = tmp / "copy"

    try:
        container = Container(id)
        pids = container.get_pids()
        err.info(f"pids: {pids}")
        for pid in pids:
            status_path = Path("/") / "proc" / str(pid) / "status"
            # one pid will fail because ls is part of the pids
            try:
                proc_status = container.read_file(status_path)
            except RuntimeError:
                err.info(f"Failed to read status of {pid}")
                continue
            lines = proc_status.splitlines()
            lines = list(filter(lambda l: b"Uid:" in l, lines))
            # todo: check if taking the first uid is correct
            err.info(f"uid of proc {pid}: {str(lines)}")
            uid = int(lines[0].split()[1])

            uid_container = ContainerWithUID(id, uid)
            src = Path("/") / "proc" / str(pid) / "exe"

            if not uid_container.test_file(src):
                err.warn(f"failed to access {src}")
                continue

            uid_container.copy_file(src, copy)
            copy_hash = hash_file(copy)
            for bin in bins:
                hash = hashes.get(bin)
                if not hash:
                    hash = hash_file(bin)
                    hashes[bin] = hash
                if copy_hash == hash:
                    matches.append((uid_container, pid))
                    break

        for match in matches:
            from_running(*match)
    finally:
        shutil.rmtree(tmp)

def handle_docker(args: Args):
    if run(["docker", "--version"], shell=False, check=False, capture_output=True).returncode != 0:
        err.warn("docker not found")
        return
    
    out = run(["docker", "build", ".", "-q"], shell=False, check=False, capture_output=True)
    if out.returncode != 0:
        print(out.stderr, end="")
        err.warn("failed to build docker container")
        return False
    
    tag = out.stdout.strip()
    runner = ["docker", "run", "-d", "-q"]
    if args.privileged:
        runner.append("--privileged")
    else:
        runner.append("--cap-add=SYS_PTRACE")

    cmd = runner + [tag]
    err.info(f"run: {' '.join(cmd)}")
    out = run(cmd, shell=False, check=False, capture_output=True)
    if out.returncode != 0:
        print(out.stderr, end="")
        err.warn("docker failed to run")
        return False
    
    containers = []
    socks = []

    id = out.stdout.strip()
    containers.append(id)

    try:
        out = run(["docker", "inspect", "--format", "{{.State.Running}}", id], shell=False, check=False, capture_output=True)
        if out.returncode != 0:
            print(out.stderr, end="")
            err.warn("docker failed to get container status")
            return False
        
        status = out.stdout.strip()
        if status == "false":
            run(["docker", "logs", id], shell=False, check=False)
            err.warn("container failed to start or exited")
            return False
        
        time.sleep(0.5)
        container = Container(id)
        ports = container.get_ports()
        err.info(f"found ports: {ports}")
        out = run(["docker", "stop", id], shell=False, check=False, capture_output=True)
        if out.returncode != 0:
            print(out.stderr, end="")
            err.warn("docker failed top stop container")
            return False
        
        for port in ports:
            runner.extend(["-p", f"{port}:{port}"])

        cmd = runner + [tag]
        err.info(f"run: {' '.join(cmd)}")
        out = run(cmd, shell=False, check=False, capture_output=True)
        if out.returncode != 0:
            print(out.stderr, end="")
            err.warn("docker failed to run")
            return False
        
        id = out.stdout.strip()
        containers.append(id)
        
        for port in ports:
            sock = establish_connection("127.0.0.1", port)
            socks.append(sock)

        time.sleep(0.5)
        from_docker_container(id)
        return True
    finally:
        for id in containers:
            out = run(["docker", "kill", id], shell=False, check=False, capture_output=True)
            if out.returncode != 0:
                print(out.stderr, end="")
                err.warn("failed to kill container")
            else:
                err.info(f"docker killed container {id}")
            
            out = run(["docker", "rm", id], shell=False, check=False, capture_output=True)
            if out.returncode != 0:
                print(out.stderr, end="")
                err.warn("docker failed to remove container")
            else:
                err.info(f"docker removed container {id}")
        
        for sock in socks:
            sock.close()

def handle_compose(args: Args):
    if run(["docker", "compose", "version"], shell=False, check=False, capture_output=True).returncode != 0:
        err.warn("docker compose not found")
        return
    
    def parse(info):
        id = info.get("ID")
        name = info.get("Name")
        pubs = info.get("Publishers")
        return (id, name, pubs)

    socks = []

    try:
        out = run(["docker", "compose", "up", "-d"], shell=False, check=False, capture_output=True)
        if out.returncode != 0:
            print(out.stderr, end="")

            if out.stderr.startswith("no configuration"):
                err.warn("failed to find compose file")
                return
            
            err.warn("failed to start compose")
            return False

        lines = run(["docker", "compose", "ps", "--format", "json", "--no-trunc"], shell=False, capture_output=True).stdout.strip().splitlines()
        infos = map(lambda line: json.loads(line), lines)
        infos = map(parse, infos)
        infos = list(infos)

        connected = set()
        for id, name, pubs in infos:
            for pub in pubs:
                protocol = pub.get("Protocol")
                # is this always just 0.0.0.0 or a proper hostname?
                url = pub.get("URL")
                pubport = pub.get("PublishedPort")
                if protocol != "tcp":
                    err.warn(f"ignoring non tcp port for container {id} ({name}) [:{pubport}]")
                    continue

                if pubport not in connected:
                    sock = establish_connection(url, pubport)
                    if sock:
                        err.info(f"connected to {id} ({name}) [:{pubport}]")
                        socks.append(sock)
                        connected.add(pubport)

        for id, *_ in infos:
            from_docker_container(id)

        return True
    finally:
        err.info("killing compose")
        out = run(["docker", "compose", "kill"], shell=False, check=False, capture_output=True)
        if out.returncode != 0:
            print(out.stderr, end="")
            err.warn("failed to stop compose")
        for sock in socks:
            sock.close()


def command(args: Args):
    res = handle_compose(args)
    if res is None:
        err.warn("docker compose not installed or compose.yml not found")
    elif not res:
        err.fatal("docker compose failed to start")
    else:
        return

    res = handle_docker(args)
    if res is None:
        err.warn("docker not installed or Dockerfile not found")
    elif not res:
        err.fatal("docker failed to start")
    else:
        return