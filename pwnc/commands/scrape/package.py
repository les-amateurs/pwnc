import tempfile
import atexit
from ...util import *
from ... import err

class Package:
    def __init__(self, distro: str, package: str, version: str, contents: bytes):
        self.distro = distro
        self.package = package
        self.version = version
        self.contents = contents
        self.tempdir = Path(tempfile.mkdtemp())
        self.unpacked = False
        self.storage = Path(self.tempdir / "storage")

        atexit.register(lambda: self.close())

    def close(self):
        shutil.rmtree(self.tempdir)

    def files(self) -> list[str]:
        self.extract()
        return list(self.storage.rglob("*"))
    
    def unpack(self):
        if not self.unpacked:
            package = self.tempdir / "package.whatever"
            with open(package, "wb+") as fp:
                fp.write(self.contents)

            run(f"ar x {package}", cwd=self.tempdir)
            data = list(self.tempdir.glob("data.tar.*"))
            if len(data) == 0:
                err.fatal(f"failed to locate data.tar.*")
            if len(data) != 1:
                err.fatal(f"too many data.tar.* found")

            data = data[0]
            storage = self.tempdir / "storage"
            storage.mkdir()
            run(f"tar -xf {data}", cwd=storage)

            self.unpacked = True

    def find(self, file: Path):
        return list(self.storage.rglob(file))