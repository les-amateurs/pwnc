from __future__ import annotations

from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest


from fixture_support import TARGETS, compile_fixture, document_for_fixture

from teemo.artifacts import ArtifactStore


ROOT = Path(__file__).parents[2]
EMITTER = ROOT / "dwarf" / "emitter" / "target" / "debug" / "teemo-dwarf"
GDB_SCRIPT = ROOT / "dwarf" / "gdb" / "teemo_gdb.py"


REQUIRED_TOOLS = (
    "clang",
    "ld.lld",
    "llvm-objdump",
    "llvm-dwarfdump",
    "readelf",
    "gdb-multiarch",
    *(target.qemu for target in TARGETS.values()),
)


@unittest.skipUnless(all(shutil.which(tool) for tool in REQUIRED_TOOLS), "cross-architecture toolchain is required")
class CrossArchitectureIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["cargo", "build", "--manifest-path", str(ROOT / "dwarf" / "emitter" / "Cargo.toml")],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.cases = {}
        store = ArtifactStore(cls.root / "state", emitter=EMITTER)
        for target_name, target in TARGETS.items():
            for pie in (False, True):
                mode = "pie" if pie else "exec"
                binary = cls.root / f"fixture-{target_name}-{mode}"
                compile_fixture(binary, target, pie=pie)
                document = document_for_fixture(binary, target)
                document.validate()
                manifest = store.publish(document, binary)
                current = cls.root / "state" / manifest.view_id / "current.json"
                cls.cases[(target_name, pie)] = (target, binary, document, manifest, current)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_all_objects_pass_readelf_dwarfdump_and_static_gdb(self) -> None:
        for (target_name, pie), (_target, binary, document, manifest, current) in self.cases.items():
            with self.subTest(architecture=target_name, pie=pie):
                readelf = subprocess.run(
                    ["readelf", "--debug-dump=info", "--debug-dump=decodedline", manifest.debug_object],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                self.assertEqual(readelf.returncode, 0, readelf.stdout)
                self.assertIn("DW_TAG_lexical_block", readelf.stdout)
                self.assertIn("DW_TAG_inheritance", readelf.stdout)
                self.assertIn("DW_AT_calling_convention", readelf.stdout)
                self.assertIn("teemo/scopes.c", readelf.stdout)

                dwarfdump = subprocess.run(
                    ["llvm-dwarfdump", "--verify", manifest.debug_object],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                self.assertEqual(dwarfdump.returncode, 0, dwarfdump.stdout)

                bias = 0x10000000 if pie else 0
                commands = [
                    "set pagination off",
                    "set confirm off",
                    "set debuginfod enabled off",
                    f"file {binary}",
                    f"source {GDB_SCRIPT}",
                    f"teemo-refresh {current} --bias {bias:#x}",
                    "info functions analyzed",
                    "info scope analyzed",
                    "ptype struct Node",
                    "ptype Derived",
                    "ptype union Payload",
                    "ptype enum Mode",
                    "info address global_counter",
                    "info address teemo_loop_body",
                    "info line teemo/scopes.c:6",
                    "break teemo/scopes.c:6",
                    "list teemo/scopes.c:15",
                    "teemo-unload",
                ]
                output = _run_gdb(commands)
                for expected in (
                    "int analyzed",
                    "Scope for analyzed",
                    "multi-location",
                    "struct Node",
                    "class Derived",
                    "private Base",
                    "union Payload",
                    "enum Mode",
                    "global_counter",
                    "teemo_loop_body",
                    "Breakpoint 1",
                    "loop_local",
                    f"bias {bias:#x}",
                ):
                    self.assertIn(expected, output)
                function_start = document.functions[0].ranges[0].start.value
                self.assertIn(f"{function_start + bias:#x}", output)

    def test_qemu_runtime_rebasing_source_and_variable_ranges(self) -> None:
        for (target_name, pie), (target, binary, _document, _manifest, current) in self.cases.items():
            with self.subTest(architecture=target_name, pie=pie):
                port = _unused_tcp_port()
                qemu = subprocess.Popen(
                    [target.qemu, "-g", str(port), str(binary)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    time.sleep(0.1)
                    if qemu.poll() is not None:
                        detail = qemu.stderr.read() if qemu.stderr else "QEMU exited"
                        self.fail(detail)
                    commands = [
                        "set pagination off",
                        "set confirm off",
                        "set debuginfod enabled off",
                        f"file {binary}",
                        f"target remote 127.0.0.1:{port}",
                        f"source {GDB_SCRIPT}",
                        f"teemo-refresh {current}",
                        "break *analyzed",
                        "break teemo/scopes.c:6",
                        "continue",
                        "print argc",
                        "print argv",
                        "print node",
                        "continue",
                        "print argc",
                        "print stack_local",
                        "print global_counter",
                        "info line *$pc",
                        "continue",
                    ]
                    output = _run_gdb(commands, timeout=30)
                finally:
                    if qemu.poll() is None:
                        qemu.terminate()
                    try:
                        qemu.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        qemu.kill()
                        qemu.wait(timeout=3)
                    if qemu.stderr is not None:
                        qemu.stderr.close()

                self.assertIn("argc=3", output)
                self.assertIn("$1 = 3", output)
                self.assertIn("$2 = (char **) 0x0", output)
                self.assertIn("global_node", output)
                self.assertIn("$4 = <optimized out>", output)
                self.assertIn("$5 = 6", output)
                self.assertIn("$6 = 7", output)
                self.assertIn("teemo/scopes.c", output)
                self.assertIn("exited with code 060", output)
                if pie:
                    self.assertRegex(output, r"bias 0x[1-9a-f][0-9a-f]+")
                else:
                    self.assertIn("bias 0x0", output)


def _run_gdb(commands: list[str], *, timeout: int = 20) -> str:
    command = ["gdb-multiarch", "-nx", "-q", "-batch"]
    for value in commands:
        command.extend(("-ex", value))
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise AssertionError(f"GDB failed with status {result.returncode}:\n{result.stdout}")
    return result.stdout


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as value:
        value.bind(("127.0.0.1", 0))
        return int(value.getsockname()[1])


if __name__ == "__main__":
    unittest.main()
