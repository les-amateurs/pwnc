from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from elftools.elf.elffile import ELFFile


PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIR))

from teemo.artifacts import ArtifactStore  # noqa: E402
from teemo.ir import (  # noqa: E402
    Address,
    AddressRange,
    Architecture,
    Binary,
    Document,
    Endianness,
    Function,
    Label,
    Line,
    LocationExpression,
    Scope,
    Section,
    Source,
    Variable,
)


ROOT = Path(__file__).parents[2]
GDB_SCRIPT = ROOT / "dwarf" / "gdb" / "teemo_gdb.py"
EMITTER = ROOT / "dwarf" / "emitter" / "target" / "debug" / "teemo-dwarf"


def inspected_elf(
    path: Path,
) -> tuple[int, int, int, int, int, int, int, int, str | None]:
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        text = elf.get_section_by_name(".text")
        data = elf.get_section_by_name(".data")
        symbols = elf.get_section_by_name(".symtab")
        main = symbols.get_symbol_by_name("main")[0]
        global_value = symbols.get_symbol_by_name("global_value")[0]
        build_id = None
        note = elf.get_section_by_name(".note.gnu.build-id")
        if note is not None:
            for value in note.iter_notes():
                if value["n_name"] == "GNU" and value["n_type"] == "NT_GNU_BUILD_ID":
                    build_id = str(value["n_desc"])
                    break
        return (
            int(elf.header.e_entry),
            int(text.header.sh_addr),
            int(text.header.sh_size),
            int(data.header.sh_addr),
            int(data.header.sh_size),
            int(main.entry.st_value),
            int(main.entry.st_size),
            int(global_value.entry.st_value),
            build_id,
        )


def document_for(path: Path, *, generation: int = 1) -> Document:
    (
        entry,
        text_addr,
        text_size,
        data_addr,
        data_size,
        main_addr,
        main_size,
        global_addr,
        build_id,
    ) = inspected_elf(path)
    text_id = "section:text"
    data_id = "section:data"
    main_end = main_addr + max(main_size, 1)
    function_range = AddressRange(Address(main_addr, text_id), Address(main_end, text_id))
    return Document(
        producer="Teemo GDB integration test",
        binary=Binary(
            filename=path.name,
            architecture=Architecture.X86_64,
            endianness=Endianness.LITTLE,
            entry_point=entry,
            image_base=0,
            build_id=build_id,
        ),
        sections=[
            Section(text_id, ".text", text_addr, text_size, executable=True),
            Section(data_id, ".data", data_addr, data_size, writable=True),
        ],
        types=[{"id": "type:int", "kind": "base", "name": "int", "byte_size": 4, "encoding": "signed"}],
        globals=[
            Variable(
                id="global:value",
                name="global_value",
                kind="global",
                type_id="type:int",
                static_location=LocationExpression(kind="address", address=Address(global_addr, data_id)),
                external=True,
            )
        ],
        functions=[
            Function(
                id="function:main",
                name="main",
                ranges=[function_range],
                return_type="type:int",
                parameters=[],
                scope=Scope("scope:main", [function_range]),
            )
        ],
        labels=[
            Label(
                "label:main",
                f"teemo_epoch_{generation}",
                Address(main_addr, text_id),
                function_id="function:main",
            )
        ],
        sources=[
            Source(
                "source:main",
                "teemo/main.c",
                "c",
                True,
                f"int main(void)\n{{\n    return global_value + {generation - 1};\n}}\n",
            )
        ],
        lines=[Line(function_range, "source:main", 3, column=5, statement=True)],
    )


@unittest.skipUnless(shutil.which("gdb") and shutil.which("clang"), "gdb and clang are required")
class GdbIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["cargo", "build", "--manifest-path", str(ROOT / "dwarf" / "emitter" / "Cargo.toml")],
            check=True,
        )

    def _run_case(self, *, pie: bool) -> str:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "fixture.c"
            source.write_text("int global_value = 7; int main(void) { return global_value; }\n")
            executable = root / ("fixture-pie" if pie else "fixture-exec")
            command = ["clang", str(source), "-g0", "-O0", "-o", str(executable)]
            command.append("-pie" if pie else "-no-pie")
            subprocess.run(command, check=True)
            document = document_for(executable)
            store = ArtifactStore(root / "state", emitter=EMITTER)
            manifest = store.publish(document, executable)
            current = root / "state" / manifest.view_id / "current.json"

            commands = [
                "set pagination off",
                "set confirm off",
                "set debuginfod enabled off",
                f"file {executable}",
            ]
            if pie:
                commands.append("starti")
            commands.extend(
                [
                    f"source {GDB_SCRIPT}",
                    f"teemo-refresh {current}",
                    "teemo-status",
                    "info address global_value",
                    "info address teemo_epoch_1",
                    "info line main",
                    "list main",
                    "ptype int",
                    "teemo-unload",
                ]
            )
            gdb_command = ["gdb", "-nx", "-q", "-batch"]
            for value in commands:
                gdb_command.extend(("-ex", value))
            result = subprocess.run(gdb_command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(result.returncode, 0, result.stdout)
            return result.stdout

    def test_non_pie_refresh(self) -> None:
        output = self._run_case(pie=False)
        self.assertIn("bias 0x0", output)
        self.assertIn("global_value", output)
        self.assertIn("teemo_epoch_1", output)
        self.assertIn("teemo/main.c", output)
        self.assertIn("return global_value", output)

    def test_auto_routing_and_manual_target_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_a = root / "binary-a.c"
            source_b = root / "binary-b.c"
            source_a.write_text("int global_value = 11; int main(void) { return global_value; }\n")
            source_b.write_text("int global_value = 22; int main(void) { return global_value + 1; }\n")
            binary_a = root / "binary-a"
            binary_b = root / "binary-b"
            for source, output in ((source_a, binary_a), (source_b, binary_b)):
                subprocess.run(
                    [
                        "clang",
                        str(source),
                        "-g0",
                        "-O0",
                        "-no-pie",
                        "-Wl,--build-id=sha1",
                        "-o",
                        str(output),
                    ],
                    check=True,
                )

            store = ArtifactStore(root / "state", emitter=EMITTER)
            manifest_a = store.publish(document_for(binary_a, generation=11), binary_a)
            store.publish(document_for(binary_b, generation=22), binary_b)
            current_a = root / "state" / manifest_a.view_id / "current.json"
            renamed_a = root / "renamed-binary-a"
            shutil.copy2(binary_a, renamed_a)

            commands = [
                "set pagination off",
                "set confirm off",
                "set debuginfod enabled off",
                f"file {binary_b}",
                f"source {GDB_SCRIPT}",
                "teemo-refresh",
                "info address teemo_epoch_22",
                f"teemo-refresh --target {renamed_a}",
                "info address teemo_epoch_11",
                "teemo-refresh",
                f"teemo-refresh {current_a}",
                "teemo-status",
                "info address teemo_epoch_11",
                "teemo-unload",
            ]
            gdb_command = ["gdb", "-nx", "-q", "-batch"]
            for value in commands:
                gdb_command.extend(("-ex", value))
            environment = os.environ.copy()
            environment["TEEMO_STATE_DIR"] = str(root / "state")
            result = subprocess.run(
                gdb_command,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("for binary-b", result.stdout)
            self.assertIn("for binary-a", result.stdout)
            self.assertIn("teemo_epoch_22", result.stdout)
            self.assertIn("teemo_epoch_11", result.stdout)
            self.assertIn("bias 0x0", result.stdout)

    def test_mismatched_manual_pie_requires_bias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pie_source = root / "pie.c"
            main_source = root / "gdb-main.c"
            pie_source.write_text("int global_value = 7; int main(void) { return global_value; }\n")
            main_source.write_text("int global_value = 9; int main(void) { return global_value + 2; }\n")
            pie = root / "manual-pie"
            gdb_main = root / "gdb-main"
            subprocess.run(
                [
                    "clang",
                    str(pie_source),
                    "-g0",
                    "-O0",
                    "-pie",
                    "-Wl,--build-id=sha1",
                    "-o",
                    str(pie),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "clang",
                    str(main_source),
                    "-g0",
                    "-O0",
                    "-no-pie",
                    "-Wl,--build-id=sha1",
                    "-o",
                    str(gdb_main),
                ],
                check=True,
            )
            store = ArtifactStore(root / "state", emitter=EMITTER)
            store.publish(document_for(pie), pie)

            commands = [
                "set pagination off",
                "set confirm off",
                "set debuginfod enabled off",
                f"file {gdb_main}",
                f"source {GDB_SCRIPT}",
                f"teemo-refresh --target {pie}",
                f"teemo-refresh --target {pie} --bias 0x50000000",
                "teemo-status",
                "teemo-unload",
                "quit",
            ]
            environment = os.environ.copy()
            environment["TEEMO_STATE_DIR"] = str(root / "state")
            result = subprocess.run(
                ["gdb", "-nx", "-q"],
                input="\n".join(commands) + "\n",
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("requires --bias ADDRESS", result.stdout)
            self.assertIn("bias 0x50000000", result.stdout)

    def test_live_refresh_replaces_generation_and_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "fixture.c"
            source.write_text("int global_value = 7; int main(void) { return global_value; }\n")
            executable = root / "fixture-exec"
            subprocess.run(
                [
                    "clang",
                    str(source),
                    "-g0",
                    "-O0",
                    "-no-pie",
                    "-Wl,--build-id=sha1",
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            gdb_source = root / "gdb-main.c"
            gdb_source.write_text(
                "int global_value = 99; int main(void) { return global_value + 3; }\n"
            )
            gdb_main = root / "gdb-main"
            subprocess.run(
                [
                    "clang",
                    str(gdb_source),
                    "-g0",
                    "-O0",
                    "-no-pie",
                    "-Wl,--build-id=sha1",
                    "-o",
                    str(gdb_main),
                ],
                check=True,
            )
            store = ArtifactStore(root / "state", emitter=EMITTER)
            first = store.publish(document_for(executable, generation=1), executable)
            current = root / "state" / first.view_id / "current.json"

            initial_commands = [
                "set pagination off",
                "set confirm off",
                "set debuginfod enabled off",
                f"file {gdb_main}",
                f"source {GDB_SCRIPT}",
                f"teemo-live on --target {executable}",
                "info address teemo_epoch_1",
            ]
            final_commands = [
                "teemo-status",
                "info address teemo_epoch_2",
                "list main",
                "teemo-live off",
                "teemo-unload",
                "quit",
            ]
            process = subprocess.Popen(
                ["gdb", "-nx", "-q"],
                env={**os.environ, "TEEMO_STATE_DIR": str(root / "state")},
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            try:
                process.stdin.write("\n".join(initial_commands) + "\n")
                process.stdin.flush()
                _wait_for_lease(current.parent / "leases", first.epoch, process)
                subscriber, subscriber_value = _wait_for_subscriber(
                    current.parent / "subscribers", process
                )
                second = store.publish(document_for(executable, generation=2), executable)
                _wait_for_lease(current.parent / "leases", second.epoch, process)
                process.stdin.write("\n".join(final_commands) + "\n")
                process.stdin.flush()
                process.wait(timeout=20)
                output = process.stdout.read()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                process.stdin.close()
                process.stdout.close()
            self.assertEqual(process.returncode, 0, output)
            self.assertIn(f"loaded epoch {first.epoch}", output)
            self.assertIn(f"loaded epoch {second.epoch}", output)
            self.assertIn(f"epoch {second.epoch}", output)
            self.assertIn("teemo_epoch_1", output)
            self.assertIn("teemo_epoch_2", output)
            self.assertIn("return global_value + 1", output)
            leases = current.parent / "leases"
            self.assertFalse(list(leases.glob("*.json")))
            self.assertFalse(subscriber.exists())
            self.assertFalse(Path(str(subscriber_value["socket_path"])).exists())

    def test_failed_refresh_restores_prior_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "fixture.c"
            source.write_text("int global_value = 7; int main(void) { return global_value; }\n")
            executable = root / "fixture-exec"
            subprocess.run(
                ["clang", str(source), "-g0", "-O0", "-no-pie", "-o", str(executable)],
                check=True,
            )
            store = ArtifactStore(root / "state", emitter=EMITTER)
            manifest = store.publish(document_for(executable), executable)
            current = root / "state" / manifest.view_id / "current.json"
            invalid_object = root / "invalid.debug"
            invalid_object.write_bytes(b"not an ELF object")
            invalid_manifest = root / "invalid.json"
            value = json.loads(current.read_text())
            value["epoch"] = manifest.epoch + 1
            value["debug_object"] = str(invalid_object)
            invalid_manifest.write_text(json.dumps(value))

            commands = [
                "set pagination off",
                "set confirm off",
                "set debuginfod enabled off",
                f"file {executable}",
                f"source {GDB_SCRIPT}",
                f"teemo-refresh {current} --bias 0",
                f"teemo-refresh {invalid_manifest} --bias 0 --force",
                "teemo-status",
                "info address teemo_epoch_1",
                "teemo-unload",
                "quit",
            ]
            result = subprocess.run(
                ["gdb", "-nx", "-q"],
                input="\n".join(commands) + "\n",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("restored the prior Teemo generation", result.stdout)
            self.assertIn(f"epoch {manifest.epoch}", result.stdout)
            self.assertIn("teemo_epoch_1", result.stdout)
            leases = current.parent / "leases"
            self.assertFalse(list(leases.glob("*.json")))

    def test_pie_refresh_derives_runtime_bias(self) -> None:
        output = self._run_case(pie=True)
        self.assertRegex(output, r"bias 0x[1-9a-f][0-9a-f]+")
        self.assertIn("teemo/main.c", output)
        self.assertIn("return global_value", output)

    def test_pie_refresh_requires_runtime_or_explicit_bias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "fixture.c"
            source.write_text("int global_value = 7; int main(void) { return global_value; }\n")
            executable = root / "fixture-pie"
            subprocess.run(
                ["clang", str(source), "-g0", "-O0", "-pie", "-o", str(executable)],
                check=True,
            )
            store = ArtifactStore(root / "state", emitter=EMITTER)
            manifest = store.publish(document_for(executable), executable)
            current = root / "state" / manifest.view_id / "current.json"
            commands = [
                "set pagination off",
                "set confirm off",
                "set debuginfod enabled off",
                f"file {executable}",
                f"source {GDB_SCRIPT}",
                f"teemo-refresh {current}",
            ]
            gdb_command = ["gdb", "-nx", "-q", "-batch"]
            for value in commands:
                gdb_command.extend(("-ex", value))
            result = subprocess.run(
                gdb_command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("cannot determine PIE load bias", result.stdout)


def _wait_for_lease(leases: Path, epoch: int, process: subprocess.Popen[str]) -> Path:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"GDB exited before loading Teemo epoch {epoch}")
        for lease in leases.glob("*.json"):
            try:
                if int(json.loads(lease.read_text())["epoch"]) == epoch:
                    return lease
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
        time.sleep(0.05)
    raise AssertionError(f"GDB did not acquire a lease for Teemo epoch {epoch}")


def _wait_for_subscriber(
    subscribers: Path, process: subprocess.Popen[str]
) -> tuple[Path, dict[str, object]]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("GDB exited before registering a Teemo subscriber")
        for descriptor in subscribers.glob("*.json"):
            try:
                value = json.loads(descriptor.read_text())
                socket_path = Path(str(value["socket_path"]))
                metadata = socket_path.lstat()
                if (
                    value.get("schema") == "pwnc.teemo.subscriber"
                    and int(value["pid"]) == process.pid
                    and stat.S_ISSOCK(metadata.st_mode)
                ):
                    return descriptor, value
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
        time.sleep(0.05)
    raise AssertionError("GDB did not register a Teemo Unix socket subscriber")


if __name__ == "__main__":
    unittest.main()
