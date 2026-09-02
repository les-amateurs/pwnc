from __future__ import annotations

import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


GDB_DIR = Path(__file__).parents[1] / "gdb"
sys.path.insert(0, str(GDB_DIR))

from loader_core import (  # noqa: E402
    ET_DYN,
    ET_EXEC,
    ElfImage,
    LoadSegment,
    LoaderError,
    LoaderManifest,
    add_symbol_file_command,
    architecture_matches,
    compute_load_bias,
    find_manifest,
    parse_proc_maps,
    read_elf,
    _gnu_build_id,
)


class LoaderCoreTests(unittest.TestCase):
    def test_parses_proc_maps_and_derives_pie_bias(self) -> None:
        mappings = parse_proc_maps(
            """55555000-55556000 r--p 00000000 00:01 1 /tmp/demo\n"
            "55556000-55557000 r-xp 00001000 00:01 1 /tmp/demo\n"
            "55557000-55558000 rw-p 00002000 00:01 1 /tmp/demo\n"""
        )
        image = ElfImage(
            64,
            "little",
            ET_DYN,
            62,
            0x1050,
            (
                LoadSegment(0, 0, 0x800, 0x800, 4, 0x1000),
                LoadSegment(0x1000, 0x1000, 0x800, 0x800, 5, 0x1000),
                LoadSegment(0x2000, 0x2000, 0x800, 0x1000, 6, 0x1000),
            ),
        )
        self.assertEqual(compute_load_bias("/tmp/demo", image, mappings, page_size=0x1000), 0x55555000)

    def test_non_pie_without_mappings_has_zero_bias(self) -> None:
        image = ElfImage(32, "little", ET_EXEC, 3, 0x8048000, ())
        self.assertEqual(compute_load_bias("/missing", image, []), 0)
        with self.assertRaises(LoaderError):
            compute_load_bias("/missing", ElfImage(32, "little", ET_DYN, 3, 0, ()), [])

    def test_reads_real_elf_classes_when_compilers_are_available(self) -> None:
        compiler = shutil.which("clang") or shutil.which("cc")
        if compiler is None:
            self.skipTest("no C compiler")
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "main.c"
            source.write_text("int main(void) { return 0; }\n")
            executable = Path(temporary) / "main"
            subprocess.run(
                [
                    compiler,
                    str(source),
                    "-o",
                    str(executable),
                    "-no-pie",
                    "-Wl,--build-id=sha1",
                ],
                check=True,
            )
            image = read_elf(executable)
            self.assertEqual(image.object_type, ET_EXEC)
            self.assertTrue(image.load_segments)
            self.assertRegex(image.build_id or "", r"^[0-9a-f]+$")

    def test_parses_aligned_gnu_build_id_notes(self) -> None:
        note = struct.pack("<III", 4, 4, 3) + b"GNU\0" + b"\x01\x02\x03\x04"
        self.assertEqual(_gnu_build_id(note, "<"), "01020304")
        self.assertIsNone(_gnu_build_id(note[:-1], "<"))

    def test_builds_complete_add_symbol_file_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            debug = root / "teemo.debug"
            ir = root / "teemo-ir.json"
            sources = root / "teemo.sources"
            debug.write_bytes(b"x")
            ir.write_text("{}")
            sources.mkdir()
            manifest_path = root / "current.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pwnc.teemo.manifest",
                        "version": 1,
                        "epoch": 2,
                        "view_id": "view",
                        "created_ns": 1,
                        "binary_path": "/tmp/demo",
                        "binary_filename": "demo",
                        "build_id": None,
                        "architecture": "x86_64",
                        "image_base": 0,
                        "entry_point": 0x1010,
                        "debug_object": str(debug),
                        "ir": str(ir),
                        "source_root": str(sources),
                        "primary_section": ".text",
                        "sections": [
                            {"name": ".text", "address": 0x1000, "size": 0x100, "executable": True, "writable": False},
                            {"name": ".data", "address": 0x2000, "size": 0x20, "executable": False, "writable": True},
                        ],
                    }
                )
            )
            manifest = LoaderManifest.load(manifest_path)
            command = add_symbol_file_command(manifest, 0x55555000)
            self.assertIn("add-symbol-file", command)
            self.assertIn("0x55556000", command)
            self.assertIn('-s ".data" 0x55557000', command)

    def test_gdb_command_quotes_paths_and_section_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'directory with "quotes"'
            root.mkdir()
            debug = root / "teemo debug"
            ir = root / "teemo ir.json"
            sources = root / "teemo sources"
            debug.write_bytes(b"x")
            ir.write_text("{}")
            sources.mkdir()
            manifest_path = root / "current.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pwnc.teemo.manifest",
                        "version": 1,
                        "epoch": 1,
                        "view_id": "view",
                        "created_ns": 1,
                        "binary_path": "/tmp/demo",
                        "binary_filename": "demo",
                        "build_id": None,
                        "architecture": "x86_64",
                        "image_base": 0,
                        "entry_point": 0x1000,
                        "debug_object": str(debug),
                        "ir": str(ir),
                        "source_root": str(sources),
                        "primary_section": '.text "hot"',
                        "sections": [
                            {
                                "name": '.text "hot"',
                                "address": 0x1000,
                                "size": 0x20,
                                "executable": True,
                                "writable": False,
                            }
                        ],
                    }
                )
            )
            command = add_symbol_file_command(LoaderManifest.load(manifest_path), 0)
            self.assertIn('directory with \\"quotes\\"/teemo debug"', command)

    def test_architecture_aliases_are_conservative(self) -> None:
        self.assertTrue(architecture_matches("x86_64", "i386:x86-64"))
        self.assertTrue(architecture_matches("x86", "i386"))
        self.assertTrue(architecture_matches("arm", "armv7"))
        self.assertTrue(architecture_matches("arm", "thumb2"))
        self.assertTrue(architecture_matches("aarch64", "arm64"))
        self.assertFalse(architecture_matches("x86", "i386:x86-64"))
        self.assertFalse(architecture_matches("x86", "aarch64"))
        self.assertFalse(architecture_matches("arm", "aarch64"))
        self.assertFalse(architecture_matches("aarch64", "armv8"))
        self.assertFalse(architecture_matches("unknown", "x86-64"))

    def test_manifest_discovery_uses_exact_path_or_build_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = root / "renamed-program"
            program.write_bytes(b"binary")

            def write_manifest(view: str, binary_path: Path, build_id: str, created_ns: int) -> Path:
                view_root = root / "state" / view
                generation = view_root / "generations" / "1"
                generation.mkdir(parents=True)
                debug = generation / "teemo.debug"
                ir = generation / "teemo-ir.json"
                sources = generation / "teemo.sources"
                debug.write_bytes(b"debug")
                ir.write_text("{}")
                sources.mkdir()
                current = view_root / "current.json"
                current.write_text(
                    json.dumps(
                        {
                            "schema": "pwnc.teemo.manifest",
                            "version": 1,
                            "epoch": 1,
                            "view_id": view,
                            "created_ns": created_ns,
                            "binary_path": str(binary_path),
                            "binary_filename": binary_path.name,
                            "build_id": build_id,
                            "architecture": "x86_64",
                            "image_base": 0,
                            "entry_point": 0x1000,
                            "debug_object": str(debug),
                            "ir": str(ir),
                            "source_root": str(sources),
                            "primary_section": ".text",
                            "sections": [
                                {
                                    "name": ".text",
                                    "address": 0x1000,
                                    "size": 0x20,
                                    "executable": True,
                                    "writable": False,
                                }
                            ],
                        }
                    )
                )
                return current

            older = write_manifest("older", root / "original-a", "aabb", 1)
            newer = write_manifest("newer", root / "original-b", "aabb", 2)
            exact = write_manifest("exact", program, "ccdd", 1)

            self.assertEqual(find_manifest(root / "state", program, build_id="aabb"), exact)
            program.unlink()
            self.assertEqual(
                find_manifest(root / "state", root / "copy", build_id="AABB"),
                newer,
            )
            self.assertNotEqual(newer, older)
            with self.assertRaisesRegex(LoaderError, "no Teemo manifest matches"):
                find_manifest(root / "state", root / "unrelated" / "original-a")


if __name__ == "__main__":
    unittest.main()
