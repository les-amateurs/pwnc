from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
TESTS_DIR = Path(__file__).parent
sys.path.insert(0, str(PLUGIN_DIR))
sys.path.insert(0, str(TESTS_DIR))

from binja_harness_probe import _generic_document_summary, _generic_prepass_summary
from run_binja_harness import (
    _annotate_generic_provenance,
    _gui_container_command,
    _stage_generic_binaries,
    parse_arguments,
)
from teemo.canary_analysis import CanaryAnalysisReport, CanaryFunctionReport
from teemo.discovery import DiscoveryReport
from teemo.format_analysis import (
    AutoTagSyncResult,
    FormatAnalysisReport,
    FormatCall,
    FormatOrigin,
    InferredWrapper,
    OriginAssessment,
    ResolvedCallee,
    SignatureBootstrapResult,
)
from teemo.ir import Architecture, Binary, Diagnostic, Document, Endianness, Section
from teemo.prepass import PreExportReport


class _View:
    def get_function_at(self, address: int):
        return SimpleNamespace(name="recovered_win") if address == 0x1337 else None


class GenericHarnessTests(unittest.TestCase):
    def test_gui_probe_is_auto_loaded_without_focused_window_input(self) -> None:
        command = _gui_container_command(
            harness=Path("/approved/harness"),
            image="binja:test",
            temporary=Path("/temporary/probe"),
            container="probe-container",
            container_binaries=["/work/probe/challenge"],
            expected_orphans={},
            mode="generic",
        )
        rendered = "\n".join(command)
        self.assertIn(
            "binja_gui_probe_plugin:/home/binja/.binaryninja/plugins/teemo_harness_probe:ro",
            rendered,
        )
        self.assertIn("TEEMO_HARNESS_MODE=generic", command)
        self.assertNotIn("BN_OPEN_FILE", rendered)
        self.assertNotIn("binja_gui_driver.py", rendered)
        metadata = json.loads(
            (TESTS_DIR / "binja_gui_probe_plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["name"], "Teemo GUI Harness Probe")

    def test_runner_cli_defaults_to_original_fixture_mode(self) -> None:
        arguments = parse_arguments([])
        self.assertEqual(arguments.binary, [])
        self.assertEqual(arguments.timeout, 180.0)

    def test_runner_cli_accepts_repeatable_real_binary_targets(self) -> None:
        arguments = parse_arguments(
            ["--binary", "/tmp/one", "--binary", "/tmp/two", "--timeout", "600"]
        )
        self.assertEqual(arguments.binary, [Path("/tmp/one"), Path("/tmp/two")])
        self.assertEqual(arguments.timeout, 600.0)

    def test_generic_targets_are_staged_without_basename_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            first = root / "first" / "challenge"
            second = root / "second" / "challenge"
            destination = root / "staged"
            first.parent.mkdir()
            second.parent.mkdir()
            destination.mkdir()
            first.write_bytes(b"first")
            second.write_bytes(b"second")

            staged = _stage_generic_binaries([first, second], destination)

            self.assertEqual([item.name for item in staged], ["challenge", "1-challenge"])
            self.assertEqual([item.read_bytes() for item in staged], [b"first", b"second"])

    def test_generic_result_records_original_binary_identity(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            binary = Path(root_name) / "challenge"
            binary.write_bytes(b"real challenge bytes")
            result: dict[str, object] = {"documents": [{}]}

            _annotate_generic_provenance(result, [binary])

            document = result["documents"][0]
            self.assertEqual(document["host_path"], str(binary.resolve()))
            self.assertEqual(document["input_size"], 20)
            self.assertEqual(
                document["input_sha256"],
                "a2e4a1d5235a855a41db0cabe3ffd7e46a0879047ef0f0f23c02bd6ac23439f9",
            )

    def test_generic_prepass_summary_preserves_security_results(self) -> None:
        resolved = ResolvedCallee("printf", 0, 1, "direct")
        risky = FormatCall(
            0x1200,
            "main",
            0x1210,
            7,
            resolved,
            OriginAssessment(FormatOrigin.WRITABLE, (0x4000,), (".data",), reason="writable"),
        )
        wrapper = InferredWrapper(0x1400, "log", 0, 1, 1, ("printf",), (0x1410,))
        report = PreExportReport(
            discovery=DiscoveryReport(
                scanned_bytes=32,
                candidates=2,
                added=(0x1337,),
                rejected=(0x1440,),
                rejection_reasons=((0x1440, "escaped gap"),),
            ),
            canary=CanaryAnalysisReport(
                "linux-x86",
                9,
                "created-auto",
                functions=(
                    CanaryFunctionReport(
                        0x1200,
                        "tls",
                        0x14,
                        ("guard-check",),
                        "created-auto",
                        "created-auto",
                    ),
                ),
                analysis_updates=1,
            ),
            format_signatures=SignatureBootstrapResult(updated_functions=(0x1030,), settled=True),
            format_analysis=FormatAnalysisReport((risky,), (wrapper,)),
            tag_sync=AutoTagSyncResult(added=2),
            diagnostics=(Diagnostic("warning", "fixture-note", "note"),),
        )

        summary = _generic_prepass_summary(_View(), report)

        self.assertEqual(summary["orphan"]["recovered"][0]["name"], "recovered_win")
        self.assertEqual(summary["canary"]["matched_functions"], [0x1200])
        self.assertEqual(summary["format"]["findings"], 1)
        self.assertEqual(summary["format"]["origins"], {"writable": 1})
        self.assertEqual(summary["tags"]["added"], 2)
        self.assertEqual(summary["diagnostics"], 1)

    def test_generic_document_summary_validates_and_counts(self) -> None:
        document = Document(
            producer="unit test",
            binary=Binary(
                "challenge",
                Architecture.X86,
                Endianness.LITTLE,
                0x1000,
                0,
                "0011",
            ),
            sections=[Section("text", ".text", 0x1000, 0x100, executable=True)],
            diagnostics=[
                Diagnostic("warning", "test-warning", f"message {index}")
                for index in range(66)
            ],
        )

        summary = _generic_document_summary(document)

        self.assertEqual(summary["architecture"], "x86")
        self.assertEqual(summary["functions"], 0)
        self.assertEqual(summary["lines"], 0)
        self.assertEqual(summary["diagnostics"]["by_code"], {"test-warning": 66})
        self.assertEqual(len(summary["diagnostics"]["details"]), 64)
        self.assertEqual(summary["diagnostics"]["details_omitted"], 2)
        self.assertEqual(summary["validation"], "ok")


if __name__ == "__main__":
    unittest.main()
