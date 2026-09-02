from __future__ import annotations

import importlib.util
import logging
import sys
import time
import unittest
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_ANGR_AVAILABLE = importlib.util.find_spec("angr") is not None


class EmbeddedAngropSourceIsolationTests(unittest.TestCase):
    def test_patched_source_digest_and_logger_namespace_are_stable(self) -> None:
        from payloads import ANGROP_PATCHED_SOURCE_SHA256

        root = Path(__file__).parents[1] / "_vendor" / "angrop"
        digest = sha256()
        for source in sorted(root.rglob("*.py")):
            digest.update(source.relative_to(root).as_posix().encode())
            digest.update(b"\0")
            contents = source.read_bytes()
            digest.update(contents)
            digest.update(b"\0")
            text = contents.decode("utf-8")
            self.assertNotIn('getLogger("angrop', text)
            self.assertNotIn("getLogger('angrop", text)

        self.assertEqual(digest.hexdigest(), ANGROP_PATCHED_SOURCE_SHA256)

    def test_rop_module_has_no_process_global_named_analysis_registration(self) -> None:
        rop_source = Path(__file__).parents[1] / "_vendor" / "angrop" / "rop.py"
        cli_source = Path(__file__).parents[1] / "_vendor" / "angrop" / "angrop_cli.py"

        self.assertNotIn("register_analysis", rop_source.read_text(encoding="utf-8"))
        cli_text = cli_source.read_text(encoding="utf-8")
        self.assertIn("project.analyses[_rop.ROP]", cli_text)
        self.assertNotIn("proj.analyses.ROP", cli_text)


@unittest.skipUnless(_ANGR_AVAILABLE, "install pwnc with the 'rop' extra to test the embedded angrop source")
class EmbeddedAngropIsolationTests(unittest.TestCase):
    def test_static_discovery_deadline_does_not_block_on_a_result_iterator(self) -> None:
        from payloads._vendor.angrop.gadget_finder import GadgetFinder

        finder = object.__new__(GadgetFinder)
        finder._cache = {}
        finder._gadget_analyzer = object()
        finder._num_addresses_to_check = lambda: 1
        finder._truncated_slices = lambda: iter(((0x1000, 0x1000),))

        class StuckPool:
            def __init__(self) -> None:
                self.terminated = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def apply_async(self, *_args, **_kwargs) -> None:
                return None

            def close(self) -> None:
                return None

            def terminate(self) -> None:
                self.terminated = True

        pool = StuckPool()
        started = time.monotonic()
        with mock.patch("payloads._vendor.angrop.gadget_finder.mp.Pool", return_value=pool):
            todos, remaining = finder._multiprocess_static_analysis(1, False, 0.05)
        elapsed = time.monotonic() - started

        self.assertEqual(todos, [])
        self.assertLessEqual(remaining, 0)
        self.assertLess(elapsed, 1.0)
        self.assertTrue(pool.terminated)

    def test_import_does_not_disable_python_integer_conversion_limits(self) -> None:
        if not hasattr(sys, "get_int_max_str_digits"):
            self.skipTest("this Python has no integer-string conversion limit")
        before = sys.get_int_max_str_digits()

        __import__("payloads._vendor.angrop")

        self.assertEqual(sys.get_int_max_str_digits(), before)

    def test_gadget_finder_construction_does_not_reconfigure_host_loggers(self) -> None:
        from payloads._vendor.angrop.gadget_finder import GadgetFinder

        names = (
            "pyvex.lifting",
            "angr.engines.vex.ccall",
            "angr.engines.vex.expressions.ccall",
            "angr.engines.vex.irop",
            "pyvex.lifting.libvex",
            "angr.state_plugins.symbolic_memory",
            "angr.state_plugins.posix",
            "angr.procedures",
        )
        levels = {name: logging.getLogger(name).level for name in names}
        try:
            for index, name in enumerate(names):
                logging.getLogger(name).setLevel(logging.DEBUG + index)
            expected = {name: logging.getLogger(name).level for name in names}
            fake_arch = SimpleNamespace(max_block_size=20, max_sym_mem_access=1)
            with mock.patch("payloads._vendor.angrop.gadget_finder.get_arch", return_value=fake_arch):
                GadgetFinder(SimpleNamespace(), only_check_near_rets=False)
            self.assertEqual({name: logging.getLogger(name).level for name in names}, expected)
        finally:
            for name, level in levels.items():
                logging.getLogger(name).setLevel(level)

    def test_initial_state_plugin_is_restored_when_state_construction_raises(self) -> None:
        import angr

        from payloads._vendor.angrop import rop_utils

        preset = angr.SimState._presets["default"]
        before = preset._default_plugins["sym_memory"]
        project = SimpleNamespace(factory=SimpleNamespace(blank_state=mock.Mock(side_effect=RuntimeError("boom"))))

        with self.assertRaisesRegex(RuntimeError, "boom"):
            rop_utils.make_initial_state(project, 1)

        self.assertIs(preset._default_plugins["sym_memory"], before)


if __name__ == "__main__":
    unittest.main()
