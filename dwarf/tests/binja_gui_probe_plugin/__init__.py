"""GUI-side launcher auto-loaded by the approved Binary Ninja harness."""

from __future__ import annotations

import json
import os
import threading
import time
import traceback
from pathlib import Path

RESULT_ENV = "TEEMO_HARNESS_RESULT"


def _mark_stage(name: str) -> None:
    result = Path(os.environ[RESULT_ENV])
    result.with_name(f"gui-stage-{name}").touch()


def _publish_result(path: Path, result: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _run() -> None:
    result_path = Path(os.environ[RESULT_ENV])
    try:
        _mark_stage("worker-started")
        # PluginCommand iteration can marshal onto the UI thread. Let plugin
        # discovery return and the Qt event loop start before the probe verifies
        # the command registry or opens BinaryViews.
        time.sleep(1)
        _mark_stage("probe-starting")
        from binja_harness_probe import run_probe

        binary_names = json.loads(os.environ["TEEMO_HARNESS_BINARIES"])
        if not isinstance(binary_names, list) or not all(isinstance(name, str) for name in binary_names):
            raise RuntimeError("TEEMO_HARNESS_BINARIES must be a JSON string list")
        output_dir = Path(os.environ["TEEMO_HARNESS_OUTPUT_DIR"])
        expected_orphans = json.loads(os.environ.get("TEEMO_HARNESS_ORPHANS", "{}"))
        if not isinstance(expected_orphans, dict) or not all(
            isinstance(name, str) and isinstance(address, int) for name, address in expected_orphans.items()
        ):
            raise RuntimeError("TEEMO_HARNESS_ORPHANS must be a JSON string-to-integer object")
        mode = os.environ.get("TEEMO_HARNESS_MODE", "fixture")
        if mode not in {"fixture", "generic"}:
            raise RuntimeError("TEEMO_HARNESS_MODE must be 'fixture' or 'generic'")
        result = run_probe(
            [Path(name) for name in binary_names],
            expected_version=os.environ.get("TEEMO_HARNESS_VERSION", "5.2.8722"),
            expected_architectures=os.environ.get("TEEMO_HARNESS_ARCHITECTURES", "x86_64,x86,arm,aarch64"),
            output_dir=output_dir,
            expected_orphans=expected_orphans,
            mode=mode,
        )
    except Exception as error:  # noqa: BLE001 - serialize any GUI probe failure.
        result = {
            "status": "error",
            "error": str(error),
            "traceback": traceback.format_exc(),
        }
    _publish_result(result_path, result)


if RESULT_ENV in os.environ:
    _mark_stage("plugin-imported")
    threading.Thread(target=_run, name="teemo-harness-probe", daemon=True).start()
