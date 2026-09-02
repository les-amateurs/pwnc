#!/usr/bin/env python3
"""Run the real Binary Ninja extraction probe in the approved container harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "dwarf" / "tests"
sys.path.insert(0, str(TESTS))

from fixture_support import TARGETS, compile_fixture

SKIP = 77
DEFAULT_HARNESS = Path("/home/ctf/binja-mcp-workspace/binja-mcp-full/test-auto")
DEFAULT_IMAGE = "teemo-binja-harness:5.2.8722"


def _run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=False, text=True)


def _image_exists(image: str) -> bool:
    return (
        subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def _build_image(harness: Path, image: str) -> None:
    workspace = harness.parents[1]
    command = [
        "docker",
        "build",
        "--tag",
        image,
        "--file",
        str(harness.relative_to(workspace) / "Dockerfile"),
        ".",
    ]
    subprocess.run(command, cwd=workspace, check=True)


def _run_gui_probe(
    *,
    harness: Path,
    image: str,
    temporary: Path,
    binaries: list[Path],
    expected_orphans: dict[Path, int],
    mode: str = "fixture",
    timeout: float = 180.0,
) -> dict[str, object]:
    container = f"teemo-binja-probe-{uuid.uuid4().hex}"
    result_path = temporary / "gui-result.json"
    container_binaries = [f"/work/probe/{binary.name}" for binary in binaries]
    command = _gui_container_command(
        harness=harness,
        image=image,
        temporary=temporary,
        container=container,
        container_binaries=container_binaries,
        expected_orphans={
            container_name: expected_orphans[binary]
            for binary, container_name in zip(binaries, container_binaries, strict=True)
            if binary in expected_orphans
        },
        mode=mode,
    )
    started = subprocess.run(command, check=False, capture_output=True, text=True)
    if started.returncode != 0:
        raise RuntimeError(f"could not start Binary Ninja GUI harness: {started.stderr.strip()}")

    logs = ""
    try:
        deadline = time.monotonic() + timeout
        import_deadline = min(deadline, time.monotonic() + 45)
        imported_stage = result_path.with_name("gui-stage-plugin-imported")
        while time.monotonic() < deadline:
            if result_path.is_file():
                break
            inspected = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container],
                check=False,
                capture_output=True,
                text=True,
            )
            if inspected.returncode != 0 or inspected.stdout.strip() != "true":
                break
            if time.monotonic() >= import_deadline and not imported_stage.is_file():
                break
            time.sleep(0.25)
        logged = subprocess.run(
            ["docker", "logs", container],
            check=False,
            capture_output=True,
            text=True,
        )
        logs = logged.stdout + logged.stderr
        if not result_path.is_file():
            if not imported_stage.is_file():
                raise RuntimeError(
                    "Binary Ninja did not auto-load the Teemo GUI harness plugin within 45 seconds\n" + logs
                )
            raise RuntimeError(
                f"Binary Ninja GUI probe did not publish a result within {timeout:g} seconds\n" + logs
            )
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(result, dict):
            raise TypeError("Binary Ninja GUI probe published a non-object result")
        if result.get("status") != "ok":
            detail = str(result.get("traceback") or result.get("error") or result)
            raise RuntimeError("Binary Ninja GUI probe failed:\n" + detail + "\n" + logs)
        return result
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def _gui_container_command(
    *,
    harness: Path,
    image: str,
    temporary: Path,
    container: str,
    container_binaries: list[str],
    expected_orphans: dict[str, int],
    mode: str,
) -> list[str]:
    """Construct a GUI launch that needs no focused window or synthetic input."""

    return [
        "docker",
        "run",
        "--detach",
        "--name",
        container,
        "--shm-size",
        "1g",
        "--volume",
        f"{ROOT}:/repo:ro",
        "--volume",
        f"{ROOT / 'dwarf' / 'plugin'}:/home/binja/.binaryninja/plugins/teemo:ro",
        "--volume",
        f"{TESTS / 'binja_gui_probe_plugin'}:/home/binja/.binaryninja/plugins/teemo_harness_probe:ro",
        "--volume",
        f"{harness / 'inject'}:/inject:ro",
        "--volume",
        f"{temporary}:/work/probe:rw",
        "--env",
        "PYTHONPATH=/repo/dwarf/tests",
        "--env",
        f"TEEMO_HARNESS_BINARIES={json.dumps(container_binaries)}",
        "--env",
        "TEEMO_HARNESS_ORPHANS="
        + json.dumps(expected_orphans),
        "--env",
        f"TEEMO_HARNESS_MODE={mode}",
        "--env",
        "TEEMO_HARNESS_OUTPUT_DIR=/work/probe/ir",
        "--env",
        "TEEMO_HARNESS_RESULT=/work/probe/gui-result.json",
        image,
    ]


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness", type=Path, default=DEFAULT_HARNESS)
    parser.add_argument("--image", default=os.environ.get("TEEMO_BINJA_IMAGE", DEFAULT_IMAGE))
    parser.add_argument("--build", action="store_true", help="build the exact harness image first")
    parser.add_argument(
        "--binary",
        action="append",
        type=Path,
        default=[],
        metavar="ELF",
        help="analyze an arbitrary ELF instead of compiling the fixture matrix; repeatable",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="maximum seconds for the GUI-side analysis probe (default: 180)",
    )
    return parser.parse_args(argv)


def _stage_generic_binaries(binaries: list[Path], temporary: Path) -> list[Path]:
    """Copy user-selected ELFs into the harness's isolated writable mount."""

    staged = []
    used_names: set[str] = set()
    for index, candidate in enumerate(binaries):
        source = candidate.expanduser().resolve(strict=True)
        if not source.is_file():
            raise ValueError(f"generic Binary Ninja target is not a regular file: {source}")
        name = source.name
        if name in used_names:
            name = f"{index}-{name}"
        used_names.add(name)
        destination = temporary / name
        shutil.copy2(source, destination)
        staged.append(destination)
    return staged


def _annotate_generic_provenance(result: dict[str, object], binaries: list[Path]) -> None:
    """Attach host-side identity to documents produced from staged copies."""

    documents = result.get("documents")
    if not isinstance(documents, list) or len(documents) != len(binaries):
        raise RuntimeError("generic Binary Ninja result does not match the requested binary list")
    for document, candidate in zip(documents, binaries, strict=True):
        if not isinstance(document, dict):
            raise RuntimeError("generic Binary Ninja result contains a non-object document")
        source = candidate.expanduser().resolve(strict=True)
        digest = hashlib.sha256()
        with source.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        document["host_path"] = str(source)
        document["input_size"] = source.stat().st_size
        document["input_sha256"] = digest.hexdigest()


def main(argv: list[str]) -> int:
    arguments = parse_arguments(argv)
    if arguments.timeout <= 0:
        raise ValueError("--timeout must be positive")
    harness = arguments.harness.expanduser().resolve(strict=False)
    if shutil.which("docker") is None:
        print("SKIP: docker is unavailable", file=sys.stderr)
        return SKIP
    if not (harness / "Dockerfile").is_file() or not (harness / "inject").is_dir():
        print(f"SKIP: approved Binary Ninja harness is unavailable at {harness}", file=sys.stderr)
        return SKIP
    if arguments.build:
        _build_image(harness, arguments.image)
    elif not _image_exists(arguments.image):
        print(
            f"SKIP: image {arguments.image!r} is absent; rerun with --build",
            file=sys.stderr,
        )
        return SKIP

    module_smoke = _run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python3",
            "--volume",
            f"{ROOT}:/repo:ro",
            "--env",
            "PYTHONPATH=/repo/dwarf/plugin",
            arguments.image,
            "-c",
            (
                "import binaryninja; "
                "import teemo.analysis, teemo.artifacts, teemo.canary_analysis, teemo.commands, "
                "teemo.extractor, teemo.format_analysis, teemo.ir, teemo.prepass, teemo.type_export; "
                "assert '5.2.8722' in str(binaryninja.core_version())"
            ),
        ]
    )
    if module_smoke.returncode != 0:
        return module_smoke.returncode

    layout_smoke = _run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python3",
            "--volume",
            f"{ROOT / 'dwarf' / 'plugin'}:/home/binja/.binaryninja/plugins/teemo:ro",
            "--env",
            "PYTHONPATH=/home/binja/.binaryninja/plugins",
            arguments.image,
            "-c",
            (
                "import binaryninja; "
                "binaryninja.PluginCommand.register = lambda *args, **kwargs: None; "
                "import teemo; import teemo.teemo.extractor; "
                "assert '5.2.8722' in str(binaryninja.core_version())"
            ),
        ]
    )
    if layout_smoke.returncode != 0:
        return layout_smoke.returncode

    with tempfile.TemporaryDirectory(prefix="teemo-binja-probe-") as temporary_name:
        temporary = Path(temporary_name)
        temporary.chmod(0o777)
        outputs = temporary / "ir"
        outputs.mkdir(mode=0o777)
        outputs.chmod(0o777)
        binaries: list[Path] = []
        expected_orphans: dict[Path, int] = {}
        mode = "generic" if arguments.binary else "fixture"
        if mode == "generic":
            binaries = _stage_generic_binaries(arguments.binary, temporary)
        else:
            for target_name, target in TARGETS.items():
                binary = temporary / f"fixture-{target_name}"
                orphan = compile_fixture(
                    binary,
                    target,
                    pie=True,
                    orphan_import=True,
                    security_annotations=True,
                )
                if orphan is None:
                    raise RuntimeError(f"orphan fixture for {target_name} returned no address")
                binaries.append(binary)
                expected_orphans[binary] = orphan
        result = _run_gui_probe(
            harness=harness,
            image=arguments.image,
            temporary=temporary,
            binaries=binaries,
            expected_orphans=expected_orphans,
            mode=mode,
            timeout=arguments.timeout,
        )
        if mode == "generic":
            _annotate_generic_provenance(result, arguments.binary)
        print(json.dumps(result, sort_keys=True))

        emitter_manifest = ROOT / "dwarf" / "emitter" / "Cargo.toml"
        subprocess.run(["cargo", "build", "--manifest-path", str(emitter_manifest)], check=True)
        emitter = ROOT / "dwarf" / "emitter" / "target" / "debug" / "teemo-dwarf"
        for binary in binaries:
            output = outputs / f"{binary.name}.json"
            debug = temporary / f"{binary.name}.debug"
            subprocess.run([str(emitter), "validate", str(output)], check=True)
            subprocess.run([str(emitter), "emit", str(output), str(debug)], check=True)
            if shutil.which("llvm-dwarfdump"):
                subprocess.run(["llvm-dwarfdump", "--verify", str(debug)], check=True)
            if shutil.which("readelf"):
                subprocess.run(
                    ["readelf", "--debug-dump=info", str(debug)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
        print(f"Binary Ninja {mode} harness extraction and DWARF emission passed")
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
