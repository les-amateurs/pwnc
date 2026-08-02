from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from payloads.tests.runtime_support.livectf import (
    ArchiveIdentity,
    LicenseIdentity,
    LiveCTFArtifactError,
    MemberIdentity,
    SourceSpec,
    _safe_extract_selected,
    _safe_extract_source,
    load_manifest,
    provision_all,
    provision_source,
    validate_provisioned_source,
)

_MANIFEST_PATH = Path(__file__).with_name("runtime_support") / "livectf_artifacts.json"


def _manifest_json() -> dict[str, object]:
    return json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))


def _load_mutation(value: dict[str, object]) -> None:
    with tempfile.TemporaryDirectory(prefix="pwnc-livectf-manifest-") as directory:
        path = Path(directory) / "manifest.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        load_manifest(path)


def _tar_bytes(
    entries: list[tuple[str, bytes | None, str | None]],
    *,
    gzip: bool = True,
) -> bytes:
    """Build a deterministic-enough in-memory tar for extraction unit tests.

    ``data is None, link is None`` creates a directory; a non-``None`` link
    creates a symlink; otherwise the entry is a regular file.
    """

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz" if gzip else "w") as archive:
        for name, data, link in entries:
            member = tarfile.TarInfo(name)
            member.mtime = 0
            if link is not None:
                member.type = tarfile.SYMTYPE
                member.linkname = link
                member.mode = 0o777
                archive.addfile(member)
            elif data is None:
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                archive.addfile(member)
            else:
                member.size = len(data)
                member.mode = 0o755 if name.endswith("challenge") else 0o644
                archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


class LiveCTFManifestTests(unittest.TestCase):
    def test_manifest_pins_all_four_source_snapshots_and_two_release_handouts(self) -> None:
        manifest = load_manifest()
        expected_commits = {
            "defcon30": "2f54bc3c481c1fd43559b6c85db41c968479f0e9",
            "defcon31": "d654ed5b65b28ed52dbad1a441083cce47edd707",
            "defcon32": "bd7dbd3aebcf2b79d7db810c92222de6657dc350",
            "defcon33": "be722a0191dc51f4531b76b6c7195dc538fb2496",
        }
        self.assertEqual(manifest.schema_version, 1)
        self.assertEqual({item.id: item.commit for item in manifest.sources}, expected_commits)
        self.assertEqual(
            set(manifest.handouts_by_id),
            {"defcon30-seek-and-destroy", "defcon31-ptrace-me-maybe"},
        )
        self.assertEqual(len(manifest.observations), 1)

    def test_every_download_and_member_is_content_pinned(self) -> None:
        manifest = load_manifest()
        archives = [item.archive for item in manifest.sources] + [item.outer_archive for item in manifest.handouts]
        for archive in archives:
            with self.subTest(archive=archive.name):
                self.assertTrue(archive.url.startswith("https://"))
                self.assertGreater(archive.size, 0)
                self.assertRegex(archive.sha256, r"^[0-9a-f]{64}$")
        for source in manifest.sources:
            identities = (source.license, *source.critical_members)
            for identity in identities:
                with self.subTest(source=source.id, member=identity.path):
                    self.assertGreater(identity.size, 0)
                    self.assertRegex(identity.sha256, r"^[0-9a-f]{64}$")
        for handout in manifest.handouts:
            if handout.nested_archive is not None:
                self.assertRegex(handout.nested_archive.sha256, r"^[0-9a-f]{64}$")
            for identity in handout.files:
                with self.subTest(handout=handout.id, member=identity.path):
                    self.assertRegex(identity.sha256, r"^[0-9a-f]{64}$")
                    self.assertRegex(identity.elf_build_id, r"^(?:[0-9a-f]{2})+$")

    def test_exact_seek_and_ptrace_release_identities_are_not_interchangeable(self) -> None:
        manifest = load_manifest()
        seek = manifest.handouts_by_id["defcon30-seek-and-destroy"]
        ptrace = manifest.handouts_by_id["defcon31-ptrace-me-maybe"]
        self.assertEqual(seek.outer_archive.sha256, "d5d879be936d7b94bb5ae35176828a1462dee03673308614224c9121e4114760")
        self.assertIsNotNone(seek.nested_archive)
        self.assertEqual(
            seek.nested_archive.sha256 if seek.nested_archive else None,
            "2fde19e72bea8435e9747f318f6c6dbccba6c5301cd8f0a6b2351aa5c7ae66ab",
        )
        self.assertEqual(
            ptrace.outer_archive.sha256, "b5580b0f55b770d7d5c78ef9960369d588b4418c8e0140db232e64ea78884cb9"
        )
        self.assertIsNone(ptrace.nested_archive)
        self.assertNotEqual(seek.files[0].sha256, ptrace.files[0].sha256)
        self.assertEqual(seek.files[1:], ptrace.files[1:])

    def test_apache_provenance_is_attested_by_each_snapshot_license_member(self) -> None:
        manifest = load_manifest()
        self.assertEqual(manifest.provenance.spdx, "Apache-2.0")
        self.assertEqual(manifest.provenance.license_url, "https://www.apache.org/licenses/LICENSE-2.0")
        self.assertTrue(all(source.license.spdx == "Apache-2.0" for source in manifest.sources))
        self.assertTrue(all(source.license.path == "LICENSE" for source in manifest.sources))

    def test_mutable_defcon32_build_is_separate_and_non_provisionable(self) -> None:
        manifest = load_manifest()
        observation = manifest.observations[0]
        self.assertEqual(observation.id, "defcon32-process-vm-readv-current-mutable-build")
        self.assertEqual(observation.source_id, "defcon32")
        self.assertFalse(observation.reproducible)
        self.assertFalse(observation.bootstrap_observation.immutable_contract)
        self.assertEqual(observation.bootstrap_observation.stable_offset, "0x22a8")
        self.assertNotIn(observation.id, manifest.handouts_by_id)
        self.assertNotIn(
            observation.files[0].sha256, {item.sha256 for handout in manifest.handouts for item in handout.files}
        )

    def test_loading_manifest_never_attempts_network_access(self) -> None:
        with mock.patch(
            "payloads.tests.runtime_support.livectf.urllib.request.urlopen",
            side_effect=AssertionError("normal fixture tests must remain offline"),
        ):
            manifest = load_manifest()
        self.assertEqual(len(manifest.sources), 4)

    def test_manifest_indexes_are_immutable(self) -> None:
        manifest = load_manifest()
        with self.assertRaises(TypeError):
            manifest.sources_by_id["extra"] = manifest.sources[0]  # type: ignore[index]
        with self.assertRaises(TypeError):
            manifest.handouts_by_id["extra"] = manifest.handouts[0]  # type: ignore[index]


class LiveCTFManifestMutationTests(unittest.TestCase):
    def assertMutationRejected(self, mutate: object, pattern: str) -> None:
        value = copy.deepcopy(_manifest_json())
        assert callable(mutate)
        mutate(value)
        with self.assertRaisesRegex(LiveCTFArtifactError, pattern):
            _load_mutation(value)

    def test_unknown_top_level_key_is_rejected(self) -> None:
        self.assertMutationRejected(lambda value: value.update({"downloads": []}), "keys differ")

    def test_non_https_source_is_rejected(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["sources"][0]["archive"]["url"] = "http://example.invalid/source.tar.gz"  # type: ignore[index]

        self.assertMutationRejected(mutate, "must be an HTTPS URL")

    def test_source_url_must_end_in_exact_commit(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["sources"][0]["archive"]["url"] = (  # type: ignore[index]
                "https://codeload.github.com/Live-CTF/LiveCTF-DEFCON30/tar.gz/0000000000000000000000000000000000000000"
            )

        self.assertMutationRejected(mutate, "does not end in its pinned commit")

    def test_bad_archive_digest_is_rejected(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["sources"][0]["archive"]["sha256"] = "A" * 64  # type: ignore[index]

        self.assertMutationRejected(mutate, "64 lowercase hexadecimal")

    def test_unsafe_source_member_is_rejected(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["sources"][0]["critical_members"][0]["path"] = "../../host"  # type: ignore[index]

        self.assertMutationRejected(mutate, "unsafe archive-relative path")

    def test_duplicate_source_id_is_rejected(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["sources"][1]["id"] = value["sources"][0]["id"]  # type: ignore[index]

        self.assertMutationRejected(mutate, "duplicate source ID")

    def test_handout_must_link_to_a_known_source(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["handouts"][0]["source_id"] = "defcon99"  # type: ignore[index]

        self.assertMutationRejected(mutate, "unknown source")

    def test_bad_elf_build_id_is_rejected(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["handouts"][0]["files"][0]["elf_build_id"] = "abc"  # type: ignore[index]

        self.assertMutationRejected(mutate, "even-length lowercase hexadecimal")

    def test_mutable_observation_cannot_be_promoted_to_reproducible(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["observations"][0]["reproducible"] = True  # type: ignore[index]

        self.assertMutationRejected(mutate, "must never be marked reproducible")

    def test_bootstrap_observation_cannot_be_promoted_to_contract(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["observations"][0]["bootstrap_observation"]["immutable_contract"] = True  # type: ignore[index]

        self.assertMutationRejected(mutate, "must not be an immutable contract")


class LiveCTFSafeExtractionTests(unittest.TestCase):
    def test_source_extraction_rejects_parent_traversal(self) -> None:
        payload = _tar_bytes(
            [
                ("repo/", None, None),
                ("repo/../../outside", b"escape", None),
            ]
        )
        with (
            tempfile.TemporaryDirectory(prefix="pwnc-livectf-extract-") as directory,
            tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive,
        ):
            with self.assertRaisesRegex(LiveCTFArtifactError, "unsafe archive-relative path"):
                _safe_extract_source(archive, Path(directory), "repo")
            self.assertFalse((Path(directory).parent / "outside").exists())

    def test_source_extraction_rejects_escaping_symlink(self) -> None:
        payload = _tar_bytes(
            [
                ("repo/", None, None),
                ("repo/link", None, "../../outside"),
            ]
        )
        with (
            tempfile.TemporaryDirectory(prefix="pwnc-livectf-extract-") as directory,
            tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive,
            self.assertRaisesRegex(LiveCTFArtifactError, "symlink target escapes"),
        ):
            _safe_extract_source(archive, Path(directory), "repo")

    def test_source_extraction_allows_an_in_tree_relative_symlink(self) -> None:
        payload = _tar_bytes(
            [
                ("repo/", None, None),
                ("repo/target", b"source", None),
                ("repo/link", None, "target"),
            ]
        )
        with tempfile.TemporaryDirectory(prefix="pwnc-livectf-extract-") as directory:
            root = Path(directory)
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
                _safe_extract_source(archive, root, "repo")
            self.assertTrue((root / "link").is_symlink())
            self.assertEqual((root / "link").read_bytes(), b"source")

    def test_handout_selection_accepts_dot_root_but_rejects_symlink_alias(self) -> None:
        payload = _tar_bytes(
            [
                ("./", None, None),
                ("./handout/", None, None),
                ("./handout/real", b"elf", None),
                ("./handout/challenge", None, "real"),
            ]
        )
        with (
            tempfile.TemporaryDirectory(prefix="pwnc-livectf-extract-") as directory,
            tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive,
            self.assertRaisesRegex(LiveCTFArtifactError, "not a regular file"),
        ):
            _safe_extract_selected(archive, Path(directory), ("handout/challenge",))


class LiveCTFContentAddressedProvisionTests(unittest.TestCase):
    def test_source_download_is_content_addressed_cached_and_locally_repairable(self) -> None:
        commit = "1" * 40
        archive_root = f"fixture-{commit}"
        license_bytes = b"Apache License\n"
        source_bytes = b"int main(void) { return 0; }\n"
        payload = _tar_bytes(
            [
                (f"{archive_root}/", None, None),
                (f"{archive_root}/LICENSE", license_bytes, None),
                (f"{archive_root}/challenge.c", source_bytes, None),
            ]
        )
        archive_digest = hashlib.sha256(payload).hexdigest()
        spec = SourceSpec(
            "fixture",
            "Synthetic fixture",
            "https://example.invalid/fixture",
            commit,
            archive_root,
            ArchiveIdentity(
                f"fixture-{commit}.tar.gz",
                f"https://example.invalid/archive/{commit}",
                len(payload),
                archive_digest,
            ),
            LicenseIdentity("LICENSE", len(license_bytes), hashlib.sha256(license_bytes).hexdigest(), "Apache-2.0"),
            (MemberIdentity("challenge.c", len(source_bytes), hashlib.sha256(source_bytes).hexdigest()),),
        )

        with (
            tempfile.TemporaryDirectory(prefix="pwnc-livectf-cache-") as directory,
            mock.patch(
                "payloads.tests.runtime_support.livectf.urllib.request.urlopen",
                return_value=io.BytesIO(payload),
            ) as urlopen,
        ):
            first = provision_source(spec, directory)
            second = provision_source(spec, directory)
            self.assertEqual(first.root, second.root)
            self.assertEqual(urlopen.call_count, 1)
            self.assertTrue((Path(directory) / "artifacts" / f"{archive_digest}.tar.gz").is_file())

            (first.root / "challenge.c").write_bytes(b"corrupt")
            repaired = provision_source(spec, directory)
            self.assertEqual((repaired.root / "challenge.c").read_bytes(), source_bytes)
            self.assertEqual(urlopen.call_count, 1)
            validate_provisioned_source(repaired)


@unittest.skipUnless(os.environ.get("PWNC_LIVECTF_TESTS") == "1", "set PWNC_LIVECTF_TESTS=1 for live downloads")
class LiveCTFDownloadTests(unittest.TestCase):
    def test_download_extract_and_verify_all_pinned_sources_and_handouts(self) -> None:
        configured_cache = os.environ.get("PWNC_LIVECTF_CACHE")
        temporary: tempfile.TemporaryDirectory[str] | None = None
        if configured_cache is None:
            temporary = tempfile.TemporaryDirectory(prefix="pwnc-livectf-live-")
            configured_cache = temporary.name
        self.addCleanup(temporary.cleanup if temporary is not None else lambda: None)

        manifest = load_manifest()
        provisioned = provision_all(configured_cache, manifest=manifest)
        self.assertEqual(set(provisioned.sources), {source.id for source in manifest.sources})
        self.assertEqual(set(provisioned.handouts), {handout.id for handout in manifest.handouts})
        for source in provisioned.sources.values():
            self.assertTrue((source.root / source.spec.license.path).is_file())
            self.assertTrue(all((source.root / identity.path).is_file() for identity in source.spec.critical_members))
        for handout in provisioned.handouts.values():
            self.assertEqual(set(handout.files), {identity.path for identity in handout.spec.files})
            self.assertTrue(all(path.is_file() for path in handout.files.values()))


if __name__ == "__main__":
    unittest.main()
