"""The build hook that pulls vectors/ into fiki-vectors (``this.i`` @58dr3z98).

These run the hook's logic against small trees laid out the two ways a build meets it: the
repository, where the vectors are two levels up, and an unpacked sdist, which carries its own copy.
test_distribution.py checks what real builds produce, and that MANIFEST is the committed set.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import hatch_build

MANIFEST = ("accepts.json", "keri/requests.json", "keys/openssh/ed25519.pub")


def write(path: Path, text: str = "{}") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def repo(tmp_path):
    """A repository with vectors/ at its root and the project at py/fiki-vectors."""
    vectors = tmp_path / "vectors"
    for name in MANIFEST:
        write(vectors / name)
    write(vectors / "generate.py", "print()")
    write(vectors / "stray.json", "{}")
    project = tmp_path / "py" / "fiki-vectors"
    project.mkdir(parents=True)
    return project


def test_a_wheel_from_the_repository_takes_the_manifest_and_nothing_else(repo):
    vectors = repo.parent.parent / "vectors"
    assert hatch_build.force_include(repo, "wheel", MANIFEST) == {
        str(vectors / "accepts.json"): "fiki_vectors/data/accepts.json",
        str(vectors / "keri" / "requests.json"): "fiki_vectors/data/keri/requests.json",
        str(vectors / "keys" / "openssh" / "ed25519.pub"): "fiki_vectors/data/keys/openssh/ed25519.pub",
    }


def test_an_sdist_from_the_repository_carries_the_vectors_at_its_root(repo):
    mapping = hatch_build.force_include(repo, "sdist", MANIFEST)
    assert sorted(mapping.values()) == ["vectors/" + name for name in sorted(MANIFEST)]


def test_a_wheel_from_an_sdist_takes_the_copy_the_sdist_carries(tmp_path):
    write(tmp_path / "PKG-INFO", "Metadata-Version: 2.4\n")
    for name in MANIFEST:
        write(tmp_path / "vectors" / name)
    # A repository two levels up must not be consulted when the sdist carries its own.
    assert sorted(hatch_build.force_include(tmp_path, "wheel", MANIFEST).values()) == sorted(
        "fiki_vectors/data/" + name for name in MANIFEST)


def test_the_default_manifest_is_the_packages_own():
    assert hatch_build.force_include.__defaults__ == (hatch_build.MANIFEST,)


@pytest.mark.parametrize("missing", MANIFEST)
def test_a_build_missing_any_file_is_refused_rather_than_shipped_short(repo, missing):
    (repo.parent.parent / "vectors" / missing).unlink()
    with pytest.raises(hatch_build.VectorsBuildError,
                       match=f"^e.state.missing.vectors.source.f: .* lack {re.escape(missing)}, "):
        hatch_build.force_include(repo, "wheel", MANIFEST)


def test_a_build_with_no_vectors_is_refused_rather_than_empty(tmp_path):
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.state.missing.vectors.source.f: "):
        hatch_build.force_include(tmp_path, "wheel", MANIFEST)


def test_an_sdist_without_its_vectors_is_refused(tmp_path):
    write(tmp_path / "PKG-INFO", "Metadata-Version: 2.4\n")
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.state.missing.vectors.source.f: "):
        hatch_build.force_include(tmp_path, "wheel", MANIFEST)


@pytest.mark.parametrize("where", ["file", "directory", "root"])
def test_a_symlink_on_the_way_to_any_file_is_refused_rather_than_followed(repo, tmp_path, where):
    # Following one would copy whatever it points at, from anywhere on the build host, into the
    # wheel.
    vectors = repo.parent.parent / "vectors"
    real = tmp_path / "elsewhere"
    if where == "file":
        moved = vectors / "keri" / "requests.json"
    elif where == "directory":
        moved = vectors / "keri"
    else:
        moved = vectors
    moved.rename(real)
    moved.symlink_to(real)
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.rule.vectors.symlink.f: "):
        hatch_build.force_include(repo, "wheel", MANIFEST)


def test_a_vectors_tree_beside_the_project_without_pkg_info_is_refused(repo):
    # Two candidate trees, and nothing that says which is meant: refuse rather than pick one.
    for name in MANIFEST:
        write(repo / "vectors" / name, '"planted"')
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.state.conflict.vectors.source.f: "):
        hatch_build.force_include(repo, "wheel", MANIFEST)


def test_an_sdist_shape_inside_a_repository_is_refused(repo):
    # A PKG-INFO and a vectors/ planted in a checkout must not shadow the repository's own.
    write(repo / "PKG-INFO", "Metadata-Version: 2.4\n")
    for name in MANIFEST:
        write(repo / "vectors" / name, '"planted"')
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.state.conflict.vectors.source.f: "):
        hatch_build.force_include(repo, "wheel", MANIFEST)


def test_a_pkg_info_alone_inside_a_repository_is_refused(repo):
    # Without a tree of its own it would point at a vectors/ that is not there, and report the
    # conflict as an absence.
    write(repo / "PKG-INFO", "Metadata-Version: 2.4\n")
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.state.conflict.vectors.source.f: "):
        hatch_build.force_include(repo, "wheel", MANIFEST)


def test_an_sdist_ignores_whatever_happens_to_sit_two_levels_above_it(tmp_path):
    # A frontend unpacks an sdist where it likes; a stray vectors/ above that is not a repository.
    root = tmp_path / "build" / "fiki_vectors-0.10.0"
    write(root / "PKG-INFO", "Metadata-Version: 2.4\n")
    for name in MANIFEST:
        write(root / "vectors" / name)
    (tmp_path / "vectors").symlink_to(tmp_path / "dangling")
    assert sorted(hatch_build.force_include(root, "wheel", MANIFEST)) == sorted(
        str(root / "vectors" / name) for name in MANIFEST)


def test_a_pkg_info_that_is_a_symlink_is_refused(tmp_path):
    real = write(tmp_path / "elsewhere" / "PKG-INFO", "Metadata-Version: 2.4\n")
    root = tmp_path / "sdist"
    root.mkdir()
    (root / "PKG-INFO").symlink_to(real)
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.rule.vectors.symlink.f: "):
        hatch_build.force_include(root, "wheel", MANIFEST)


def hook(root: Path, target: str) -> hatch_build.VectorsHook:
    return hatch_build.VectorsHook(str(root), {}, None, None, str(root / "dist"), target)


def test_the_hook_adds_the_vectors_to_a_build(monkeypatch, repo):
    monkeypatch.setattr(hatch_build.force_include, "__defaults__", (MANIFEST,))
    build_data = {"force_include": {"keep.txt": "keep.txt"}}
    hook(repo, "wheel").initialize("standard", build_data)
    assert build_data["force_include"]["keep.txt"] == "keep.txt"
    assert "fiki_vectors/data/accepts.json" in build_data["force_include"].values()


def test_the_hook_refuses_an_editable_install(repo):
    # An editable wheel points the import at src/, where no vectors are, so it would install a
    # package whose data is missing.
    with pytest.raises(hatch_build.VectorsBuildError,
                       match="^e.feature.unsupported.vectors.editable.f: "):
        hook(repo, "wheel").initialize("editable", {"force_include": {}})
