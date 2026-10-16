"""The build hook that pulls vectors/ into fiki-vectors (``this.i`` @58dr3z98).

These run the hook's logic against small trees laid out the two ways a build meets it: the
repository, where the vectors are two levels up, and an unpacked sdist, which carries its own copy.
test_distribution.py checks what real builds produce.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import hatch_build


def write(path: Path, text: str = "{}") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def repo(tmp_path):
    """A repository with vectors/ at its root and the project at py/fiki-vectors."""
    vectors = tmp_path / "vectors"
    write(vectors / "accepts.json")
    write(vectors / "generate.py", "print()")
    write(vectors / "__pycache__" / "generate.cpython-314.pyc", "")
    write(vectors / "keri" / "requests.json")
    write(vectors / "keys" / "keys.json")
    write(vectors / "keri" / "generate.py", "print()")
    write(vectors / "keys" / "openssh" / "ed25519.pub", "ssh-ed25519 AAAA")
    write(vectors / "third_party" / "structured-field-tests" / "LICENSE.md", "BSD")
    project = tmp_path / "py" / "fiki-vectors"
    project.mkdir(parents=True)
    return project


def test_a_wheel_from_the_repository_takes_every_file_but_the_generators(repo):
    vectors = repo.parent.parent / "vectors"
    assert hatch_build.force_include(repo, "wheel") == {
        str(vectors / "accepts.json"): "fiki_vectors/data/accepts.json",
        str(vectors / "keri" / "requests.json"): "fiki_vectors/data/keri/requests.json",
        str(vectors / "keys" / "keys.json"): "fiki_vectors/data/keys/keys.json",
        str(vectors / "keys" / "openssh" / "ed25519.pub"): "fiki_vectors/data/keys/openssh/ed25519.pub",
        str(vectors / "third_party" / "structured-field-tests" / "LICENSE.md"):
            "fiki_vectors/data/third_party/structured-field-tests/LICENSE.md",
    }


def test_an_sdist_from_the_repository_carries_the_vectors_at_its_root(repo):
    mapping = hatch_build.force_include(repo, "sdist")
    assert sorted(mapping.values()) == [
        "vectors/accepts.json",
        "vectors/keri/requests.json",
        "vectors/keys/keys.json",
        "vectors/keys/openssh/ed25519.pub",
        "vectors/third_party/structured-field-tests/LICENSE.md",
    ]


def test_a_wheel_from_an_sdist_takes_the_copy_the_sdist_carries(tmp_path):
    write(tmp_path / "PKG-INFO", "Metadata-Version: 2.4\n")
    for name in hatch_build.REQUIRED:
        write(tmp_path / "vectors" / name)
    # A repository two levels up must not be consulted when the sdist carries its own.
    assert sorted(hatch_build.force_include(tmp_path, "wheel").values()) == sorted(
        "fiki_vectors/data/" + name for name in hatch_build.REQUIRED)


@pytest.mark.parametrize("missing", hatch_build.REQUIRED)
def test_a_build_missing_any_set_of_vectors_is_refused(repo, missing):
    # One file stands for each set, so a partial tree cannot ship formats it has no data for.
    (repo.parent.parent / "vectors" / missing).unlink()
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.state.missing.vectors.source.f: "):
        hatch_build.force_include(repo, "wheel")


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_a_symlink_in_the_vectors_is_refused_rather_than_followed(repo, tmp_path, kind):
    # Following one would copy whatever it points at, from anywhere on the build host, into the
    # wheel.
    outside = write(tmp_path / "outside" / "secret.txt", "secret")
    target = outside if kind == "file" else outside.parent
    (repo.parent.parent / "vectors" / "keri" / "link").symlink_to(target)
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.rule.vectors.symlink.f: "):
        hatch_build.force_include(repo, "wheel")


def test_a_vectors_directory_that_is_itself_a_symlink_is_refused(repo, tmp_path):
    real = tmp_path / "py" / "real-vectors"
    (tmp_path / "vectors").rename(real)
    (tmp_path / "vectors").symlink_to(real)
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.rule.vectors.symlink.f: "):
        hatch_build.force_include(repo, "wheel")


def test_a_build_with_no_vectors_is_refused_rather_than_empty(tmp_path):
    with pytest.raises(hatch_build.VectorsBuildError) as raised:
        hatch_build.force_include(tmp_path, "wheel")
    assert str(raised.value).startswith("e.state.missing.vectors.source.f: ")


def test_an_sdist_without_its_vectors_is_refused(tmp_path):
    write(tmp_path / "PKG-INFO", "Metadata-Version: 2.4\n")
    with pytest.raises(hatch_build.VectorsBuildError, match="^e.state.missing.vectors.source.f: "):
        hatch_build.force_include(tmp_path, "wheel")


def hook(root: Path, target: str) -> hatch_build.VectorsHook:
    return hatch_build.VectorsHook(str(root), {}, None, None, str(root / "dist"), target)


def test_the_hook_adds_the_vectors_to_a_build(repo):
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
