"""What a consumer installs is fiki's vectors, byte for byte (``this.i`` @58dr3z98).

Each test runs against a wheel this suite built and installed, by both routes a wheel is made: from
the source tree, which is what uv does for a git dependency, and from an sdist, which is what any
installer does with a published release. Nothing here imports fiki_vectors from src/.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

import fiki

PROJECT = Path(__file__).resolve().parents[1]
REPO = PROJECT.parents[1]
VECTORS = REPO / "vectors"


def run(*args: str | Path) -> None:
    done = subprocess.run([str(a) for a in args], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def expected() -> dict[str, bytes]:
    """Every committed file under vectors/ except the generators, by path below vectors/."""
    listed = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z", "vectors"],
                            check=True, capture_output=True).stdout.decode().split("\0")
    return {
        name.removeprefix("vectors/"): (REPO / name).read_bytes()
        for name in listed if name and not name.endswith(".py")
    }


def test_the_build_manifest_is_the_committed_vectors_without_the_generators():
    import hatch_build
    assert sorted(hatch_build.MANIFEST) == sorted(expected())


def build(route: str, out: Path) -> Path:
    if route == "source":
        run("uv", "build", "--wheel", "--out-dir", out / "wheel", PROJECT)
    else:
        run("uv", "build", "--sdist", "--out-dir", out / "sdist", PROJECT)
        (sdist,) = (out / "sdist").glob("*.tar.gz")
        run("uv", "build", "--wheel", "--out-dir", out / "wheel", sdist)
    (wheel,) = (out / "wheel").glob("*.whl")
    return wheel


@pytest.fixture(scope="session", params=["source", "sdist"])
def wheel(request, tmp_path_factory) -> Path:
    return build(request.param, tmp_path_factory.mktemp(request.param))


@pytest.fixture(scope="session")
def installed(wheel, tmp_path_factory):
    """fiki_vectors imported from an install of ``wheel``, and from nowhere else."""
    target = tmp_path_factory.mktemp("site")
    run("uv", "pip", "install", "--no-deps", "--python", sys.executable, "--target", target, wheel)
    saved_path = list(sys.path)
    saved = {k: sys.modules.pop(k) for k in list(sys.modules) if k.split(".")[0] == "fiki_vectors"}
    sys.path.insert(0, str(target))
    importlib.invalidate_caches()
    module = importlib.import_module("fiki_vectors")
    assert Path(module.__file__).is_relative_to(target)
    yield module
    sys.path[:] = saved_path
    for name in [k for k in sys.modules if k.split(".")[0] == "fiki_vectors"]:
        del sys.modules[name]
    sys.modules.update(saved)


def walk(node, prefix: str = "") -> dict[str, bytes]:
    found = {}
    for child in node.iterdir():
        name = prefix + child.name
        if child.is_dir():
            found.update(walk(child, name + "/"))
        else:
            found[name] = child.read_bytes()
    return found


def test_the_installed_files_are_the_committed_vectors_byte_for_byte(installed):
    shipped = walk(installed.files())
    want = expected()
    assert sorted(shipped) == sorted(want)
    assert all(shipped[name] == want[name] for name in want)


def test_the_set_compared_holds_each_kind_of_file_the_package_promises():
    # Guards the comparison above against passing on a filter that dropped a whole class of file.
    names = expected()
    assert "accepts.json" in names
    assert "keri/requests.json" in names
    assert "keys/keys.json" in names
    assert "keys/openssh/ed25519.pub" in names
    assert "third_party/structured-field-tests/LICENSE.md" in names
    assert not any(name.endswith(".py") for name in names)


def test_the_wheel_carries_the_package_and_its_metadata_and_nothing_else(wheel):
    with zipfile.ZipFile(wheel) as archive:
        tops = {name.split("/")[0] for name in archive.namelist()}
    assert tops == {"fiki_vectors", "fiki_vectors-" + version() + ".dist-info"}


def version() -> str:
    return tomllib.loads((PROJECT / "pyproject.toml").read_text())["project"]["version"]


def test_the_version_moves_with_fiki_py():
    fiki_version = tomllib.loads((REPO / "py" / "pyproject.toml").read_text())["project"]["version"]
    assert version() == fiki_version


@pytest.mark.parametrize(("constant", "key", "pattern"), [
    ("VECTORS_FORMAT", "vectors_format", "*.json"),
    ("KERI_VECTORS_FORMAT", "keri_vectors_format", "keri/*.json"),
    ("KEY_VECTORS_FORMAT", "key_vectors_format", "keys/*.json"),
])
def test_each_exported_format_is_the_one_its_files_declare_and_fiki_satisfies(
        installed, constant, key, pattern):
    declared = getattr(installed, constant)
    files = sorted(VECTORS.glob(pattern))
    assert files
    for path in files:
        assert installed.load(path.relative_to(VECTORS).as_posix())[key] == declared, path
    assert declared == getattr(fiki, constant)
    assert constant in installed.__all__


def test_load_reads_a_vector_file_by_its_path_below_vectors(installed):
    assert installed.load("keri/requests.json") == json.loads(
        (VECTORS / "keri" / "requests.json").read_bytes())


@pytest.mark.parametrize("name", [
    "", ".", "..", "../py/pyproject.toml", "keri/../accepts.json", "/etc/passwd", "keri//x.json",
    "keri/", "keri\\requests.json", "accepts.json\0", None, 7, b"accepts.json",
    "D:secret.json", "keri/C:x.json", "c:/windows", "accepts.json ", "keri/requests.json\n",
])
def test_load_refuses_a_name_that_is_not_a_plain_path_below_vectors(installed, name):
    with pytest.raises(ValueError, match="^e.input.format.vectors.name.f: "):
        installed.load(name)


class Shifty(str):
    """A str whose split() answers differently each time it is asked."""

    calls = 0

    def split(self, *args, **kwargs):
        Shifty.calls += 1
        return iter(["accepts.json"] if Shifty.calls == 1 else ["..", "..", "py", "pyproject.toml"])


def test_load_reads_a_str_subclass_by_its_value_not_by_its_split(installed):
    Shifty.calls = 0
    assert installed.load(Shifty("accepts.json")) == installed.load("accepts.json")
    Shifty.calls = 0
    with pytest.raises(ValueError, match="^e.input.format.vectors.name.f: "):
        installed.load(Shifty("../py/pyproject.toml"))


@pytest.mark.parametrize("name", [
    "no-such-file.json", "keri/no-such-file.json", "nope/requests.json",
    # Names Windows resolves to a device or to another file; matched exactly, they are no file.
    "nul", "con.json", "keri/aux", "accepts.json.", "ACCEPTS.JSON",
    # A file is not a directory, and naming one as such is a missing file, not a crash.
    "accepts.json/x", "keri",
])
def test_load_of_a_file_that_is_not_there_says_so(installed, name):
    with pytest.raises(FileNotFoundError):
        installed.load(name)


def test_fikis_own_artifacts_carry_no_vectors(tmp_path):
    # The runtime wheel is what a cron job installs, and its footprint is a requirement
    # (@07wstqk7); conformance data belongs in this package only.
    run("uv", "build", "--out-dir", tmp_path, REPO / "py")
    (sdist,) = tmp_path.glob("fiki-*.tar.gz")
    (runtime,) = tmp_path.glob("fiki-*.whl")
    with tarfile.open(sdist) as archive:
        names = archive.getnames()
    with zipfile.ZipFile(runtime) as archive:
        names += archive.namelist()
    assert names
    assert not [n for n in names if "fiki-vectors" in n or "fiki_vectors" in n or n.endswith(".json")]
