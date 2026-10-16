"""Pulls fiki's committed vectors into a build of fiki-vectors (``this.i`` @58dr3z98).

The vectors live once, at the repository root, and are read from there at build time rather than
copied under this project: a second copy inside the repo that exists to have one would age on its
own, and a symlink is not materialized on a Windows checkout. A build from the source tree, which
is what uv does for a git dependency, reads ``../../vectors``. An sdist carries the files at its own
``vectors/``, so a wheel built from it reads them there. Every file is taken except the generator
scripts and their bytecode, which are how the vectors are made rather than part of what they say.
"""

from __future__ import annotations

from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

NO_VECTORS = "e.state.missing.vectors.source.f"
EDITABLE = "e.feature.unsupported.vectors.editable.f"
SYMLINK = "e.rule.vectors.symlink.f"

# One file standing for each set the package exports a format for, plus the corpus license that
# must travel with the corpus. A tree missing any of them is partial, and a partial package would
# still export the formats of the sets it lacks.
REQUIRED = (
    "accepts.json",
    "keri/requests.json",
    "keys/keys.json",
    "third_party/structured-field-tests/LICENSE.md",
)


class VectorsBuildError(RuntimeError):
    """The build cannot produce a fiki-vectors that holds the vectors, so it does not produce one."""


def source(root: Path) -> Path:
    """Where this build's vectors are: inside an unpacked sdist, else the repository's."""
    if (root / "PKG-INFO").is_file():
        return root / "vectors"
    return root.parent.parent / "vectors"


def force_include(root: Path, target: str) -> dict[str, str]:
    """Map each vector file to its place in the ``target`` artifact, a wheel or an sdist."""
    vectors = source(root)
    missing = [name for name in REQUIRED if not (vectors / name).is_file()]
    if missing:
        raise VectorsBuildError(
            f"{NO_VECTORS}: The vectors at {vectors} lack {', '.join(missing)}, so fiki-vectors"
            " would build partial or empty. Build it from a fiki checkout, where vectors/ is two"
            " directories above this project, or from an sdist that carries them.")
    found = sorted(vectors.rglob("*"))
    links = [path for path in [vectors, *found] if path.is_symlink()]
    if links:
        # Following a link would copy whatever it names, from anywhere on the build host.
        raise VectorsBuildError(
            f"{SYMLINK}: fiki-vectors ships only regular files, and these are symlinks:"
            f" {', '.join(str(p) for p in links)}. Replace each with what it should be.")
    prefix = "vectors" if target == "sdist" else "fiki_vectors/data"
    return {
        str(path): f"{prefix}/{path.relative_to(vectors).as_posix()}"
        for path in found
        if path.is_file() and path.suffix not in (".py", ".pyc")
        and "__pycache__" not in path.relative_to(vectors).parts
    }


class VectorsHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        if version == "editable":
            raise VectorsBuildError(
                f"{EDITABLE}: An editable install of fiki-vectors would import from src/, where no"
                " vectors are. Install it from a wheel, or from a git URL without -e.")
        build_data["force_include"].update(force_include(Path(self.root), self.target_name))
