"""Pulls fiki's committed vectors into a build of fiki-vectors (``this.i`` @58dr3z98).

The vectors live once, at the repository root, and are read from there at build time rather than
copied under this project: a second copy inside the repo that exists to have one would age on its
own, and a symlink is not materialized on a Windows checkout. A build from the source tree, which
is what uv does for a git dependency, reads ``../../vectors``. An sdist carries the files at its own
``vectors/``, so a wheel built from it reads them there. The files taken are exactly those listed
in MANIFEST: every committed file except the generator scripts, which are how the vectors are made
rather than part of what they say.
"""

from __future__ import annotations

from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

NO_VECTORS = "e.state.missing.vectors.source.f"
EDITABLE = "e.feature.unsupported.vectors.editable.f"
SYMLINK = "e.rule.vectors.symlink.f"

# Exactly what the package ships, by path below vectors/: every committed file there except the
# generator scripts. A build takes these and nothing else, so a sparse or partial tree is refused
# rather than shipped short, and a stray untracked file is never swept in. A test holds this equal
# to `git ls-files vectors` without the generators, so a vector file added or removed without
# updating it fails CI rather than going missing.
MANIFEST = (
    "accepts.json",
    "aid-lens.json",
    "keri/legacy.json",
    "keri/refusals.json",
    "keri/requests.json",
    "keri/responses.json",
    "keri/rfc9421.json",
    "keys/keys.json",
    "keys/openssh/cryptography-rfc9421.key",
    "keys/openssh/ecdsa.key",
    "keys/openssh/ecdsa.pub",
    "keys/openssh/ed25519-encrypted.key",
    "keys/openssh/ed25519-encrypted.pub",
    "keys/openssh/ed25519.key",
    "keys/openssh/ed25519.pub",
    "keys/openssh/rsa.key",
    "keys/openssh/rsa.pub",
    "misuse.json",
    "refusals.json",
    "responses.json",
    "signature-base.json",
    "signs.json",
    "third_party/structured-field-tests/LICENSE.md",
    "third_party/structured-field-tests/README.md",
    "third_party/structured-field-tests/binary.json",
    "third_party/structured-field-tests/boolean.json",
    "third_party/structured-field-tests/date.json",
    "third_party/structured-field-tests/dictionary.json",
    "third_party/structured-field-tests/display-string.json",
    "third_party/structured-field-tests/examples.json",
    "third_party/structured-field-tests/item.json",
    "third_party/structured-field-tests/list.json",
    "third_party/structured-field-tests/listlist.json",
    "third_party/structured-field-tests/number.json",
    "third_party/structured-field-tests/param-dict.json",
    "third_party/structured-field-tests/param-list.json",
    "third_party/structured-field-tests/param-listlist.json",
    "third_party/structured-field-tests/serialisation-tests/number.json",
    "third_party/structured-field-tests/string.json",
    "third_party/structured-field-tests/token.json",
)


class VectorsBuildError(RuntimeError):
    """The build cannot produce a fiki-vectors that holds the vectors, so it does not produce one."""


def source(root: Path) -> Path:
    """Where this build's vectors are: inside an unpacked sdist, else the repository's."""
    if (root / "PKG-INFO").is_file():
        return root / "vectors"
    return root.parent.parent / "vectors"


def force_include(root: Path, target: str, manifest: tuple[str, ...] = MANIFEST) -> dict[str, str]:
    """Map each file in ``manifest`` to its place in the ``target`` artifact, a wheel or an sdist."""
    vectors = source(root)
    paths = [vectors.joinpath(*name.split("/")) for name in manifest]
    # The root, each file, and every directory between them; following a link would copy whatever
    # it names, from anywhere on the build host.
    walked = {vectors} | {parent for path in paths for parent in path.parents
                          if parent.is_relative_to(vectors)} | set(paths)
    links = sorted(str(path) for path in walked if path.is_symlink())
    if links:
        raise VectorsBuildError(
            f"{SYMLINK}: fiki-vectors ships only regular files, and these are symlinks:"
            f" {', '.join(links)}. Replace each with what it should be.")
    missing = [name for name, path in zip(manifest, paths) if not path.is_file()]
    if missing:
        raise VectorsBuildError(
            f"{NO_VECTORS}: The vectors at {vectors} lack {', '.join(missing)}, so fiki-vectors"
            " would build partial or empty. Build it from a full fiki checkout, where vectors/ is"
            " two directories above this project, or from an sdist that carries them.")
    prefix = "vectors" if target == "sdist" else "fiki_vectors/data"
    return {str(path): f"{prefix}/{name}" for name, path in zip(manifest, paths)}


class VectorsHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        if version == "editable":
            raise VectorsBuildError(
                f"{EDITABLE}: An editable install of fiki-vectors would import from src/, where no"
                " vectors are. Install it from a wheel, or from a git URL without -e.")
        build_data["force_include"].update(force_include(Path(self.root), self.target_name))
