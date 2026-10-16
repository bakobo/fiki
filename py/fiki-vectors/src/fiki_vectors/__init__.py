"""fiki's committed conformance vectors, installed as a test dependency (``this.i`` @58dr3z98).

A consumer that wraps fiki and runs fiki's vectors against its own wrapper installs this package at
the same git commit it pins fiki at, so the vectors it runs are the ones that fiki commit satisfies
rather than a vendored copy aging on its own. The tree under :func:`files` is the repository's
``vectors/`` byte for byte, without the generator scripts: the shared vectors at its root, the KERI
profile's under ``keri/``, the key spellings under ``keys/``, and the vendored httpwg
structured-field corpus, with its license, under ``third_party/``.
"""

from __future__ import annotations

import json
import re
from importlib.resources import files as _files
from importlib.resources.abc import Traversable
from typing import Any

# The formats these files declare in their headers, and the ones a port must export to run them
# (``this.i`` @4fhrre0m). A consumer asserts these against the port it is testing, as each port's
# own driver does, so newer vectors fail loudly rather than passing a subset.
VECTORS_FORMAT = 4
KERI_VECTORS_FORMAT = 6
KEY_VECTORS_FORMAT = 1

BAD_NAME = "e.input.format.vectors.name.f"

# One path segment as the vector files are named. Anything else -- a drive letter, a backslash, a NUL,
# whitespace -- is refused rather than handed to a filesystem that might read it as a path.
_SEGMENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*")

__all__ = ["VECTORS_FORMAT", "KERI_VECTORS_FORMAT", "KEY_VECTORS_FORMAT", "files", "load"]


def files() -> Traversable:
    """The root of the vectors tree, laid out as ``vectors/`` is in the repository."""
    return _files(__name__) / "data"


def load(name: str) -> Any:
    """Parse one vector file, named by its path below ``vectors/``: ``"keri/requests.json"``."""
    # The unbound str.split over str.__str__, so a str subclass's own split cannot answer validation
    # and lookup differently.
    parts = str.split(str.__str__(name), "/") if isinstance(name, str) else [""]
    if not all(_SEGMENT.fullmatch(part) for part in parts):
        raise ValueError(
            f"{BAD_NAME}: {name!r} is not a path below vectors/. Name a file with forward slashes"
            " between segments of letters, digits, '.', '_' and '-' that do not start with '.',"
            " such as 'keri/requests.json'.")
    # Each segment is matched exactly against the entries the package holds, never handed to the
    # filesystem to resolve, so no name a platform reads specially (a device, a trailing dot, a
    # case-folded spelling) reaches anything but the file of that exact name.
    node = files()
    for part in parts:
        node = next((child for child in node.iterdir() if child.name == part), None) \
            if node.is_dir() else None
        if node is None:
            break
    if node is None or not node.is_file():
        raise FileNotFoundError(f"There is no file {name!r} below vectors/ in fiki-vectors.")
    return json.loads(node.read_bytes())
