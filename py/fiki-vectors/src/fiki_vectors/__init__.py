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

__all__ = ["VECTORS_FORMAT", "KERI_VECTORS_FORMAT", "KEY_VECTORS_FORMAT", "files", "load"]


def files() -> Traversable:
    """The root of the vectors tree, laid out as ``vectors/`` is in the repository."""
    return _files(__name__) / "data"


def load(name: str) -> Any:
    """Parse one vector file, named by its path below ``vectors/``: ``"keri/requests.json"``."""
    parts = name.split("/") if isinstance(name, str) else [""]
    if any(part in ("", ".", "..") or "\\" in part or "\0" in part for part in parts):
        raise ValueError(
            f"{BAD_NAME}: {name!r} is not a path below vectors/. Name a file with forward slashes"
            " and no empty, '.' or '..' segments, such as 'keri/requests.json'.")
    return json.loads(files().joinpath(*parts).read_bytes())
