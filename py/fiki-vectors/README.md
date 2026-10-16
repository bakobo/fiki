# fiki-vectors

fiki's committed conformance vectors as a Python distribution of their own, for a project that wraps fiki and wants to run fiki's vectors against its wrapper without vendoring a copy of them (`this.i` @58dr3z98). The fiki runtime wheel does not carry the vectors; this package carries nothing else.

The package holds every committed file under the repository's [`vectors/`](../../vectors) except the generator scripts, byte for byte: the shared vectors at the root, the KERI profile's under `keri/`, the key spellings under `keys/`, and the vendored httpwg structured-field corpus under `third_party/`, which keeps its BSD-3-Clause `LICENSE.md` beside it.

## Installing it at the commit you pin fiki at

The vectors are only meaningful against the fiki they were committed with, so install both from the same commit. With uv, in the consumer's `pyproject.toml`:

```toml
[project]
dependencies = ["fiki"]

[dependency-groups]
dev = ["fiki-vectors"]

[tool.uv.sources]
fiki = { git = "https://github.com/bakobo/fiki", rev = "<commit>", subdirectory = "py" }
fiki-vectors = { git = "https://github.com/bakobo/fiki", rev = "<commit>", subdirectory = "py/fiki-vectors" }
```

With pip, `pip install "fiki-vectors @ git+https://github.com/bakobo/fiki@<commit>#subdirectory=py/fiki-vectors"`. The package is not published to PyPI.

An editable install is refused at build time, because an editable package would import from `src/`, where no vectors are.

## Reading the vectors

```python
import fiki
import fiki_vectors

assert fiki_vectors.VECTORS_FORMAT == fiki.VECTORS_FORMAT
assert fiki_vectors.KERI_VECTORS_FORMAT == fiki.KERI_VECTORS_FORMAT

accepts = fiki_vectors.load("accepts.json")
requests = fiki_vectors.load("keri/requests.json")

root = fiki_vectors.files()   # an importlib.resources Traversable laid out as vectors/ is
license = (root / "third_party" / "structured-field-tests" / "LICENSE.md").read_text()
```

`VECTORS_FORMAT`, `KERI_VECTORS_FORMAT` and `KEY_VECTORS_FORMAT` are the formats the files declare in their headers. Assert them against the port you are testing, as each fiki port's own driver does, so that vectors from a newer format fail loudly instead of passing a subset.

## Developing it

```sh
cd py/fiki-vectors
uv sync
uv run pytest
```

The suite builds the wheel twice, once from the source tree, which is what uv does for a git dependency, and once from an sdist, installs each, and checks that the installed files are the committed vectors byte for byte. The project is never installed into its own environment, so the tests import only what a real build produced. The suite enforces 100% branch coverage.
