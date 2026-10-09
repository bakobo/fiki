"""Shared by the drivers that pin how many cases each vector file holds (tick 7xbw, T8)."""

from __future__ import annotations

import pytest


@pytest.fixture
def collected(request):
    """How many cases of a parametrized test this run holds, or None when the run was narrowed.

    A driver pins each file's case count, and a file emptied or cut short fails at collection. This
    is the other half: every case collected is a case that runs, so a driver that stopped feeding
    some of them to its test would show here. A run narrowed with -k, -m or a node id holds a
    subset by design, and is not checked.
    """
    config = request.config
    narrowed = (config.option.keyword or config.option.markexpr
                or any("::" in arg for arg in config.args))

    def count(name: str) -> int | None:
        if narrowed:
            return None
        # By module too: two drivers each have a test_refusal_vectors.
        return sum(1 for item in request.session.items
                   if item.originalname == name and item.path == request.path)

    return count
