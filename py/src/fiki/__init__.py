"""fiki — sign and verify HTTP requests with a bare Ed25519 key as the identifier.

Standard RFC 9421, with one lens: an Ed25519 public key is rendered as a non-transferable AID
(CESR ``Ed25519N``, a 44-character ``B…`` string), so the identifier is the verifying key and a
verifier resolves nothing. Two dependencies, ``cryptography`` and ``http_sfv``, and never keripy.

See ``this.i`` @07wstqk7 for why this is a library of its own rather than a corner of heti.
"""

from __future__ import annotations

from . import errors
from .base import DEFAULT_COVERED, DERIVED, signature_base
from .errors import FikiError
from .keys import Key, to_aid, verifying_key
from .messages import Verdict, sign_request, verify_request

# The conformance contract this port satisfies (``this.i`` @4fhrre0m). Two artifacts interoperate
# when their declared vectors format matches, whatever their own version numbers say — so this is
# the number to compare, not the release. Monotonic, because a conformance contract has no
# meaningful minor: an implementation either satisfies the vectors or it does not.
VECTORS_FORMAT = 1

__all__ = [
    "VECTORS_FORMAT",
    "DEFAULT_COVERED",
    "DERIVED",
    "FikiError",
    "Key",
    "Verdict",
    "errors",
    "sign_request",
    "signature_base",
    "to_aid",
    "verify_request",
    "verifying_key",
]
