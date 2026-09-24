# keri_vectors_format 3 candidates from the round-2 review of bakobo/fiki#4, which could not be vectors under format 2 because adding a case is a format change (@4fhrre0m): (1) a malformed-key refusal for a padding-bit alias of a B keyid (flip bit 4 of the second character; see py/tests/test_keys.py padding_bit_alias), which keys_rule now forbids but no case pins, so an implementation accepting aliases still passes; (2) a digest-mismatch response case where the response covers "content-digest";req and the request body handed to the verifier does not match the request's Content-Digest (fiki commit eb0a48c). Add both at the next bump, together with any other format-3 changes.
kind: todo
tags: keri
created: 2026-09-24T17:22Z

