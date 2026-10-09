# Vector gaps a port could ship through: 10 more forgeable small-order/non-canonical key encodings (V-C1), expected_aid (V-C2), response from unexpected B key (V-C3), signer pinned by signs.json byte for byte incl. default covered set and @query (V-C4), absent created, far expires vs max_age, keyid aliases, param order, lowercase headers, KERI resolution decided by harness not library (V-S1..S6). JSON drafts in vector-adversary.md. (bakobo/reviews fiki/2026-10-08-input-hardening/synthesis.md section 3)
kind: todo
created: 2026-10-08T16:49Z

- 2026-10-09T16:21Z Resolved in #18 (d7a4aae) except two parts moved to their own ticks: V-S6 (KERI resolution decided by harnesses) is ~3ljo and V-M7 (profile code name) is ~44hj. Everything else -- small-order forgeries, expected_aid, B-key response, signs.json, absent created, far expires, keyid aliases, param order, lowercase names, S+L, duplicates, created after 2038, tag, http/80 -- is pinned at vectors_format 3 / keri_vectors_format 5.
