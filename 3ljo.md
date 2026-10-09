# KERI key-resolution refusals are decided by each port's test harness, not the library (review V-S6, bakobo/reviews fiki/2026-10-08-input-hardening/vector-adversary.md): each harness carries its own wellFormedAid and a resolver that throws the expected error itself, and py's KERI run imports the generator's verifier. Move the AID-shape checks into each library's public API (or a shared resolver contract) so keyid-not-an-aid, padding-bit-alias-of-a-b-keyid and the unsupported-signer cases test fiki, and add refusal cases to aid-lens.json that harnesses pass straight to verifyingKey.
kind: todo
created: 2026-10-09T04:12Z

