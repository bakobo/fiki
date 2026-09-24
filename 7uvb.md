# Follow-ups from the KERI RFC 9421 profile (rfc9421 session, 2026-09-24; research.md §4). (1) Reword this.i @07wstqk7 and @2hwvpm42: 'the KERI flavor diverges' becomes 'the legacy KERI flavor diverges'. Once keripy's canonical mode ships, the KERI profile is plain RFC 9421 with an AID as keyid. (2) Once keripy PR-K (keri.end.httpsigning) and signify-ts's canonical mode are public, add them as CROSS-CHECK oracles for vectors/keri/. They check the vectors; they never generate them (@5gf6r08f). (3) Publishing (4qlo) becomes urgent if signify-ts or keripy ever depends on fiki rather than carrying copies of the vectors. (4) vectors/keri/*.json 'profile.where' still names an unpublished .ignored path, so update it when the profile is published.
kind: todo
tags: rfc9421
created: 2026-09-24T12:09Z

