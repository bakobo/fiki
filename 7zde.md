# Supplying authorities= to a verifier does not by itself bind the signature to the host: the authority check runs only when the signature covers @authority, and the profile's minimum (REQUEST_MINIMUM) omits @authority, so a GET signed for attacker.example with the minimum verifies for victim.example even with authorities={'victim.example'} (hostile review of #11, reproduced against fiki-py; likely every port). Profile section 3 ties the comparison to a verifier that REQUIRES @authority, so this is consistent with the profile but a fail-open reading of the caller's intent. Proposed for 0.7.0 / sweep 6ixo: when authorities is supplied, @authority must be covered (InsufficientCoverage otherwise), in every port, with a vector. Until then, a verifier that wants host binding adds @authority to its minimum.
kind: todo
created: 2026-10-07T19:55Z
closed: 2026-10-07T21:48Z

