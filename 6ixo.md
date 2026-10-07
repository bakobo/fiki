# Cross-port sweep after the parity PRs (#5 js, #6 go, #7 csharp, #8 rust, #9 py, #10 java) merge: reviews kept finding the same input-handling holes port by port, and each port got only the findings raised so far. Run every port (py and C# included) against the checklist at .ignored/parity/cross-port-checklist.md in the main checkout (zero-padded ports, Content-Length trimming beyond SP/HTAB, malformed keyid before expected-keyid mismatch in section 9 order, inherited-member lookups on untrusted keys, byte-sequence padding, plus the rulings D-C3BH, D-QMDN, D-Q9ZT), fix what differs, and pin the cases in vectors at the next vectors_format / keri_vectors_format bump so drift is caught mechanically rather than by reviewers.
kind: todo
created: 2026-10-07T17:51Z

