# vectors/keys/keys.json has no accept case whose private section is already aligned, so its padding is empty, which is what ssh-keygen writes for a comment of 5, 13, 21, ... characters (measured on OpenSSH 10.2, 2026-10-12, answering the hostile pass on #26, which wrongly claimed OpenSSH pads an aligned section with eight bytes). fiki-py and fiki-js accept such a key; go, rust, java and csharp are believed to but no vector proves it. Add an accept case (a comment of 5 characters) at the next key_vectors_format bump.
kind: todo
tags: vectors
created: 2026-10-12T03:23Z

