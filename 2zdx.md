# Host/URL canonicalization divergences: U+212A KELVIN lowercases to k before the ASCII check (all ports in URL host; go, csharp, java elsewhere); py/js/go strip TAB/CR/LF from URLs so /\nx verifies as /x; java splits host:port at the last colon and accepts Unicode schemes; rust reads https:///x as empty authority; py depends on Python patch release. (bakobo/reviews fiki/2026-10-08-input-hardening/synthesis.md 1.6-1.8)
kind: todo
created: 2026-10-08T16:49Z

- 2026-10-09T02:54Z From the format-3 sweep: fiki-go (hardening-go 0cb0c79) now refuses a non-ASCII host in an ABSOLUTE URL before lowercasing it (so U+212A KELVIN SIGN is no longer read as k), which py and the others do not yet do and no vector pins. Pin it with a refusal vector and bring the other five ports to the same rule before format 3 ships, or ports diverge in the release.
- 2026-10-09T03:01Z fiki-csharp (hardening-csharp 69ec39f) now also refuses a non-ASCII host in an absolute URL before lowercasing, as fiki-go does; py, js, rust and java do not yet. Still unpinned by any vector.
