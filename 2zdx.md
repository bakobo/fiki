# Host/URL canonicalization divergences: U+212A KELVIN lowercases to k before the ASCII check (all ports in URL host; go, csharp, java elsewhere); py/js/go strip TAB/CR/LF from URLs so /\nx verifies as /x; java splits host:port at the last colon and accepts Unicode schemes; rust reads https:///x as empty authority; py depends on Python patch release. (bakobo/reviews fiki/2026-10-08-input-hardening/synthesis.md 1.6-1.8)
kind: todo
created: 2026-10-08T16:49Z

