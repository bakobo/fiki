# fiki-py's decoding of RFC 8941 byte sequences reportedly differs between Python 3.11-3.13 and 3.14 in how '=' padding is handled (reported by the C# port worker 2026-10-07, not yet reproduced by hand), and py's CI runs all four versions, so the same py release may accept a Signature header on one interpreter and refuse it on another. Reproduce, pin the intended behavior in a vector at the next vectors_format bump, and make py version-independent. The C# port follows 3.14.
kind: todo
created: 2026-10-07T17:24Z

