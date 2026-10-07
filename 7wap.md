# fiki-py's verifying_key raises a bare ValueError rather than MalformedKey for a 44-character B-prefixed AID containing non-ASCII characters (found by the C# port worker 2026-10-07; the C# port mirrors it with ArgumentException). A malformed keyid should be MalformedKey everywhere. Fix py with a red test first, then the C# port.
kind: todo
created: 2026-10-07T17:24Z

