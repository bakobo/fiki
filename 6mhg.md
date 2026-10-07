# Input bounds across every fiki port: Copilot on bakobo/fiki#7 (csharp/src/Bakobo.Fiki/HeaderSnapshot.cs:24) noted that header count, cumulative header bytes, Signature/Signature-Input length, dictionary members and covered components are all unbounded, against the Bakobo input-handling standard (AGENTS.md: size, then shape, then meaning; nothing crosses a boundary unbounded). No port bounds them today, fiki-py included, and the C# port only made the work linear (01c5a32). A bound is a new refusal, so it is a cross-port decision: pick the limits and the error kind once, add vectors at the next vectors_format bump, and implement in all six ports.
kind: todo
created: 2026-10-07T18:48Z

