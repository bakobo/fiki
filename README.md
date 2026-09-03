# fiki

[![CI](https://github.com/bakobo/fiki/actions/workflows/ci.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci.yml)

Sign and verify HTTP requests with a bare Ed25519 key as the identifier. Standard [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html), no KERI dependencies.

The public half of an Ed25519 key is rendered as a non-transferable AID — a 44-character `B…` string in CESR's `Ed25519N` encoding — and that string is both the identifier and the verifying key. A verifier needs no key event log, no directory lookup, and no network call to recover it. A client registers its AID once with whoever it calls, and signs from then on. There is nothing to rotate and nothing to fetch.

fiki exists for the party that needs to prove who it is and nothing else: an ESB client, a cron job, a container that calls one API. That party should not have to install a KERI stack to say its own name. If you need key rotation, delegation, credentials, or anything anchored to a key event log, you want [heti](https://github.com/bakobo/heti) instead; fiki is deliberately the floor.

## Status

Early. The Python implementation is under construction and the wire format is not yet frozen.

## Layout

fiki is polyglot on purpose. Each language implementation is a top-level directory, and all of them are checked against the same conformance vectors:

```
vectors/    conformance vectors, shared and normative
py/         the Python implementation
```

A new port adds a directory here rather than a repository, so the vectors cannot fork and drift apart. See `this.i` for why that mattered enough to shape the layout.

## Conformance

Two oracles stand behind fiki. RFC 9421's own Appendix B vectors, which no Bakobo party authored, pin the signature base and the signing algorithm — including on the signing side, since B.1.4 publishes the Ed25519 private key and Ed25519 is deterministic. The `vectors/` set pins what the RFC cannot: the AID lens, the default covered set, and the refusal to sign a body that nothing digests.

## Building

Per-language instructions live with the implementation. For Python, see [`py/README.md`](py/README.md).

## License

Apache-2.0.
