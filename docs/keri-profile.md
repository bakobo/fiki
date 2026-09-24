# KERI profile of RFC 9421 HTTP Message Signatures

Version 1, 2026-09-24.

This document specifies how keripy, KERIA and signify-ts sign and verify HTTP requests and responses once WebOfTrust/keripy#1669 lands. The key words MUST, SHOULD and MAY are used in the RFC 2119 sense.

## 1. Why, and scope

Signify's requests to KERIA and KERIA's responses are signed today, but the signature covers neither the query string nor the body of a request, nor the status or body of a response. KERIA routes on query parameters (`type` for rotation versus interaction, `filter_field`, `sender`, `pre`) and acts on bodies, so an intermediary that can alter them does so undetected. Closing that gap is the purpose of this profile, and it is what #1669 and keria#467 ask for.

RFC 9421 already defines how to cover a query (`@query`) and a body (`Content-Digest`, RFC 9530), so this profile uses it as written, rather than extending the deployed scheme with digests of its own. Conformance comes nearly for free: covering any new component forces every verifier to upgrade anyway, and the cost of making the upgraded base the RFC's is small. The resulting interoperability serves the verifiers that are not KERIA, such as a third party receiving a request from `createSignedRequest`, or a generic RFC 9421 verifier of a non-transferable signer. It is not an argument that KERIA needs clients other than Signify.

ESSR, KERIA's encrypted mode, already covers the whole request and response, and it ships in KERIA and signify-ts. It does not make this profile redundant, for three reasons. It is not the default, and the signed-header mode that is the default is the one with the gap. It exists only between a Signify client and its own agent, so it cannot reach the third parties `createSignedRequest` signs for. And nothing outside KERI can verify it. This profile leaves ESSR untouched.

The profile has two modes. Canonical mode is this profile. Legacy mode is the scheme deployed today, which verifiers keep accepting (§8). The implementations are keripy (library), KERIA (server), signify-ts (client) and, on the legacy side only, SignifyPy, which pins keri 1.2.x and calls keripy's legacy `ending` functions; those functions stay untouched on every keripy line, including the 1.2.x and 1.3.x backports.

Out of scope for this version: replay detection by nonce tracking, multi-key and threshold signers, algorithms other than Ed25519, ESSR, and deprecating legacy mode.

## 2. Signature base

The signature base is exactly RFC 9421 §2.5. Each covered component contributes one line, `<component-identifier>: <component-value>`, where the identifier is serialized as an RFC 8941 String with its parameters (`"@method"`, `"content-digest"`, `"@path";req`). Lines are joined by a single LF with no trailing LF. The final line is `"@signature-params": ` followed by the RFC 8941 serialization of the Inner List of covered component identifiers with the signature parameters (§4).

On verification the `@signature-params` line is serialized from the parsed `Signature-Input` member, keeping the component and parameter order in which they arrived. A verifier MUST NOT re-emit parameters in its own preferred order.

Component values follow RFC 9421 §2.1 and §2.2:

- HTTP fields: a field name in a component identifier parsed from the wire MUST already be lowercase and is refused otherwise; a signer's local caller may pass plain names and have them lowercased as a convenience. Values are the field's lines with leading and trailing whitespace removed and obsolete line folding replaced by a single space, and multiple field lines are joined with `", "` in the order received. A covered field that is absent from the message MUST cause signing and verification to fail. It is never skipped.
- `@method`: the method as sent, with no case transformation (RFC 9421 §2.2.1). Browsers' `fetch()` uppercases standard methods, so a signer must be given the method exactly as it will go on the wire.
- `@authority`: the target authority, lowercased, with the default port for the scheme removed. Taken from the target URI, or from `Host` when the server has only that; see §3 on what a verifier must compare it with.
- `@path`: the absolute path of the target URI as sent, in its encoded form, percent-encoding included and unnormalized; an empty path is `/`. A verifier that cannot see the raw path must not substitute a decoded or re-encoded one and call it conformant; see O1.
- `@query`: the query of the target URI as sent, including the leading `?`. When the target has no query the value is `?` alone.
- `@status`: the response status code as three digits. Valid only in responses.

The only component parameter supported is `req` (RFC 9421 §2.4), and only in responses. Any other component parameter (`sf`, `key`, `bs`, `name`, `tr`) and any derived component not listed above (`@target-uri`, `@scheme`, `@request-target`, `@query-param`) MUST be refused by signers and verifiers alike with an error that names the component. Silently dropping an unsupported component, as the legacy base builder does, is forbidden.

A component's parameters keep the order in which they were given. The same component appearing twice in one covered list is refused, and the duplicate check ignores parameter order.

## 3. Covered components

A signer covers at least the minimum set below, and refuses to sign a covered list that falls short of it. A verifier MUST enforce the minimum set from its own policy, and MUST NOT accept a signature merely because the components listed on the wire were all verified; a signature over too little is refused even if it is valid. A policy MUST NOT be configurable below the minimum set of this section, and `max_age` and `skew` must be positive. Covering more than the minimum is allowed.

Request, minimum set:

- `@method`, `@path`, `@query`.
- `content-digest` whenever the request has a body (below). Signing a request with a non-empty body without covering `content-digest` is an error.

A request has a body, for the purpose of the minimum set, when it carries a `Content-Length` greater than zero or any `Transfer-Encoding`. A verifier that checks coverage when the headers arrive applies that test. When it later reads the body, it MUST also refuse a non-empty body that arrived without a covered `content-digest`, whatever the headers said. A body is never handed to application code uncovered.

Request, default signer set: the minimum set plus `@authority`. KERIA's default policy does not require `@authority`, because its `keyid` already names a controller hosted by that agent and a proxy may rewrite `Host`. A deployment MAY add `@authority` to its minimum set. A signer signing for a third party (`createSignedRequest`) MUST cover `@authority`, and a verifier that is not the signer's own agent SHOULD require it. A verifier that requires `@authority` MUST compare the covered value with the set of authorities it serves, configured, not merely rebuild it from the `Host` it received. Otherwise a request signed for one service replays to another.

Response, minimum set:

- `@status`.
- `content-digest` whenever the response has a non-empty body.
- The request's own covered components that fall in the request minimum set, each marked `req`: `"@method";req`, `"@path";req`, `"@query";req`, and `"content-digest";req` when the request had a body.

For the response minimum, "the request had a body" means the request's content was non-empty. Its headers don't count here: by the time a response is signed or verified, both sides hold the whole request, so the header-time test of the request rules is no longer needed.

The `req` components bind the response to what was asked. A response does not cover the request's `Signature` or `Signature-Input` fields, which RFC 9421 §2.4 marks NOT RECOMMENDED because signatures of signatures do not give transitive coverage (§7.3.7).

Known limitation: the binding is to what was asked, not to the individual request. Two identical GETs produce identical `req` values, so an intermediary can answer the second with a recorded response to the first, provided the recording is still inside the freshness window of §6. The consequence is a stale read, such as key state from before a rotation; any KEL event built from it fails when submitted. This is accepted.

## 4. Signature-Input and signature parameters

`Signature-Input` is an RFC 8941 Dictionary. In canonical mode it carries exactly one member. The label is arbitrary; Signify and KERIA SHOULD emit `signify`, and a verifier MUST accept any single label and MUST refuse more than one. A verifier MUST refuse a `Signature` whose labels do not match `Signature-Input`'s.

Parameters, emitted by a signer in the order `created`, `expires`, `nonce`, `alg`, `keyid`, `tag`:

- `created`, Integer, REQUIRED. Seconds since the Unix epoch.
- `expires`, Integer, optional. When present it MUST be enforced (§6).
- `nonce`, String, optional on the wire. Signify and KERIA SHOULD emit a fresh random nonce of at least 128 bits on every message, so that a replay cache can be added later without changing any signer; a verifier in this version never requires or checks it.
- `alg`, String, optional on the wire as in RFC 9421. Signers SHOULD emit it. When present it MUST be `ed25519` in this version and MUST agree with the resolved key, or the message is refused; when absent the algorithm is the one the resolved key's CESR code implies (§7, R2).
- `keyid`, String, REQUIRED. The signer's AID in qb64 (§7, R1).
- `tag`, String, optional. Passed through and covered; never required or checked.

Any other parameter is refused. `context`, which the legacy code parses, is not a canonical parameter.

## 5. Signature and Content-Digest

`Signature` is an RFC 8941 Dictionary whose member for the label is a Byte Sequence holding the raw 64-byte Ed25519 signature: `signify=:<base64>:`. The CESR `indexed`/`signer`/`ordinal`/`digest`/`kind` metadata of the legacy header is not carried; it was never covered by the signature, so dropping it loses no protection.

`Content-Digest` follows RFC 9530. A signer emits `sha-256=:<base64>:` computed over the message content as sent. A verifier recognizes `sha-256` and `sha-512`, ignores other algorithms (RFC 9530 §2), and requires every recognized one to match. A header with no recognized member is an error, not a pass. The digest MUST be recomputed over the received content before the message is accepted. Covering `Content-Digest` without recomputing it protects nothing.

The two checks may run at different times, but an implementation MUST NOT let the second be forgotten: a header-time verification whose body check is still owed must say so in what it returns, rather than look like a completed verification. A verifier SHOULD verify the signature over the base as soon as the headers arrive, which rejects forgeries without reading the body, and compare the digest once the body has been read. Both MUST pass before the request reaches application code. A covered `content-digest` on a message with no content is checked against the digest of the empty string.

A streamed response body is buffered so it can be digested and covered. Signing a streamed response without `content-digest` would leave its body uncovered, which is the gap #1669 exists to close. KERIA's only streamed response, GET `/contacts/{prefix}/img`, serves an upload capped at 1 MB.

## 6. Freshness

In canonical mode a verifier MUST refuse a message whose `created` is earlier than `now - max_age - skew` or later than `now + skew`, and one whose `expires` is present and earlier than `now - skew`. Defaults are `max_age = 300` and `skew = 60` seconds, both configurable; the verifier reads its clock through an injectable source so tests can pin it. The checks apply to requests verified by a server and to responses verified by a client. The arithmetic matches fiki's.

Legacy mode performs no freshness check, as today, so no deployed client breaks. Replay within the window is not detected; endpoints that must be safe against it should be idempotent, as iFergal proposed in keria#287.

## 7. Where the profile is KERI-flavoured

Each of these uses a field RFC 9421 leaves to the application. None is a syntactic divergence.

- R1, `keyid`. The value is the signer's AID in qb64. The verifier decides how to resolve it from the prefix's derivation code, never from its first character alone: a non-transferable code yields the Ed25519 key directly, and every transferable code, including the basic transferable Ed25519 prefix `D…`, resolves to the current key state in the KEL the verifier holds. An AID with a transferable code that the verifier has no KEL for is `unknown-key`, never a raw key. Treating a `D…` keyid as a key would accept a signature from a rotated-away inception key and undo pre-rotation. A server that serves one controller per agent (KERIA) routes on `keyid` in place of the legacy `Signify-Resource` header, which canonical mode does not use; `Signify-Timestamp` is likewise replaced by `created`. A client verifying a response MUST check that `keyid` is the AID it expects to be talking to.
- R2, `alg`. Derived from the key's CESR code. Ed25519 maps to `ed25519`. `ecdsa-p256-sha256` could later map to secp256r1 keys; secp256k1 has no registered algorithm.
- R3, key state. The key is the one current at verification time. A request signed just before a rotation fails and the client retries. Legacy Signage could name a key state with `ordinal` and `digest`; canonical mode has no place for it and does not need one for request/response authentication.
- R4, a single effective signer. A canonical signature carries no key index, so the verifier must know which key signed. The resolved key state qualifies when exactly one of its current signing keys satisfies the signing threshold on its own; that key is the one used. A plain single-key state qualifies. So does the state a Signify controller reaches when its passcode is rotated (keys `[new, prior-next]`, threshold `['1','0']`), where only the first key satisfies the threshold alone. Any other state, such as a 2-of-3 group, or `1` over two keys where either key alone suffices, is refused as `unsupported-signer`. Multiple labels (RFC 9421 §4.3) leave room for multi-key signers later.

## 8. Legacy mode, mode selection, and transition

Legacy mode is the scheme in keripy's `ending.siginput`/`signature` and KERIA's `SignedHeaderAuthenticator` today: a non-RFC base (`"@signature-params: …"` quote placement, unquoted identifiers and string parameters), the `Signify-Resource` and `Signify-Timestamp` headers, the `signify` label, and a `Signature` header of the form `indexed="?0";signify="0B…"`. This profile does not change it.

A verifier chooses the mode from the `Signature` header:

- it parses as an RFC 8941 Dictionary and every member value is a Byte Sequence: canonical;
- otherwise, keripy's legacy parser (`ending.designature`) accepts it: legacy;
- otherwise: refused as `malformed-signature`.

In legacy mode the signer's key is found by looking `Signify-Resource` up in the verifier's key state and taking its first current key, exactly as KERIA does today. An implementation whose resolver can't make that lookup separately uses the resolver it was given as-is, without refusing. §7's resolution rules (derivation-code transferability, R4's single-key requirement) apply to canonical mode only, so legacy traffic from multi-key controllers keeps verifying. The legacy test is the legacy parser, not RFC 8941, because many headers keripy's own `signature()` produces, such as indexed signatures labelled `0`, are not valid RFC 8941 and would otherwise be refused. The two modes are domain-separated because their bases differ in the final line, so a signature produced in one mode never verifies in the other.

A server responds in the mode the request used, and a client refuses a response in the other mode as `mode-mismatch`, in either direction. An upgraded client therefore gets canonical responses and an old client gets legacy ones, with no version header. A client that sent a canonical request MUST refuse a legacy response. The legacy response covers neither status nor body, so accepting one would let an intermediary substitute them.

A client that sent a canonical request also refuses an unsigned response, with one exception: an unsigned 401 is reported to the caller as an authentication failure and its body is not trusted. KERIA cannot sign a refusal it issues before it has resolved the agent. Every other unsigned response is `missing-signature`.

A client MUST NOT retry a request in legacy mode because a canonical one was refused. Automatic fallback is a downgrade any intermediary can trigger by forging one 401, and it discards the coverage this profile adds. signify-ts continues to sign in legacy mode by default until a KERIA release verifies canonical mode, because its CI integration-tests against a pinned KERIA image. Canonical signing is opt-in until then, including in `createSignedRequest`. Flipping the default is keyed to a KERIA release. A client talking to an older deployment is configured back to legacy by its operator, not by probing. Having KERIA advertise its supported modes in the unauthenticated agent state would remove that configuration step, and is noted as a follow-up.

Verifiers accept legacy mode until a separate decision retires it, unless a deployment turns it off with the `accept_legacy` setting. The keripy verifier and KERIA's config carry `accept_legacy`, on by default; an operator whose clients have all upgraded turns it off, and legacy requests are then refused as `malformed-signature`. A per-keyid ratchet is deferred: it needs per-controller state and breaks a controller running an old and a new client side by side.

## 9. Refusals

Implementations raise errors in their own idiom, but each refusal maps to one of these codes, and the shared vectors name refusals by code, never by an implementation's class name. A verifier runs its checks in the order the codes are grouped below and reports the first that fails, so every message has exactly one correct code.

Headers present and readable: `missing-signature`, `missing-signature-input`, `malformed-signature` (the `Signature` header is neither form of §8), `malformed-signature-input` (does not parse, an uppercase field name, an unknown parameter), `malformed-signature-label` (other than exactly one label), `missing-signature-label` (the two headers name different labels), `malformed-signature-value` (a Byte Sequence that is not 64 bytes). A member that is not a Byte Sequence at all makes the header neither form of §8, which is `malformed-signature`.

Mode, checked immediately after the mode is detected and before any canonical-only check: `mode-mismatch` (a legacy response to a canonical request).

Covered list: `duplicate-component`, `unsupported-component`, then `insufficient-coverage` (the minimum set of §3 is not covered, including a body without `content-digest`).

Key: `malformed-key` (the keyid is not a well-formed AID), `unknown-key` (no KEL for a transferable keyid), `unsupported-signer` (R4), `unsupported-algorithm` (an `alg` other than `ed25519`, or one that disagrees with the key).

Base and signature: `missing-component` (a covered field is absent), then `signature-mismatch`. `signature-mismatch` also covers a base that cannot be built (a component value with a newline or a non-ASCII byte), and a covered `@authority` outside the authorities a verifier serves (§3). A response signed by an AID other than the one the client expects is `unknown-key`.

Policy: `signature-stale` (`created` outside the window of §6), `signature-expired`. These run after the signature check, as fiki's do, so an unauthenticated message never learns the verifier's clock policy.

Response only, before any other check: `unauthenticated` (an unsigned 401 answering a canonical request; §8).

Body: `malformed-digest` (does not parse, or has no recognized algorithm), `digest-mismatch`, `missing-signature` for an unsigned response (§8).

A signer refusing to sign a non-empty body without `content-digest` reports `uncovered-body`, which is a signer-side code only.

Relation to fiki's classes, which are the names its own vectors use: `MissingSignature`, `MissingSignatureInput`, `MissingSignatureLabel`, `MissingComponent`, `MalformedSignature`, `MalformedSignatureInput`, `MalformedSignatureLabel`, `MalformedSignatureValue`, `MalformedKey`, `MalformedDigest`, `UnsupportedComponent`, `UnsupportedAlgorithm`, `UncoveredBody`, `SignatureExpired`, `DigestMismatch`, `SignatureMismatch`, `UnknownKey`, `UnsupportedSigner`, `DuplicateComponent`, `InsufficientCoverage` and `Unauthenticated` map to the code of the same name in kebab case, and `SignatureTooOld` maps to `signature-stale`. fiki's `MissingKey` (no keyid and no key supplied) has no counterpart, since `keyid` is required here and its absence is `malformed-signature-input`. fiki has no counterpart to `mode-mismatch`, because it does not parse legacy headers.

## 10. Test oracles

- RFC 9421 Appendix B.2.6: signing the Appendix B.2 request with the B.1.4 Ed25519 key reproduces the published base and signature byte for byte.
- Shared vectors in [`vectors/keri/`](../vectors/keri/), generated by fiki, which is independent of the code under test, covering what the RFC does not: `@query`, `content-digest` (including a header with an extra unknown-algorithm member, and one with two recognized members of which one mismatches), response binding with `req` (each response case carries its request alongside), a lowercase `@method`, a `@path` containing a character hio re-encodes (O1), non-transferable and transferable AID `keyid`s (the transferable case supplies the current key as resolver input, and one case pins a `D…` keyid that must not resolve as a raw key), an absent `alg`, freshness at each boundary of §6, a chunked body without `content-digest`, and each refusal code in §9. The JSON uses no language-specific encodings. keripy and signify-ts carry identical copies. fiki's Python implementation follows this profile where it and fiki's earlier behaviour differed (method case, multi-digest checking).
- Legacy vectors taken from the signatures pinned in KERIA's and signify-ts's current tests, so each implementation proves it still accepts today's traffic.

## 11. Open implementation notes

- O1, `@path` on KERIA. hio's WSGI server (`serving.py`) decodes the request path and re-encodes it with `quote`, so KERIA sees a re-encoding rather than the client's bytes; they differ for `~`, `%2F`, lowercase hex, and `: @ + = , ; ! $ & ' ( ) *`. Paths built from AIDs and SAIDs are unaffected, but identifier names chosen by users are not. The plan is for hio to expose the raw path as `RAW_URI`, for KERIA to use it when present, and until then to fall back to the re-encoded path, so such requests fail verification in canonical mode. The alternative, having Signify pre-normalize the path to hio's form, would be a KERI-specific rule and is rejected.
- O2, response freshness. §6 applies freshness to responses verified by a client. A browser whose clock is wrong will then fail every response, which is harder to diagnose than a failed request; implementations should say so in the error.
- O3, CORS. KERIA's CORS middleware runs after response signing, so the headers it adds are not covered. None of them is security-relevant to Signify, but this profile does not claim otherwise.
