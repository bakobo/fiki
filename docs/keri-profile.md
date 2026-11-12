# KERI profile of RFC 9421 HTTP Message Signatures

Version 1.2, 2026-11-12. Section 12 says how versions are numbered and what changed from versions 1 and 1.1.

This document specifies how keripy, KERIA and signify-ts sign and verify HTTP requests and responses once WebOfTrust/keripy#1669 lands. The key words MUST, SHOULD and MAY are used in the RFC 2119 sense.

## 1. Why, and scope

Signify's requests to KERIA and KERIA's responses are signed today, but the signature covers neither the query string nor the body of a request, nor the status or body of a response. KERIA routes on query parameters (`type` for rotation versus interaction, `filter_field`, `sender`, `pre`) and acts on bodies, so an intermediary that can alter them does so undetected. Closing that gap is the purpose of this profile, and it is what #1669 and keria#467 ask for.

RFC 9421 already defines how to cover a query (`@query`) and a body (`Content-Digest`, RFC 9530), so this profile uses it as written, rather than extending the deployed scheme with digests of its own. Conformance comes nearly for free: covering any new component forces every verifier to upgrade anyway, and the cost of making the upgraded base the RFC's is small. The resulting interoperability serves the verifiers that are not KERIA, such as a third party receiving a request from `createSignedRequest`, or a generic RFC 9421 verifier of a non-transferable signer. It is not an argument that KERIA needs clients other than Signify.

ESSR, KERIA's encrypted mode, already covers the whole request and response, and it ships in KERIA and signify-ts. It does not make this profile redundant, for three reasons. It is not the default, and the signed-header mode that is the default is the one with the gap. It exists only between a Signify client and its own agent, so it cannot reach the third parties `createSignedRequest` signs for. And nothing outside KERI can verify it. This profile leaves ESSR untouched.

The profile has two modes. Canonical mode is this profile. Legacy mode is the scheme deployed today, which verifiers keep accepting (§8). The implementations are keripy (library), KERIA (server), signify-ts (client) and, on the legacy side only, SignifyPy, which pins keri 1.2.x and calls keripy's legacy `ending` functions; those functions stay untouched on every keripy line, including the 1.2.x and 1.3.x backports.

Out of scope for this version: replay detection by nonce tracking, multi-key and threshold signers in canonical mode, algorithms other than Ed25519, ESSR, and deprecating legacy mode.

## 2. Signature base

The signature base is exactly RFC 9421 §2.5. Each covered component contributes one line, `<component-identifier>: <component-value>`, where the identifier is serialized as an RFC 8941 String with its parameters (`"@method"`, `"content-digest"`, `"@path";req`). Lines are joined by a single LF with no trailing LF. The final line is `"@signature-params": ` followed by the RFC 8941 serialization of the Inner List of covered component identifiers with the signature parameters (§4).

On verification the `@signature-params` line is serialized from the parsed `Signature-Input` member, keeping the component and parameter order in which they arrived. A verifier MUST NOT re-emit parameters in its own preferred order.

Component values follow RFC 9421 §2.1 and §2.2:

- HTTP fields: a field name in a component identifier parsed from the wire MUST already be lowercase and is refused otherwise; a signer's local caller may pass plain names and have them lowercased as a convenience. Values are the field's lines with leading and trailing whitespace removed and obsolete line folding replaced by a single space, and multiple field lines are joined with `", "` in the order received. A covered field that is absent from the message MUST cause signing and verification to fail. It is never skipped.
- `@method`: the method as sent, with no case transformation (RFC 9421 §2.2.1). Browsers' `fetch()` uppercases standard methods, so a signer must be given the method exactly as it will go on the wire.
- `@authority`: the target authority, lowercased, with the default port of the scheme the request was sent with removed (`:443` for `https`, `:80` for `http`; RFC 9110 §4.2.3). Taken from the target URI, or from `Host` when the server has only that. `Host` is a field value, so only SP and HTAB are trimmed from it, and a value that is then not a valid authority (one carrying a no-break space, say) is a base that cannot be built (§9). A verifier that has only `Host`, and so does not know the scheme, uses it as received, lowercased, and removes no port. See §3 on what a verifier must compare it with.
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

A request has a body, for the purpose of the minimum set, when its headers announce one: any `Transfer-Encoding`, or a `Content-Length` other than a plain zero. A plain decimal is one or more ASCII digits once SP and HTAB are trimmed, so a negative length, or one carrying any other whitespace such as a no-break space, is no evidence of an empty body and counts as announcing one. The covered-list check (§9) applies this test and no other. Content that no header announced is checked at the body stage (§9): a non-empty body without a covered `content-digest` is refused whatever the headers said, after the signature and freshness checks. A verifier that already holds the body when the headers arrive still applies the header test at the covered list and refuses unannounced content at the body stage, so it reports the same code as one that reads the body later. A body is never handed to application code uncovered.

Request, default signer set: the minimum set plus `@authority`. KERIA's default policy does not require `@authority`, because its `keyid` already names a controller hosted by that agent and a proxy may rewrite `Host`. A deployment MAY add `@authority` to its minimum set. A signer signing for a third party (`createSignedRequest`) MUST cover `@authority`, and a verifier that is not the signer's own agent SHOULD require it. A verifier that requires `@authority` MUST compare the covered value with the set of authorities it serves, configured, not merely rebuild it from the `Host` it received. Otherwise a request signed for one service replays to another. Requiring `@authority` applies to canonical mode only. A legacy request covers no authority, so the requirement does not apply to it, and a verifier that needs the comparison for all its traffic turns legacy mode off (§8).

Response, minimum set:

- `@status`.
- `content-digest` whenever the response has a non-empty body. A response's body is its content, and its headers are not evidence of one (a HEAD or 304 response announces a length it does not send), so this is checked at the body stage (§9).
- The request's own covered components that fall in the request minimum set, each marked `req`: `"@method";req`, `"@path";req`, `"@query";req`, and `"content-digest";req` when the request had a body.

For the response minimum, "the request had a body" means the request's content was non-empty. Its headers don't count here: by the time a response is signed or verified, both sides hold the whole request, so the header-time test of the request rules is no longer needed.

The `req` components bind the response to what was asked. A response does not cover the request's `Signature` or `Signature-Input` fields, which RFC 9421 §2.4 marks NOT RECOMMENDED because signatures of signatures do not give transitive coverage (§7.3.7).

Known limitation: the binding is to what was asked, not to the individual request. Two identical GETs produce identical `req` values, so an intermediary can answer the second with a recorded response to the first, provided the recording is still inside the freshness window of §6. The consequence is a stale read, such as key state from before a rotation; any KEL event built from it fails when submitted. This is accepted.

## 4. Signature-Input and signature parameters

`Signature-Input` is an RFC 8941 Dictionary. In canonical mode it carries exactly one member. A `Signature-Input` that is empty once SP and HTAB are trimmed is `malformed-signature-input`, not absent. The label is arbitrary; Signify and KERIA SHOULD emit `signify`, and a verifier MUST accept any single label and MUST refuse more than one. A verifier MUST refuse a `Signature` whose labels do not match `Signature-Input`'s.

Parameters, emitted by a signer in the order `created`, `expires`, `nonce`, `alg`, `keyid`, `tag`:

- `created`, Integer, REQUIRED. Seconds since the Unix epoch. An RFC 8941 Decimal is not an Integer, even with a zero fraction such as `1700000000.0`, so `created` or `expires` given as one is `malformed-signature-input`; a verifier MUST NOT read it as the whole number it equals.
- `expires`, Integer, optional. When present it MUST be enforced (§6).
- `nonce`, String, optional on the wire. Signify and KERIA SHOULD emit a fresh random nonce of at least 128 bits on every message, so that a replay cache can be added later without changing any signer; a verifier in this version never requires or checks it.
- `alg`, String, optional on the wire as in RFC 9421. Signers SHOULD emit it. When present it MUST be `ed25519` in this version and MUST agree with the resolved key, or the message is refused; when absent the algorithm is the one the resolved key's CESR code implies (§7, R2).
- `keyid`, String, REQUIRED. The signer's AID in qb64 (§7, R1).
- `tag`, String, optional. Passed through and covered; never required or checked.

Any other parameter is refused. `context`, which the legacy code parses, is not a canonical parameter.

## 5. Signature and Content-Digest

`Signature` is an RFC 8941 Dictionary whose member for the label is a Byte Sequence holding the raw 64-byte Ed25519 signature: `signify=:<base64>:`. A signer emits the base64 with its `=` padding. A verifier MUST accept a Byte Sequence without it, in `Signature` and in `Content-Digest` alike, since RFC 8941 §4.2.7 says parsers SHOULD NOT fail when padding is absent and two verifiers that differ here accept different messages. The CESR `indexed`/`signer`/`ordinal`/`digest`/`kind` metadata of the legacy header is not carried; it was never covered by the signature, so dropping it loses no protection.

`Content-Digest` follows RFC 9530. A signer emits `sha-256=:<base64>:` computed over the message content as sent. A verifier recognizes `sha-256` and `sha-512`, ignores other algorithms (RFC 9530 §2), and requires every recognized one to match. A header with no recognized member is an error, not a pass. The digest MUST be recomputed over the received content before the message is accepted. Covering `Content-Digest` without recomputing it protects nothing.

The two checks may run at different times, but an implementation MUST NOT let the second be forgotten: a header-time verification whose body check is still owed must say so in what it returns, rather than look like a completed verification. A verifier SHOULD verify the signature over the base as soon as the headers arrive, which rejects forgeries without reading the body, and compare the digest once the body has been read. Both MUST pass before the request reaches application code. A covered `content-digest` on a message with no content is checked against the digest of the empty string.

A streamed response body is buffered so it can be digested and covered. Signing a streamed response without `content-digest` would leave its body uncovered, which is the gap #1669 exists to close. KERIA's only streamed response, GET `/contacts/{prefix}/img`, serves an upload capped at 1 MB.

## 6. Freshness

In canonical mode a verifier MUST refuse a message whose `created` is earlier than `now - max_age - skew` or later than `now + skew`, and one whose `expires` is present and earlier than `now - skew`. Defaults are `max_age = 300` and `skew = 60` seconds, both configurable; the verifier reads its clock through an injectable source so tests can pin it. `now` is that clock in whole seconds, rounded down, so a clock with a fractional part moves no boundary. The checks apply to requests verified by a server and to responses verified by a client. The arithmetic matches fiki's.

Legacy mode performs no freshness check, as today, so no deployed client breaks. Replay within the window is not detected; endpoints that must be safe against it should be idempotent, as iFergal proposed in keria#287.

## 7. Where the profile is KERI-flavoured

Each of these uses a field RFC 9421 leaves to the application. None is a syntactic divergence.

- R1, `keyid`. The value is the signer's AID in qb64. It is a well-formed AID when it is the canonical qb64 spelling of one of the prefix derivation codes keripy's `PreDex` lists: `B`, `D`, `E`, `F`, `G`, `H` and `I` over 32 bytes; `0D`, `0E`, `0F` and `0G` over 64; `1AAA`, `1AAB`, `1AAI` and `1AAJ` over 33; `1AAC` and `1AAD` over 57; and `1AAE` over 114. Any other keyid, or another spelling of the same bytes, is `malformed-key`. The verifier decides how to resolve it from the prefix's derivation code, never from its first character alone. The non-transferable Ed25519 code `B` yields the key directly from the prefix: the verifier never asks its key store or a resolver for it, so a verifier that holds no key state at all still verifies a `B` keyid. Another non-transferable code (`1AAA`, `1AAC`, `1AAI`) is `unsupported-algorithm`. Every transferable code, including the basic transferable Ed25519 prefix `D…`, resolves to the current key state in the KEL the verifier holds. An AID with a transferable code that the verifier has no KEL for is `unknown-key`, never a raw key. Treating a `D…` keyid as a key would accept a signature from a rotated-away inception key and undo pre-rotation. The key a `B` keyid carries, and any key resolved from key state, MUST be a valid point of Ed25519's prime-order subgroup: the canonical encoding of a point on the curve whose order is the group order L, which is what libsodium's `crypto_core_ed25519_is_valid_point` accepts. A key of small order, or of mixed order (a subgroup point plus a torsion component), is `malformed-key`. No seed yields such a key, and under a small-order one a signature verifies over any message. A server that serves one controller per agent (KERIA) routes on `keyid` in place of the legacy `Signify-Resource` header, which canonical mode does not use; `Signify-Timestamp` is likewise replaced by `created`. A client verifying a response MUST check that `keyid` is the AID it expects to be talking to.
- R2, `alg`. Derived from the key's CESR code. Ed25519 maps to `ed25519`. `ecdsa-p256-sha256` could later map to secp256r1 keys; secp256k1 has no registered algorithm.
- R3, key state. The key is the one current at verification time. A request signed just before a rotation fails and the client retries. Legacy Signage could name a key state with `ordinal` and `digest`; canonical mode has no place for it and does not need one for request/response authentication.
- R4, a single effective signer. A canonical signature carries no key index, so the verifier must know which key signed. The resolved key state qualifies when exactly one of its current signing keys satisfies the signing threshold on its own; that key is the one used. A plain single-key state qualifies. So does the state a Signify controller reaches when its passcode is rotated (keys `[new, prior-next]`, threshold `['1','0']`), where only the first key satisfies the threshold alone. Any other state, such as a 2-of-3 group, or `1` over two keys where either key alone suffices, is refused as `unsupported-signer`. R4 applies to canonical mode only; legacy mode has its own rule (§8). Multiple labels (RFC 9421 §4.3) leave room for multi-key signers later.

## 8. Legacy mode, mode selection, and transition

Legacy mode is the scheme in keripy's `ending.siginput`/`signature` and KERIA's `SignedHeaderAuthenticator` today: a non-RFC base (`"@signature-params: …"` quote placement, unquoted identifiers and string parameters), the `Signify-Resource` and `Signify-Timestamp` headers, the `signify` label, and a `Signature` header of the form `indexed="?0";signify="0B…"`. This profile does not change its wire format or its base.

A verifier chooses the mode from the `Signature` header:

- it parses as an RFC 8941 Dictionary and every member value is a Byte Sequence: canonical;
- otherwise, keripy's legacy parser (`ending.designature`) accepts it: legacy;
- otherwise: refused as `malformed-signature`.

In legacy mode the verifier looks `Signify-Resource` up in its key state and accepts the signature when it verifies under some current key that alone satisfies the controller's signing threshold, trying each such key. A legacy signature is not indexed (`indexed="?0"`), so nothing on the wire says which key made it. For a Signify or SignifyPy controller with one key, or after a passcode rotation (keys `[new, prior-next]`, threshold `['1','0']`), the only such key is the first. For an AID made with more than one key under threshold `1`, which signify-ts's `createSignedRequest` signs with its first key, every key qualifies, so that traffic verifies. A key state in which no key alone satisfies the threshold, such as a 2-of-3 group, is refused as `unsupported-signer`. A signature by a key that does not alone satisfy the threshold verifies under none of the keys that do, and is `signature-mismatch`: with threshold `['0','1']`, a signature by the first key, which carries no weight, is refused, and one by the second is accepted. Version 1 took the first current key whatever the threshold said, so one member of a group could act as the group and a compromised key rotated to weight 0 kept authenticating; version 1.1 took only a single effective signer and so refused `1` over two keys, which signify-ts still sends (§12). Legacy mode never takes a key from a prefix: R1's derivation-code rules apply to canonical mode only, and a `Signify-Resource` with no key state is `unknown-key`, whatever its code, including `B`. The legacy test is the legacy parser, not RFC 8941, because many headers keripy's own `signature()` produces, such as indexed signatures labelled `0`, are not valid RFC 8941 and would otherwise be refused. The two modes are domain-separated because their bases differ in the final line, so a signature produced in one mode never verifies in the other.

A server responds in the mode the request used, and a client refuses a response in the other mode as `mode-mismatch`, in either direction. An upgraded client therefore gets canonical responses and an old client gets legacy ones, with no version header. A client that sent a canonical request MUST refuse a legacy response. The legacy response covers neither status nor body, so accepting one would let an intermediary substitute them.

A client that sent a canonical request also refuses an unsigned response, with one exception: an unsigned 401 is reported to the caller as an authentication failure and its body is not trusted. A response whose `Signature` header is present but empty is unsigned, so an empty `Signature` on a 401 is that exception too. KERIA cannot sign a refusal it issues before it has resolved the agent. Every other unsigned response is `missing-signature`.

A client MUST NOT retry a request in legacy mode because a canonical one was refused. Automatic fallback is a downgrade any intermediary can trigger by forging one 401, and it discards the coverage this profile adds. signify-ts continues to sign in legacy mode by default until a KERIA release verifies canonical mode, because its CI integration-tests against a pinned KERIA image. Canonical signing is opt-in until then, including in `createSignedRequest`. Flipping the default is keyed to a KERIA release. A client talking to an older deployment is configured back to legacy by its operator, not by probing. Having KERIA advertise its supported modes in the unauthenticated agent state would remove that configuration step, and is noted as a follow-up.

Verifiers accept legacy mode until a separate decision retires it, unless a deployment turns it off with the `accept_legacy` setting. The keripy verifier and KERIA's config carry `accept_legacy`, on by default; an operator whose clients have all upgraded turns it off, and legacy requests are then refused as `malformed-signature`. Turning legacy off is the only way a verifier refuses a request for being legacy. Legacy requests cover no authority, query or body and carry no freshness, so a verifier that requires `@authority` (§3) does not apply that requirement to them; a deployment that needs the authority comparison, or any other canonical guarantee, for every request turns legacy off. A per-keyid ratchet is deferred: it needs per-controller state and breaks a controller running an old and a new client side by side.

## 9. Refusals

Implementations raise errors in their own idiom, but every refusal of a peer's message maps to one of these codes, in either mode, and the shared vectors name refusals by code, never by an implementation's class name. A verifier never answers anything a peer sent with an error outside this list, such as a parser's own exception or a crash. A canonical verifier runs these checks in this order and reports the first that fails, so every canonical message has exactly one correct code:

1. `unauthenticated`, responses only: an unsigned 401 answering a canonical request, including one whose `Signature` header is present but empty (§8).
2. `missing-signature`: no `Signature` header. On a response, an empty one too (§8), so every unsigned response other than that 401.
3. `missing-signature-input`: no `Signature-Input` header.
4. `malformed-signature`: the `Signature` header is neither form of §8. That includes a member that is not a Byte Sequence, an empty `Signature` on a request, and a legacy `Signature` when legacy mode is turned off.
5. `mode-mismatch`, responses only: a legacy response to a canonical request, or a canonical response to a legacy request (§8). It is checked as soon as the mode is known, before any check that belongs to one mode.
6. `malformed-signature-input`: `Signature-Input` does not parse, is empty, names a field in uppercase, carries an unknown parameter or one of the wrong type (a Decimal `created` or `expires`, §4), or lacks `created` or `keyid`.
7. `malformed-signature-label`: either header carries other than exactly one label.
8. `missing-signature-label`: the two headers name different labels.
9. `malformed-signature-value`: a Byte Sequence that is not 64 bytes.
10. `duplicate-component`.
11. `unsupported-component`.
12. `insufficient-coverage`: the minimum set of §3 is not covered, judged by the headers. That includes a request body announced by its headers without `content-digest`, `"content-digest";req` when the request's content was non-empty, and `@authority` when the verifier requires it.
13. `malformed-key`: the keyid is not a well-formed AID, or is a `B` keyid whose key is not a valid point of the prime-order subgroup (R1). This needs nothing but the keyid.
14. `unknown-key`: on a response, a keyid other than the AID the client expects (R1), checked before any key state is read; then a transferable keyid the verifier has no KEL for.
15. `unsupported-signer`: R4.
16. `malformed-key`: the key resolved from key state is not a valid point of the prime-order subgroup (R1).
17. `unsupported-algorithm`: a non-transferable keyid whose code is not `B`, a resolved key that is not Ed25519, or an `alg` other than `ed25519` or one that disagrees with the key.
18. `missing-component`: a covered field is absent.
19. `signature-mismatch`: a base that cannot be built (a component value with a newline or a non-ASCII byte, or an authority that is not valid), a signature that does not verify, or a covered `@authority` outside the authorities a verifier serves (§3).
20. `signature-stale`: `created` outside the window of §6.
21. `signature-expired`.
22. `insufficient-coverage`: content no header announced, without a covered `content-digest` (§3). This and the next two are the body stage.
23. `malformed-digest`: a covered `Content-Digest` does not parse, or has no recognized algorithm.
24. `digest-mismatch`.

The policy checks, 20 and 21, run after the signature check, as fiki's do, so an unauthenticated message never learns the verifier's clock policy. The body stage runs last whether or not the verifier held the body when the headers arrived. A verifier that defers it (§5) runs steps 22 to 24 once the body is read, and one that already holds the body still runs them after step 21, so both report the same code for the same message. Every covered digest is parsed before any is compared.

Legacy mode uses the same codes after step 5, in this order: `missing-component` (no `Signify-Resource`); on a response, `unknown-key` for a `Signify-Resource` other than the AID the client expects; `unknown-key` (no key state for `Signify-Resource`); `unsupported-signer` (no key alone satisfies the threshold, §8); `malformed-signature-input` (`Signature-Input` does not parse, or a covered item is not a String); `missing-signature-label`; `signature-mismatch` (the signature verifies under none of the keys that alone satisfy the threshold).

A signer refusing to sign a non-empty body without `content-digest` reports `uncovered-body`, which is a signer-side code only.

Relation to fiki's classes, which are the names its own vectors use: `MissingSignature`, `MissingSignatureInput`, `MissingSignatureLabel`, `MissingComponent`, `MalformedSignature`, `MalformedSignatureInput`, `MalformedSignatureLabel`, `MalformedSignatureValue`, `MalformedKey`, `MalformedDigest`, `UnsupportedComponent`, `UnsupportedAlgorithm`, `UncoveredBody`, `SignatureExpired`, `DigestMismatch`, `SignatureMismatch`, `UnknownKey`, `UnsupportedSigner`, `DuplicateComponent`, `InsufficientCoverage` and `Unauthenticated` map to the code of the same name in kebab case, and `SignatureTooOld` maps to `signature-stale`. fiki's `MissingKey` (no keyid and no key supplied) has no counterpart, since `keyid` is required here and its absence is `malformed-signature-input`. fiki has no counterpart to `mode-mismatch`, because it does not parse legacy headers.

## 10. Test oracles

- RFC 9421 Appendix B.2.6: signing the Appendix B.2 request with the B.1.4 Ed25519 key reproduces the published base and signature byte for byte.
- Shared vectors in [`vectors/keri/`](../vectors/keri/), generated by fiki, which is independent of the code under test, covering what the RFC does not: `@query`, `content-digest` (including a header with an extra unknown-algorithm member, one with two recognized members of which one mismatches, and one without `=` padding), response binding with `req` (each response case carries its request alongside), a lowercase `@method`, a `@path` containing a character hio re-encodes (O1), non-transferable and transferable AID `keyid`s (the transferable case supplies the current key as resolver input, one case pins a `D…` keyid that must not resolve as a raw key, and one `B` keyid has no key state at all), keyids with other prefix codes, small-order and mixed-order `B` keys, an absent `alg`, freshness at each boundary of §6 and under a fractional clock, a chunked body without `content-digest`, `Host` values that keep a default port or carry a no-break space, each refusal code in §9, and two cases with two defects each, which pin the order of §9 where the body stage meets the signature and freshness checks. The JSON uses no language-specific encodings. keripy and signify-ts carry identical copies. fiki's Python implementation follows this profile where it and fiki's earlier behaviour differed (method case, multi-digest checking). Two cases are carried by fiki as data rather than verified: an unpadded `Signature` and an unpadded `Content-Digest`, because fiki's own vectors refuse missing padding.
- Legacy vectors taken from the signatures pinned in KERIA's and signify-ts's current tests, so each implementation proves it still accepts today's traffic, and legacy messages generated by fiki from controllers with more than one current key, so each implementation proves it applies §8's rule: `1` over two keys accepted from either key, a 2-of-3 group refused as `unsupported-signer`, a passcode-rotated Signify controller accepted, and a controller with threshold `['0','1']` accepted from its second key and refused from its first. Two more pin that legacy mode takes no key from a `B` prefix and that a `Signature-Input` covering something other than a String is refused with a code.

## 11. Open implementation notes

- O1, `@path` on KERIA. hio's WSGI server (`serving.py`) decodes the request path and re-encodes it with `quote`, so KERIA sees a re-encoding rather than the client's bytes; they differ for `~`, `%2F`, lowercase hex, and `: @ + = , ; ! $ & ' ( ) *`. Paths built from AIDs and SAIDs are unaffected, but identifier names chosen by users are not. KERIA now sets `RAW_URI` itself, through its own server type, and uses it when present; a deployment on a server that does not set it falls back to the re-encoded path, so such requests fail verification in canonical mode. The alternative, having Signify pre-normalize the path to hio's form, would be a KERI-specific rule and is rejected.
- O2, response freshness. §6 applies freshness to responses verified by a client. A browser whose clock is wrong will then fail every response, which is harder to diagnose than a failed request; implementations should say so in the error.
- O3, CORS. KERIA's CORS middleware runs after response signing, so the headers it adds are not covered. None of them is security-relevant to Signify, but this profile does not claim otherwise.

## 12. Versions

A minor version (1.1, 1.2) clarifies the profile or tightens it: it states a reading the earlier text left open, or refuses a message no conforming signer produces. A major version (2) is breaking: a conforming signer's messages would be refused, or a verifier would have to accept something the earlier version refused. Each version is tagged in bakobo/fiki as `keri-profile-v<version>` (`keri-profile-v1`, `keri-profile-v1.1`, `keri-profile-v1.2`), and implementations and vectors cite the tag rather than the main branch, which moves.

Version 1.1 said that what it refused in legacy mode was a signature that never authenticated its controller, that no Signify or SignifyPy client produces one, and that it was therefore a tightening. That was wrong. signify-ts's `createSignedRequest`, in legacy mode, its default, signs with the first key of an AID whatever its threshold, and an AID made with two keys under threshold `1` is one whose first key alone satisfies the threshold. Version 1.1 refused it as `unsupported-signer`, so it refused messages a conforming signer produces, which by the rule above made it a breaking change. Version 1.2 accepts that traffic again: a legacy signature is accepted under any current key that alone satisfies the threshold. It still refuses what 1.1 rightly refused, a group member signing as the group and a key with no weight, so it is a minor version. A verifier on 1.1 should move to 1.2.

Version 1.2's other changes give one answer where the text, the vectors or the implementations gave two, and where it refuses something 1.1 left open it is a message neither Signify nor KERIA produces. Changes from version 1.1 (2026-11-10, tag `keri-profile-v1.1`):

- §8: legacy mode accepts a signature under any current key that alone satisfies the signing threshold, rather than only a single effective signer, and takes no key from a prefix. R4 is now canonical-only.
- §8 and §3: requiring `@authority` does not apply to legacy requests; turning legacy off is the only way to refuse them.
- §9: the refusal order is one numbered list. `mode-mismatch` comes immediately after `malformed-signature`, a response keyid other than the expected AID is `unknown-key` immediately after the keyid's own well-formedness, and legacy mode has its own order. Every refusal of a peer's message is a §9 code.
- §3 and §9: content no header announced is refused at the body stage, after the signature and freshness checks, for requests and responses alike. §3 states the plain-decimal `Content-Length` test the vectors already carried.
- §7 R1 and §9: a `B` keyid whose key is of small or mixed order, or any resolved key that is, is `malformed-key`. A keyid is a well-formed AID under keripy's `PreDex` codes, and a non-transferable code other than `B` is `unsupported-algorithm`. A `B` keyid's key comes from the prefix, never a resolver.
- §4: a Decimal `created` or `expires` is `malformed-signature-input`, and so is an empty `Signature-Input`.
- §5: Byte Sequences without `=` padding are accepted.
- §6: `now` is rounded down to whole seconds.
- §2: `@authority` drops the default port of the scheme it was sent with; `Host` keeps whatever port it carries, and only SP and HTAB are trimmed from it.
- §10 and §11: the new vectors, and O1's note that KERIA now sets `RAW_URI`.

Changes from version 1 (2026-09-24, tag `keri-profile-v1`) to version 1.1:

- §8: legacy mode uses the controller's single effective signer under R4 rather than its first current key, and refuses a controller without one as `unsupported-signer`. R4 notes that it applies to legacy mode too. (Revised by 1.2.)
- §9: `mode-mismatch` names both directions, as §8 already did.
- §8 and §9: a response whose `Signature` header is present but empty is unsigned, so a 401 carrying one is `unauthenticated`.
- §9: a well-formed `B` keyid whose key is a small-order Ed25519 point is `malformed-key`.
- §10: the legacy vectors include generated multi-key cases.
- §12: this section.
