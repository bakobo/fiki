using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;

namespace Bakobo.Fiki
{
    /// <summary>
    /// Signing and verifying whole requests and responses (this.i @2hwvpm42, @7xrx5evg), as
    /// fiki-py's messages.py does.
    /// </summary>
    /// <remarks>
    /// The keyid is the signer's raw key unless the caller names another, so a fiki-signed message
    /// carries its own verifying key; a verifier handed a resolver never falls back to reading a key
    /// out of the keyid. A body is always covered or the signature is refused. The bound: fiki
    /// cannot cover a body it was never given.
    /// </remarks>
    internal static class Messages
    {
        internal const string Alg = "ed25519";

        // RFC 9530. sha-256 on the way out; both are accepted on the way in, because fiki is not the
        // only thing that will ever have signed a message it is asked to verify. Every one of these a
        // header carries must match; any other algorithm is ignored (RFC 9530 section 2).
        private const string DigestOut = "sha-256";

        private const int SignatureLength = 64;
        private const int KeyLength = 32;

        // The RFC 8037 "x" form of a raw keyid (@7xrx5evg): 32 bytes, base64url, unpadded.
        private const int RawKeyIdLength = 43;
        private const string UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        // RFC 9421 section 2.3's six signature parameters and whether each is an integer. Anything
        // else is refused rather than carried: a parameter fiki does not understand could be one
        // whose meaning the signer relied on (@7f28p7xk).
        private static readonly string[] ParamNames = { "created", "expires", "nonce", "alg", "keyid", "tag" };

        // The KERI profile's minimum covered sets (section 3). A body adds content-digest on top,
        // and a response to a request that had a body adds "content-digest";req.
        internal static readonly string[] RequestMinimum = { "@method", "@path", "@query" };

        // What VerifyRequest requires when the caller states no minimum of its own (this.i
        // @524c8qgv): fiki's own signing default, so a verifier left at its defaults accepts what a
        // fiki signer produces and nothing that covers less. WithoutMinimum opts out.
        internal static readonly string[] DefaultMinimum = { "@method", "@authority", "@path", "@query" };

        internal static readonly string[] ResponseMinimum =
            { "@status", Components.Req("@method"), Components.Req("@path"), Components.Req("@query") };

        private static readonly SfItem BodyDigest = Components.Component(Components.ContentDigest);
        private static readonly SfItem RequestDigest = Components.Component(Components.Req(Components.ContentDigest));
        private static readonly SfItem Authority = Components.Component("@authority");

        internal static string ContentDigest(byte[] body) => DigestOut + "=:" + Convert.ToBase64String(Hash(DigestOut, body)) + ":";

        private static byte[] Hash(string algorithm, byte[] data)
        {
            using (HashAlgorithm hash = algorithm == DigestOut ? (HashAlgorithm)SHA256.Create() : SHA512.Create())
            {
                return hash.ComputeHash(data);
            }
        }

        private static bool IsDigestAlgorithm(string name) => name == "sha-256" || name == "sha-512";

        /// <summary>
        /// A supplied minimum selects the KERI profile's policy, so it may only add to the profile's.
        /// Anything smaller is the caller's mistake rather than a message's defect.
        /// </summary>
        private static List<SfItem>? Floored(IEnumerable<string>? minimum, string[] floor)
        {
            if (minimum == null)
            {
                return null;
            }
            var given = Components.Parse(minimum);
            var missing = new List<string>();
            foreach (var spec in floor)
            {
                if (!Components.Contains(given, Components.Component(spec)))
                {
                    missing.Add(spec);
                }
            }
            if (missing.Count > 0)
            {
                throw new ArgumentException(
                    $"A minimum covered set must include the profile's own, {string.Join(", ", floor)}; this one leaves out " +
                    $"{string.Join(", ", missing)}. Pass no minimum, or call VerifyOptions.WithoutMinimum, to apply none at all.");
            }
            return given;
        }

        private static bool BindsRequestDigest(IEnumerable<SfItem> items) => Components.Contains(items, RequestDigest);

        private static bool CoversBody(IEnumerable<SfItem> items) => Components.Contains(items, BodyDigest);

        /// <summary>Header names lowercased, values as given; a later name wins.</summary>
        private static Dictionary<string, string> Lowered(IEnumerable<KeyValuePair<string, string>> headers)
        {
            var lowered = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var header in headers)
            {
                lowered[PyText.AsciiLower(header.Key)] = header.Value;
            }
            return lowered;
        }

        private static bool HasContent(byte[]? body) => body != null && body.Length > 0;

        /// <summary>
        /// Cover a body the caller handed over, or refuse to sign (@2hwvpm42). True when fiki
        /// computed the Content-Digest and so must return it among the headers.
        /// </summary>
        private static bool CoverBody(List<SfItem> items, List<KeyValuePair<string, string>> sending, byte[]? body, bool chosen)
        {
            if (body == null)
            {
                return false;
            }
            // Whether the caller CHOSE the covered set is the difference between fiki helping and
            // fiki overriding: on the default path a body simply gets covered, and on an explicit
            // one, silently adding a component would sign something the caller did not ask for.
            if (!CoversBody(items))
            {
                if (chosen)
                {
                    throw new FikiException(
                        FikiErrorKind.UncoveredBody,
                        $"This message carries a body, but the covered components do not include \"{Components.ContentDigest}\", " +
                        "so the signature would not bind the body. Add it to the covered set, or omit the body if it is " +
                        "genuinely not part of what you are signing.");
                }
                items.Add(Components.Component(Components.ContentDigest));
            }
            if (Lowered(sending).TryGetValue(Components.ContentDigest, out var supplied))
            {
                // A digest the caller supplied is signed as given, so it must be one the verifier will
                // accept for this body: a mismatch, or one that does not parse or names nothing fiki
                // computes, is the call's mistake, not a message (@5zrf8gjk).
                try
                {
                    CompareDigest(ReadDigest(supplied), body);
                }
                catch (FikiException ex)
                {
                    throw new ArgumentException(
                        $"The Content-Digest supplied with this body is not one a verifier would accept for it: {ex.Message} " +
                        "Omit it and fiki computes one, or supply the body it describes.",
                        ex);
                }
                return false;
            }
            sending.Add(new KeyValuePair<string, string>("Content-Digest", ContentDigest(body)));
            return true;
        }

        private static IReadOnlyDictionary<string, string> Signed(Key key, byte[] signatureBase, string signatureParams, string label, List<KeyValuePair<string, string>> sending, bool digested)
        {
            var output = new Dictionary<string, string>
            {
                { "Signature-Input", label + "=" + signatureParams },
                { "Signature", label + "=:" + Convert.ToBase64String(key.Sign(signatureBase)) + ":" },
            };
            if (digested)
            {
                output.Add("Content-Digest", sending[sending.Count - 1].Value);
            }
            return output;
        }

        /// <summary>
        /// Refuse a label that is not an RFC 8941 dictionary key, since the headers it would label
        /// could not be parsed back by any verifier, this port's included. fiki-py writes whatever
        /// label it is given; refusing is a divergence that changes nothing on the wire, because no
        /// such header is valid there (hostile review of bakobo/fiki#7, finding 3).
        /// </summary>
        private static void CheckLabel(string label)
        {
            if (!Sfv.IsKey(label))
            {
                throw new ArgumentException(
                    $"The label \"{label}\" is not an RFC 8941 dictionary key, so no verifier could read the headers it " +
                    "would label: it must begin with a lowercase letter or \"*\" and continue with lowercase letters, digits, " +
                    "\"_\", \"-\", \".\" or \"*\".",
                    nameof(label));
            }
        }

        private static long Clock() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        /// <summary>The raw verifying key, base64url and unpadded: the RFC 8037 JWK "x" form (@7xrx5evg).</summary>
        private static string RawKeyId(Key key) => Base64Url.Encode(Aids.VerifyingKey(key.Aid));

        internal static IReadOnlyDictionary<string, string> SignRequest(Key key, string method, string url,
            IEnumerable<KeyValuePair<string, string>>? headers, byte[]? body, IEnumerable<string>? covered, long? created,
            string label, long? expires, string? nonce, string? tag, string? keyId, IEnumerable<string>? minimum)
        {
            CheckLabel(label);
            Components.CheckSignerParams(created, expires, keyId, Alg, nonce, tag);
            Components.CheckMethod(method);
            var floor = Floored(minimum, RequestMinimum);
            var sending = new List<KeyValuePair<string, string>>(HeaderSnapshot.Take(headers ?? new KeyValuePair<string, string>[0]));
            var items = Components.Parse(covered ?? HttpSignatures.DefaultCovered);
            var digested = CoverBody(items, sending, body, chosen: covered != null);
            if (floor != null)
            {
                CheckMinimum(items, floor, RequestHasBody(Lowered(sending), body), requestHadBody: false);
            }

            Components.CheckCovered(items, response: false);
            var lines = Components.LinesFor(items, Components.RequestMessage(method, url, sending));
            var signatureParams = Components.SignatureParams(items, created ?? Clock(), keyId ?? RawKeyId(key), Alg, expires, nonce, tag);
            return Signed(key, Components.Join(lines, signatureParams), signatureParams, label, sending, digested);
        }

        internal static IReadOnlyDictionary<string, string> SignResponse(Key key, int status, Request? request,
            IEnumerable<KeyValuePair<string, string>>? headers, byte[]? body, IEnumerable<string>? covered, long? created,
            string label, long? expires, string? nonce, string? tag, string? keyId, IEnumerable<string>? minimum)
        {
            CheckLabel(label);
            Components.CheckSignerParams(created, expires, keyId, Alg, nonce, tag);
            if (request != null)
            {
                Components.CheckMethod(request.Method);
            }
            var floor = Floored(minimum, ResponseMinimum);
            var sending = new List<KeyValuePair<string, string>>(HeaderSnapshot.Take(headers ?? new KeyValuePair<string, string>[0]));
            HeaderSnapshot.Check(request);
            var chosen = covered != null;
            // By content alone: both sides hold the whole request by now (profile section 3, @7p9s3g9k).
            var hadBody = HasContent(request?.BodyRef);
            if (covered == null)
            {
                var defaults = new List<string> { "@status" };
                if (request != null)
                {
                    defaults.AddRange(new[] { Components.Req("@method"), Components.Req("@path"), Components.Req("@query") });
                }
                covered = defaults;
            }
            var items = Components.Parse(covered);
            var digested = CoverBody(items, sending, body, chosen);
            if (!chosen && hadBody)
            {
                if (!Lowered(request!.Headers).ContainsKey(Components.ContentDigest))
                {
                    throw new FikiException(
                        FikiErrorKind.UncoveredBody,
                        "The request this response answers carried a body and no Content-Digest, so the response has " +
                        "nothing to bind that body with. Sign the request with a digest first, or name the covered " +
                        "components yourself.");
                }
                items.Add(Components.Component(Components.Req(Components.ContentDigest)));
            }
            if (floor != null)
            {
                CheckMinimum(items, floor, HasContent(body), hadBody);
            }
            // The check VerifyResponse will make, made first: a signer does not vouch for a request
            // digest that the request body it was handed contradicts (bakobo/fiki#4).
            if (request?.BodyRef != null && BindsRequestDigest(items))
            {
                CompareDigest(ReadDigest(Header(Lowered(request.Headers), Components.ContentDigest)), request.BodyRef);
            }

            Components.CheckCovered(items, response: true);
            var lines = Components.LinesFor(items, Components.ResponseMessage(status, sending, request));
            var signatureParams = Components.SignatureParams(items, created ?? Clock(), keyId ?? RawKeyId(key), Alg, expires, nonce, tag);
            return Signed(key, Components.Join(lines, signatureParams), signatureParams, label, sending, digested);
        }

        private static string? Header(Dictionary<string, string> headers, string name) =>
            headers.TryGetValue(name, out var value) ? value : null;

        internal static Verdict VerifyRequest(string method, string url, IEnumerable<KeyValuePair<string, string>> given, VerifyOptions options)
        {
            var headers = HeaderSnapshot.Take(given);
            if (options.Request != null)
            {
                throw new ArgumentException("A request answers no other request; WithRequest applies to verifying a response.");
            }
            // A required decision, like the freshness policy (this.i @524c8qgv): which hosts this
            // verifier serves, or that it declines the check. A default either way would be wrong.
            if (!options.AuthoritiesStated)
            {
                throw new ArgumentException(
                    "Verifying a request needs a decision about the hosts it may be signed for: " +
                    "VerifyOptions.WithAuthorities(new[] { \"api.example.com\" }) or DecliningAuthorityCheck().");
            }
            var floor = Floored(options.MinimumStated ? options.Minimum : DefaultMinimum, RequestMinimum);
            return Verify(Components.RequestMessage(method, url, headers, received: true), headers, options, response: false, floor);
        }

        internal static Verdict VerifyResponse(int status, IEnumerable<KeyValuePair<string, string>> given, VerifyOptions options)
        {
            var headers = HeaderSnapshot.Take(given);
            HeaderSnapshot.Check(options.Request);
            if (options.Authorities != null)
            {
                throw new ArgumentException("A response covers no authority of its own; WithAuthorities applies to verifying a request.");
            }
            // A required decision, like the authorities of a request (this.i @524c8qgv): the AID the
            // client is talking to, or that any signer will do and is read from the verdict.
            if (!options.ExpectedKeyIdStated)
            {
                throw new ArgumentException(
                    "Verifying a response needs a decision about who may have signed it: " +
                    "VerifyOptions.WithExpectedKeyId(aid), the AID this client is talking to, or DecliningKeyidCheck().");
            }
            // Unstated, a response is held to the profile's own minimum; WithoutMinimum opts out.
            var floor = Floored(options.MinimumStated ? options.Minimum : ResponseMinimum, ResponseMinimum);
            // A server that refuses before it knows the agent cannot sign the refusal, so an
            // unsigned 401 is an authentication failure whose body is not to be trusted (@2f227n4r).
            // An empty Signature is no signature: the same unsigned 401 (@5zrf8gjk).
            if (status == 401 && string.IsNullOrEmpty(Header(Lowered(headers), "signature")))
            {
                throw new FikiException(
                    FikiErrorKind.Unauthenticated,
                    "The server answered 401 without signing the answer, so the request was not authenticated and the " +
                    "body of the refusal cannot be trusted.");
            }
            return Verify(Components.ResponseMessage(status, headers, options.Request, received: true), headers, options, response: true, floor);
        }

        /// <summary>The KERI profile's section 9 order, so a message has exactly one correct refusal.</summary>
        private static Verdict Verify(Components.Message message, IEnumerable<KeyValuePair<string, string>> headers,
            VerifyOptions options, bool response, List<SfItem>? minimum)
        {
            if (options.ExpectedAid != null && options.Resolver != null)
            {
                throw new ArgumentException("Pass an expected AID or a resolver, not both; each decides the key alone.");
            }
            var request = response ? options.Request : null;
            var body = options.Body;

            var found = Lowered(headers);
            var inner = Read(found, out var signature, requireKeyId: options.ExpectedAid == null, requireCreated: minimum != null);
            var items = new List<SfItem>(inner.Items);
            Components.CheckCovered(items, response);
            if (minimum != null)
            {
                CheckMinimum(items, minimum,
                    hasBody: response ? HasContent(body) : RequestHasBody(found, body),
                    // By the request's content alone, as SignResponse decides it (@7p9s3g9k).
                    requestHadBody: HasContent(request?.BodyRef));
            }
            // Served authorities bind the signature to a host only if it commits to one, so supplying
            // them makes @authority required (@605z9tnw): coverage, before the key, as section 9 orders.
            if (options.Authorities != null)
            {
                CheckMinimum(items, new List<SfItem> { Authority }, hasBody: false, requestHadBody: false);
            }

            // Section 9's key steps in order (@5zrf8gjk): what the keyid alone shows, then the expected
            // keyid, and only then the resolver, which is never asked about a keyid already refused.
            var keyId = inner.Params.TryGet("keyid", out var keyIdValue) ? keyIdValue!.Text : null;
            var publicKey = LocalKey(options.ExpectedAid, keyId, options.Resolver, out var aid);
            if (options.ExpectedKeyId != null && keyId != options.ExpectedKeyId)
            {
                throw new FikiException(
                    FikiErrorKind.UnknownKey,
                    $"This message is signed by \"{keyId}\", and the one expected is \"{options.ExpectedKeyId}\".",
                    keyId: keyId);
            }
            publicKey ??= Resolved(keyId!, options.Resolver!, out aid);
            if (inner.Params.TryGet("alg", out var alg) && alg!.Text != Alg)
            {
                throw new FikiException(
                    FikiErrorKind.UnsupportedAlgorithm,
                    $"This signature is made with \"{alg.Text}\", and fiki verifies only {Alg} signatures.")
                { Alg = alg.Text };
            }

            var lines = Components.LinesFor(items, message);
            if (!new PublicKey(publicKey).Verify(signature, Components.Join(lines, inner.Serialize())))
            {
                throw new FikiException(
                    FikiErrorKind.SignatureMismatch,
                    "The signature does not match this message under the signer's key, so the message cannot be " +
                    "treated as authentic.");
            }

            if (options.Authorities != null)
            {
                foreach (var item in items)
                {
                    if (item.Value.Text == "@authority" && !options.Authorities.Contains(Components.ValueOf(item, message)))
                    {
                        throw new FikiException(
                            FikiErrorKind.SignatureMismatch,
                            $"The signature covers the authority {PyText.Shown(Components.ValueOf(item, message))}, which this verifier " +
                            "does not serve, so it was signed for somebody else.");
                    }
                }
            }

            // AFTER the signature check, deliberately. created and expires are covered by the
            // signature, so acting on them before verifying it would enforce a policy against values
            // an attacker could still have chosen. The clock is read only if a check is live, which
            // keeps a message declaring no freshness deterministic (@67shl6c5).
            CheckFreshness(inner.Params, options.MaxAgeSeconds, options.Skew, options.Now);

            var digests = new List<KeyValuePair<string?, byte[]?>>();
            if (CoversBody(items))
            {
                digests.Add(new KeyValuePair<string?, byte[]?>(Header(found, Components.ContentDigest), body));
            }
            // A response binding the request's digest binds a request body only if somebody hashes
            // it (bakobo/fiki#4). A verifier handed no request body cannot, and a verdict that
            // skipped the check would look like one that made it, so that is the caller's mistake.
            if (request != null && BindsRequestDigest(items))
            {
                if (request.BodyRef == null)
                {
                    throw new ArgumentException(
                        "The response covers \"content-digest\";req, so the request body it binds must be supplied in " +
                        "Request.Body to be checked; it was not.");
                }
                digests.Add(new KeyValuePair<string?, byte[]?>(Header(Lowered(request.Headers), Components.ContentDigest), request.BodyRef));
            }
            // Every covered digest is parsed before any is compared, so a malformed one outranks a
            // mismatched one wherever each sits (profile section 9, bakobo/fiki#4).
            var parsed = new List<KeyValuePair<List<KeyValuePair<string, byte[]>>, byte[]?>>();
            foreach (var digest in digests)
            {
                parsed.Add(new KeyValuePair<List<KeyValuePair<string, byte[]>>, byte[]?>(ReadDigest(digest.Key), digest.Value));
            }
            foreach (var digest in parsed)
            {
                CompareDigest(digest.Key, digest.Value);
            }

            var covered = new List<string>();
            foreach (var item in items)
            {
                covered.Add(Components.SpecOf(item));
            }
            return new Verdict(aid, covered.AsReadOnly(), keyId);
        }

        /// <summary>
        /// The profile's request body test: a length above zero, any transfer coding, or content.
        /// Requests only: a response's body is its content, since a HEAD or 304 response carries the
        /// length of a representation it does not send (@2f227n4r).
        /// </summary>
        private static bool RequestHasBody(Dictionary<string, string> found, byte[]? body)
        {
            if (HasContent(body) || found.ContainsKey("transfer-encoding"))
            {
                return true;
            }
            if (!found.TryGetValue("content-length", out var length))
            {
                return false;
            }
            // Fail closed: a length that is not a plain decimal, negative ones included, is not
            // evidence that there is no body.
            // Only SP and HTAB are trimmed (this.i @56qu7gyw), so a length with a CR or any other
            // byte beside its digits is not a plain decimal, and counts as a body.
            length = Components.OwsTrimmed(length);
            var plain = length.Length > 0;
            var zero = true;
            foreach (var c in length)
            {
                plain &= c >= '0' && c <= '9';
                zero &= c == '0';
            }
            return !plain || !zero;
        }

        private static void CheckMinimum(List<SfItem> items, List<SfItem> minimum, bool hasBody, bool requestHadBody)
        {
            var required = new List<SfItem>(minimum);
            if (hasBody)
            {
                required.Add(BodyDigest);
            }
            if (requestHadBody)
            {
                required.Add(RequestDigest);
            }
            foreach (var item in required)
            {
                if (!Components.Contains(items, item))
                {
                    throw new FikiException(
                        FikiErrorKind.InsufficientCoverage,
                        $"The signature does not cover {Components.SpecOf(item)}, which this verifier requires, so it is " +
                        "refused even though it may be valid: a signature over too little is a signature over what an " +
                        "intermediary is free to change.")
                    { Component = Components.SpecOf(item) };
                }
            }
        }

        /// <summary>Enforce the verifier's maximum age, then the signer's expires (profile section 9).</summary>
        private static void CheckFreshness(SfParameters parameters, long? maxAge, long skew, long? now)
        {
            long? expires = parameters.TryGet("expires", out var e) ? e!.Integer : (long?)null;
            long? created = parameters.TryGet("created", out var c) ? c!.Integer : (long?)null;
            if (expires == null && maxAge == null)
            {
                return;
            }
            var stamp = now ?? Clock();

            // In decimal, so a vast max_age or skew cannot overflow the way Python's integers never do.
            if (maxAge != null)
            {
                if (created == null)
                {
                    throw TooOld(
                        "This signature carries no created timestamp, so its age cannot be checked against the " +
                        $"{maxAge}-second limit you asked for.", null, stamp, maxAge.Value);
                }
                if ((decimal)stamp - created.Value > (decimal)maxAge.Value + skew)
                {
                    throw TooOld(
                        $"This signature was created at {created}, which is more than {maxAge} seconds before {stamp}, so " +
                        "it is too old to accept.", created, stamp, maxAge.Value);
                }
                if ((decimal)created.Value - stamp > skew)
                {
                    throw TooOld(
                        $"This signature claims to have been created at {created}, which is in the future relative to " +
                        $"{stamp} by more than the {skew}-second skew allowance.", created, stamp, maxAge.Value);
                }
            }

            if (expires != null && stamp > (decimal)expires.Value + skew)
            {
                throw new FikiException(
                    FikiErrorKind.SignatureExpired,
                    $"This signature expired at {expires} and it is now {stamp}, so the signer has already declared it " +
                    "should not be accepted.")
                { Expires = expires, Now = stamp };
            }
        }

        private static FikiException TooOld(string message, long? created, long now, long maxAge) =>
            new FikiException(FikiErrorKind.SignatureTooOld, message) { Created = created, Now = now, MaxAge = maxAge };

        /// <summary>
        /// Every key check that needs nothing beyond the keyid itself (profile section 9): the key to
        /// verify with and the identity to report when no resolver is needed, or null when the
        /// resolver decides. Either way a keyid that is not well formed is refused here, before the
        /// expected keyid is compared and before any resolver sees it (@5zrf8gjk).
        /// </summary>
        private static byte[]? LocalKey(string? expectedAid, string? keyId, Func<string, byte[]?>? resolve, out string aid)
        {
            if (expectedAid != null)
            {
                var expected = Aids.VerifyingKey(expectedAid);
                aid = Aids.ToAid(expected);
                return expected;
            }
            if (string.IsNullOrEmpty(keyId))
            {
                throw MissingKey();
            }
            if (resolve != null)
            {
                if (Aids.Misspelled(keyId!))
                {
                    throw new FikiException(
                        FikiErrorKind.MalformedKey,
                        $"The keyid \"{keyId}\" is shaped like an AID and is not its canonical spelling, so it is not an AID at all.",
                        keyId: keyId);
                }
                aid = keyId!;
                return null;
            }
            // Strictly, as an AID is decoded: a lenient decoder discards characters outside the
            // alphabet and ignores trailing bits, so a keyid that is not the key's encoding could
            // verify as whatever key it happened to decode to. Only the canonical spelling is a key.
            var wellFormed = keyId!.Length == RawKeyIdLength;
            foreach (var ch in keyId)
            {
                wellFormed &= UrlAlphabet.IndexOf(ch) >= 0;
            }
            if (!wellFormed)
            {
                throw new FikiException(
                    FikiErrorKind.MalformedKey,
                    $"The keyid \"{keyId}\" is not a base64url-encoded 32-byte Ed25519 public key: that is exactly " +
                    $"{RawKeyIdLength} characters from the base64url alphabet, unpadded.",
                    keyId: keyId);
            }
            var raw = Base64Url.Decode(keyId);
            if (Base64Url.Encode(raw) != keyId)
            {
                throw new FikiException(
                    FikiErrorKind.MalformedKey,
                    $"The keyid \"{keyId}\" is not the canonical base64url spelling of any key.",
                    keyId: keyId);
            }
            if (!Aids.IsUsableKey(raw))
            {
                throw Aids.Unusable(keyId);
            }
            aid = Aids.ToAid(raw);
            return raw;
        }

        /// <summary>The resolver's key for a keyid already found well formed, and the keyid it vouched for.</summary>
        private static byte[] Resolved(string keyId, Func<string, byte[]?> resolve, out string aid)
        {
            // The resolver is authoritative: fiki never falls back to decoding the keyid, because a
            // transferable prefix that embeds a key embeds its INCEPTION key (@6g9zjsv9).
            var resolved = resolve(keyId) ?? throw new FikiException(
                FikiErrorKind.UnknownKey,
                $"No key is known for the keyid \"{keyId}\", so the signature cannot be checked.",
                keyId: keyId);
            if (resolved.Length != KeyLength)
            {
                throw new FikiException(
                    FikiErrorKind.MalformedKey,
                    $"The key resolved for \"{keyId}\" is not a {KeyLength}-byte Ed25519 public key.",
                    keyId: keyId);
            }
            // A small-order key is refused here, in the key's place in section 9's order, rather
            // than attempted: against it a signature anyone can write verifies.
            if (!Aids.IsUsableKey(resolved))
            {
                throw Aids.Unusable(keyId);
            }
            aid = keyId;
            return resolved;
        }

        private static FikiException MissingKey() => new FikiException(
            FikiErrorKind.MissingKey,
            "This signature carries no keyid and no expected AID was supplied, so there is no key to verify it against.");

        /// <summary>
        /// Pull one signature and its input out of the headers, or say what is wrong with them, in
        /// the KERI profile's section 9 order: absence before malformation, the Signature header
        /// before Signature-Input, the members' shape before the label count.
        /// </summary>
        private static SfInnerList Read(Dictionary<string, string> found, out byte[] signature, bool requireKeyId, bool requireCreated)
        {
            var rawSignature = Header(found, "signature");
            var rawInput = Header(found, "signature-input");
            if (string.IsNullOrEmpty(rawSignature))
            {
                throw new FikiException(FikiErrorKind.MissingSignature, "This message has no Signature header, so there is nothing to verify.");
            }
            if (string.IsNullOrEmpty(rawInput))
            {
                throw new FikiException(
                    FikiErrorKind.MissingSignatureInput,
                    "This message has no Signature-Input header, so there is no way to know which components a signature would cover.");
            }

            var signatures = Parse(rawSignature, "Signature", FikiErrorKind.MalformedSignature);
            foreach (var member in signatures)
            {
                // Draft 6 of the KERI profile would call this malformed-signature, since such a header
                // is neither mode's form; the kind stays the one the shared vectors pin (@2f227n4r).
                if (!(member.Value is SfItem item && item.Value.Type == SfType.ByteSequence))
                {
                    throw new FikiException(
                        FikiErrorKind.MalformedSignatureValue,
                        "RFC 9421 carries a signature as an RFC 8941 byte sequence, wrapped in colons; this Signature header carries something else.");
                }
            }
            var inputs = Parse(rawInput, "Signature-Input", FikiErrorKind.MalformedSignatureInput);
            foreach (var member in inputs)
            {
                CheckInput(member.Value, requireKeyId, requireCreated);
            }

            if (inputs.Count != 1 || signatures.Count != 1)
            {
                throw new FikiException(
                    FikiErrorKind.MalformedSignatureLabel,
                    $"fiki verifies a message carrying exactly one signature; this one declares {inputs.Count} in " +
                    $"Signature-Input and {signatures.Count} in Signature.");
            }
            KeyValuePair<string, SfMember> only = default;
            foreach (var member in inputs)
            {
                only = member;
            }
            if (!signatures.TryGet(only.Key, out var labelled))
            {
                throw new FikiException(
                    FikiErrorKind.MissingSignatureLabel,
                    $"The Signature header carries no entry labelled \"{only.Key}\", so the covered components describe a signature that is not here.")
                { Label = only.Key };
            }

            signature = ((SfItem)labelled!).Value.Bytes;
            if (signature.Length != SignatureLength)
            {
                throw new FikiException(
                    FikiErrorKind.MalformedSignatureValue,
                    "RFC 9421 carries an Ed25519 signature as a 64-byte RFC 8941 byte sequence, wrapped in colons; this one is something else.");
            }
            return (SfInnerList)only.Value;
        }

        /// <summary>Refuse a Signature-Input member fiki would otherwise have to guess about.</summary>
        private static void CheckInput(SfMember member, bool requireKeyId, bool requireCreated)
        {
            if (!(member is SfInnerList list))
            {
                throw new FikiException(
                    FikiErrorKind.MalformedSignatureInput,
                    "A Signature-Input member is a parenthesized list of covered components; this one is a single value.");
            }
            foreach (var item in list.Items)
            {
                if (item.Value.Type != SfType.String)
                {
                    throw new FikiException(
                        FikiErrorKind.MalformedSignatureInput,
                        $"Every covered component is named by a quoted string; {item.Serialize()} is not one.");
                }
                if (!item.Value.Text.StartsWith("@", StringComparison.Ordinal) && item.Value.Text != PyText.Lower(item.Value.Text))
                {
                    throw new FikiException(
                        FikiErrorKind.MalformedSignatureInput,
                        $"The covered field {item.Serialize()} is not lowercase, and RFC 9421 section 2.1 requires field names " +
                        "in the covered list to be lowercased by the signer.");
                }
            }
            if (requireKeyId && !list.Params.Contains("keyid"))
            {
                // Here rather than when the key is resolved: keyid is REQUIRED, so its absence belongs
                // with the other defects of Signature-Input, ahead of the covered list (@2f227n4r).
                throw MissingKey();
            }
            if (requireCreated && !list.Params.Contains("keyid"))
            {
                // Under a minimum, which is how a caller applies the KERI profile, keyid is REQUIRED
                // even when an expected AID names the key (the profile's section 4; the ruling from
                // the review of bakobo/fiki#8). MissingKey, fiki-py's kind for an absent keyid.
                throw new FikiException(
                    FikiErrorKind.MissingKey,
                    "This signature carries no keyid, which the verifier's policy requires even though the key was named.");
            }
            if (requireCreated && !list.Params.Contains("created"))
            {
                // Only under a minimum, which is how a caller applies the KERI profile, where created is
                // REQUIRED. RFC 9421 makes it optional, and without a minimum it stays so (@7p9s3g9k).
                throw new FikiException(
                    FikiErrorKind.MalformedSignatureInput,
                    "This signature carries no created timestamp, which the verifier's policy requires.");
            }
            foreach (var parameter in list.Params)
            {
                var at = Array.IndexOf(ParamNames, parameter.Key);
                if (at < 0)
                {
                    throw new FikiException(
                        FikiErrorKind.MalformedSignatureInput,
                        $"The signature parameter \"{parameter.Key}\" is not one fiki understands; it accepts {string.Join(", ", ParamNames)}.");
                }
                var integer = at < 2;
                if (parameter.Value.Type != (integer ? SfType.Integer : SfType.String))
                {
                    throw new FikiException(
                        FikiErrorKind.MalformedSignatureInput,
                        $"The signature parameter \"{parameter.Key}\" must be {(integer ? "an integer" : "a quoted string")}.");
                }
                if (integer && parameter.Value.Integer < 0)
                {
                    // A time before 1970 is no time a signer could have meant (this.i @524c8qgv).
                    // Zero is a time, and is accepted for both.
                    throw new FikiException(
                        FikiErrorKind.MalformedSignatureInput,
                        $"The signature parameter \"{parameter.Key}\" is {parameter.Value.Integer.ToString(CultureInfo.InvariantCulture)}, and a UNIX time is not negative.");
                }
            }
        }

        /// <summary>
        /// Parse one signature-related header, bounded before it is read (@5zrf8gjk, ticks 65q7 and
        /// 6mhg): its size in bytes as received, before any trimming, then the members, inner-list
        /// items and parameters of what parsed. Over any bound is the header's malformed kind.
        /// </summary>
        private static SfDictionary Parse(string? raw, string name, FikiErrorKind kind)
        {
            SfDictionary parsed;
            try
            {
                raw = raw ?? throw new FormatException("There is no header.");
                var size = System.Text.Encoding.UTF8.GetByteCount(raw);
                if (size > HttpSignatures.MaxFieldBytes)
                {
                    throw new FikiException(kind, $"The {name} header is {size} bytes, and fiki reads one of at most {HttpSignatures.MaxFieldBytes}.");
                }
                parsed = Sfv.ParseDictionary(raw);
            }
            catch (FormatException)
            {
                throw new FikiException(kind, $"I could not parse the {name} header; RFC 9421 spells it as an RFC 8941 dictionary.");
            }
            CheckCounts(parsed, name, kind);
            return parsed;
        }

        private static void CheckCounts(SfDictionary parsed, string name, FikiErrorKind kind)
        {
            FikiException Refuse(string what, int limit) => new FikiException(
                kind, $"The {name} header has more than {limit} {what}, which is more than fiki reads from any honest signer.");

            if (parsed.Count > HttpSignatures.MaxDictionaryMembers)
            {
                throw Refuse("members", HttpSignatures.MaxDictionaryMembers);
            }
            foreach (var member in parsed)
            {
                var items = member.Value is SfInnerList list ? list.Items : new SfItem[0];
                if (items.Count > HttpSignatures.MaxInnerListItems)
                {
                    throw Refuse("items in one inner list", HttpSignatures.MaxInnerListItems);
                }
                foreach (var item in new List<SfMember>(items) { member.Value })
                {
                    if (item.Params.Count > HttpSignatures.MaxParameters)
                    {
                        throw Refuse("parameters on one item", HttpSignatures.MaxParameters);
                    }
                }
            }
        }

        /// <summary>
        /// Parse a Content-Digest into the members fiki computes, or refuse it as MalformedDigest.
        /// Separate from the comparison so that two covered digests are both parsed before either is
        /// hashed: section 9 of the KERI profile puts malformed-digest first.
        /// </summary>
        private static List<KeyValuePair<string, byte[]>> ReadDigest(string? header)
        {
            var recognized = new List<KeyValuePair<string, byte[]>>();
            foreach (var member in Parse(header, "Content-Digest", FikiErrorKind.MalformedDigest))
            {
                if (!IsDigestAlgorithm(member.Key))
                {
                    continue;
                }
                if (!(member.Value is SfItem item && item.Value.Type == SfType.ByteSequence))
                {
                    throw new FikiException(
                        FikiErrorKind.MalformedDigest,
                        $"The {member.Key} Content-Digest is not an RFC 8941 byte sequence, so it cannot be compared with anything.");
                }
                recognized.Add(new KeyValuePair<string, byte[]>(member.Key, item.Value.Bytes));
            }
            if (recognized.Count == 0)
            {
                throw new FikiException(
                    FikiErrorKind.MalformedDigest,
                    "The Content-Digest header names no algorithm fiki computes; it computes sha-256 and sha-512.");
            }
            return recognized;
        }

        /// <summary>
        /// Recompute the digest over the body actually received (@2hwvpm42). The header is covered
        /// by the signature, but a covered digest only attests to a body nobody hashed until
        /// somebody hashes it.
        /// </summary>
        private static void CompareDigest(List<KeyValuePair<string, byte[]>> recognized, byte[]? body)
        {
            if (body == null)
            {
                throw new FikiException(
                    FikiErrorKind.DigestMismatch,
                    "The signature covers content-digest, but no body was supplied to check it against, so the body is unverified.");
            }
            foreach (var digest in recognized)
            {
                if (!ByteArrays.Equal(Hash(digest.Key, body), digest.Value))
                {
                    throw new FikiException(
                        FikiErrorKind.DigestMismatch,
                        $"The body does not match its {digest.Key} Content-Digest, so the body is not the one that was signed.");
                }
            }
        }
    }
}
