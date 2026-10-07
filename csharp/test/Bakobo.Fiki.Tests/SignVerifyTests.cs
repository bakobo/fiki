using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The high-level sign and verify surface, and the whole of @2hwvpm42, mirroring
    /// py/tests/test_sign_verify.py. The tamper cases are the load-bearing rows: each changes
    /// something an attacker would change and asserts that verification refuses.
    /// </summary>
    public class SignVerifyTests
    {
        internal static readonly Key TheKey = Key.FromSeed(Bytes.Range(0, 32));
        private const string Url = "https://api.example.com/things?limit=1&sort=name";
        private static readonly byte[] Body = Bytes.Utf8("{\"hello\": \"world\"}");

        /// <summary>A request as a verifier receives it: method, URL, body, and headers.</summary>
        internal sealed class Message
        {
            public string Method = "POST";
            public string Url = "";
            public byte[]? Body;
            public Dictionary<string, string> Headers = new Dictionary<string, string>();

            public Verdict Verify(VerifyOptions? options = null) =>
                HttpSignatures.VerifyRequest(Method, Url, Headers, (options ?? VerifyOptions.DecliningFreshness()).WithBody(Body));

            public FikiException Refused(VerifyOptions? options = null) =>
                Assert.Throws<FikiException>(() => Verify(options));
        }

        internal static Message Signed(Key? key = null, string method = "POST", string url = Url,
            Dictionary<string, string>? headers = null, byte[]? body = null, bool noBody = false,
            IEnumerable<string>? covered = null, long? created = null, long? expires = null, string? keyId = null)
        {
            var given = new Dictionary<string, string>(headers ?? new Dictionary<string, string>());
            var sent = noBody ? null : body ?? Body;
            var message = new Message { Method = method, Url = url, Body = sent, Headers = new Dictionary<string, string>(given) };
            foreach (var header in HttpSignatures.SignRequest(key ?? TheKey, method, url, given, sent, covered, created, expires: expires, keyId: keyId))
            {
                message.Headers[header.Key] = header.Value;
            }
            return message;
        }

        internal static string KeyIdOf(Message message) =>
            message.Headers["Signature-Input"].Split(new[] { "keyid=\"" }, StringSplitOptions.None)[1].Split('"')[0];

        [Fact]
        public void ASignedRequestVerifiesAndNamesTheSigner() => Assert.Equal(TheKey.Aid, Signed().Verify().Aid);

        [Fact]
        public void TheDefaultCoveredSetBindsMethodAuthorityPathAndQuery()
        {
            var covered = Signed().Verify().Covered;
            Assert.All(HttpSignatures.DefaultCovered, c => Assert.Contains(c, covered));
        }

        [Fact]
        public void TheKeyidCarriesTheRawKeyRatherThanTheAid()
        {
            // @7xrx5evg: heti's vanilla dialect decodes keyid as 32 raw bytes, so fiki emits that form.
            var keyId = KeyIdOf(Signed());
            Assert.Equal(43, keyId.Length);
            Assert.Equal(Key.VerifyingKey(TheKey.Aid).ToBytes(), Bytes.FromB64Url(keyId));
        }

        [Fact]
        public void ABodyIsDigestedAndTheDigestIsCovered()
        {
            var message = Signed();
            Assert.True(message.Headers.ContainsKey("Content-Digest"));
            Assert.Contains("content-digest", message.Verify().Covered);
        }

        [Fact]
        public void TheReturnedHeadersAreTheSignatureHeadersAndTheDigestInThatOrder()
        {
            var headers = HttpSignatures.SignRequest(TheKey, "POST", Url, body: Body, created: 1700000000);
            Assert.Equal(new[] { "Signature-Input", "Signature", "Content-Digest" }, headers.Keys.ToArray());
            Assert.StartsWith("sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\");created=1700000000;alg=\"ed25519\";keyid=\"",
                headers["Signature-Input"], StringComparison.Ordinal);
        }

        [Fact]
        public void SigningABodyWithACoveredSetThatExcludesTheDigestIsRefused()
        {
            // The refusal @2hwvpm42 turns on. A warning here would be read by nobody.
            var caught = Assert.Throws<FikiException>(() =>
                HttpSignatures.SignRequest(TheKey, "POST", Url, body: Body, covered: new[] { "@method", "@path" }));
            Assert.Equal(FikiErrorKind.UncoveredBody, caught.Kind);
        }

        [Fact]
        public void ABodylessRequestNeedsNoDigest()
        {
            var message = Signed(noBody: true);
            Assert.False(message.Headers.ContainsKey("Content-Digest"));
            Assert.Equal(TheKey.Aid, message.Verify().Aid);
        }

        [Fact]
        public void TheMethodIsSignedExactlyAsGiven()
        {
            // @22g0xkr8: 'post' stays 'post', and does not verify as 'POST'.
            var message = Signed(method: "post");
            Assert.Equal(TheKey.Aid, message.Verify().Aid);
            message.Method = "POST";
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused().Kind);
        }

        // --- the tampering that heti's KERI dialect cannot detect ---

        [Fact]
        public void ARewrittenQueryStringIsRefused()
        {
            var message = Signed();
            message.Url = "https://api.example.com/things?limit=1000000&sort=name";
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused().Kind);
        }

        [Fact]
        public void ARewrittenHostIsRefused()
        {
            var message = Signed();
            message.Url = "https://evil.example.com/things?limit=1&sort=name";
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused().Kind);
        }

        [Fact]
        public void ASwappedBodyIsRefused()
        {
            var message = Signed();
            message.Body = Bytes.Utf8("{\"hello\": \"goodbye\"}");
            Assert.Equal(FikiErrorKind.DigestMismatch, message.Refused().Kind);
        }

        [Fact]
        public void ASwappedBodyWithAMatchingDigestIsStillRefused()
        {
            // The digest header is itself covered, so re-digesting does not rescue the tamper.
            var message = Signed();
            message.Body = Bytes.Utf8("{\"hello\": \"goodbye\"}");
            using (var sha = SHA256.Create())
            {
                message.Headers["Content-Digest"] = "sha-256=:" + Convert.ToBase64String(sha.ComputeHash(message.Body)) + ":";
            }
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused().Kind);
        }

        [Fact]
        public void ACoveredDigestWithNoBodyToCheckItAgainstIsRefused()
        {
            var message = Signed();
            message.Body = null;
            Assert.Equal(FikiErrorKind.DigestMismatch, message.Refused().Kind);
        }

        [Fact]
        public void ARewrittenMethodIsRefused()
        {
            var message = Signed();
            message.Method = "DELETE";
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused().Kind);
        }

        [Fact]
        public void ASignatureFromADifferentKeyIsRefused()
        {
            var message = Signed();
            message.Headers["Signature"] = Signed(key: Key.FromSeed(Bytes.Range(1, 32))).Headers["Signature"];
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused().Kind);
        }

        // --- preregistration, which is the case an AID exists for ---

        [Fact]
        public void AnExpectedAidIsAuthoritativeOverTheInlineKeyid() =>
            Assert.Equal(TheKey.Aid, Signed().Verify(VerifyOptions.DecliningFreshness().WithExpectedAid(TheKey.Aid)).Aid);

        [Fact]
        public void ARequestSignedBySomeoneOtherThanTheExpectedAidIsRefused()
        {
            var stranger = Key.FromSeed(Bytes.Range(1, 32)).Aid;
            Assert.Equal(FikiErrorKind.SignatureMismatch,
                Signed().Refused(VerifyOptions.DecliningFreshness().WithExpectedAid(stranger)).Kind);
        }

        [Fact]
        public void AMalformedExpectedAidIsAMalformedKey() =>
            Assert.Equal(FikiErrorKind.MalformedKey,
                Signed().Refused(VerifyOptions.DecliningFreshness().WithExpectedAid("not-an-aid")).Kind);

        // --- malformed input ---

        [Theory]
        [InlineData("no-signature", FikiErrorKind.MissingSignature)]
        [InlineData("no-signature-input", FikiErrorKind.MissingSignatureInput)]
        [InlineData("empty-signature", FikiErrorKind.MissingSignature)]
        [InlineData("empty-signature-input", FikiErrorKind.MissingSignatureInput)]
        [InlineData("unparsable-input", FikiErrorKind.MalformedSignatureInput)]
        [InlineData("unparsable-signature", FikiErrorKind.MalformedSignature)]
        public void MalformedSignatureHeadersAreRefused(string mangle, FikiErrorKind expected)
        {
            // Each header names its own condition, so a sender can be told which one to fix.
            var message = Signed();
            switch (mangle)
            {
                case "no-signature": message.Headers.Remove("Signature"); break;
                case "no-signature-input": message.Headers.Remove("Signature-Input"); break;
                case "empty-signature": message.Headers["Signature"] = ""; break;
                case "empty-signature-input": message.Headers["Signature-Input"] = ""; break;
                case "unparsable-input": message.Headers["Signature-Input"] = "not a dictionary («"; break;
                default: message.Headers["Signature"] = "sig=:not-base64!:"; break;
            }
            Assert.Equal(expected, message.Refused().Kind);
        }

        [Fact]
        public void TwoSignatureLabelsAreRefused()
        {
            var message = Signed();
            var rest = message.Headers["Signature-Input"].Substring(message.Headers["Signature-Input"].IndexOf('=') + 1);
            message.Headers["Signature-Input"] += ",other=" + rest;
            Assert.Equal(FikiErrorKind.MalformedSignatureLabel, message.Refused().Kind);
        }

        [Fact]
        public void AnAlgorithmOtherThanEd25519IsRefused()
        {
            var message = Signed();
            message.Headers["Signature-Input"] += ";alg=\"rsa-pss-sha512\"";
            var caught = message.Refused();
            Assert.Equal(FikiErrorKind.UnsupportedAlgorithm, caught.Kind);
            Assert.Equal("rsa-pss-sha512", caught.Alg);
        }

        // --- paths a caller reaches by driving fiki rather than accepting its defaults ---

        [Fact]
        public void AnExplicitCoveredSetThatIncludesTheDigestSignsABody()
        {
            var message = Signed(covered: new[] { "@method", "@path", "content-digest" });
            Assert.True(message.Headers.ContainsKey("Content-Digest"));
            Assert.Equal(TheKey.Aid, message.Verify().Aid);
        }

        [Fact]
        public void ACallerSuppliedContentDigestIsUsedRatherThanRecomputed()
        {
            var supplied = new Dictionary<string, string> { { "Content-Digest", HttpSignatures.ContentDigest(Body) } };
            var headers = HttpSignatures.SignRequest(TheKey, "POST", Url, supplied, Body);
            Assert.False(headers.ContainsKey("Content-Digest"));
            var message = Signed(headers: supplied);
            Assert.Equal(supplied["Content-Digest"], message.Headers["Content-Digest"]);
            Assert.Equal(TheKey.Aid, message.Verify().Aid);
        }

        [Fact]
        public void ACallerSuppliedDigestIsFoundWhateverTheCaseOfItsName()
        {
            var supplied = new Dictionary<string, string> { { "content-DIGEST", HttpSignatures.ContentDigest(Body) } };
            Assert.False(HttpSignatures.SignRequest(TheKey, "POST", Url, supplied, Body).ContainsKey("Content-Digest"));
        }

        [Fact]
        public void AContentDigestNamingAnUnknownAlgorithmAlongsideAKnownOneVerifies()
        {
            // RFC 9530 allows several digests; fiki ignores the ones it cannot compute (@7f28p7xk).
            var message = Signed(headers: new Dictionary<string, string> { { "Content-Digest", "sha-1=:AAAA:, " + HttpSignatures.ContentDigest(Body) } });
            Assert.Equal(TheKey.Aid, message.Verify().Aid);
        }

        [Fact]
        public void AContentDigestNamingOnlyAlgorithmsFikiCannotComputeIsRefused()
        {
            // Fail closed: an uncheckable digest is an unchecked body, not a checked one.
            var message = Signed(headers: new Dictionary<string, string> { { "Content-Digest", "sha-1=:AAAA:" } });
            var caught = message.Refused();
            Assert.Equal(FikiErrorKind.MalformedDigest, caught.Kind);
            Assert.Equal("The Content-Digest header names no algorithm fiki computes; it computes sha-256 and sha-512.", caught.Message);
        }

        [Fact]
        public void TheContentDigestOfABodyIsItsSha256()
        {
            Assert.Equal("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", HttpSignatures.ContentDigest(Bytes.Utf8("{\"hello\": \"world\"}")));
        }

        // --- more malformed input ---

        [Fact]
        public void ASignatureLabelledDifferentlyFromItsInputIsRefused()
        {
            var message = Signed();
            message.Headers["Signature"] = "other=" + message.Headers["Signature"].Substring(4);
            var caught = message.Refused();
            Assert.Equal(FikiErrorKind.MissingSignatureLabel, caught.Kind);
            Assert.Equal("sig", caught.Label);
        }

        [Fact]
        public void ASignatureThatIsNotAByteSequenceIsRefused()
        {
            var message = Signed();
            message.Headers["Signature"] = "sig=\"this is a string, not a byte sequence\"";
            Assert.Equal(FikiErrorKind.MalformedSignatureValue, message.Refused().Kind);
        }

        [Fact]
        public void ASignatureWithNoKeyidAndNoExpectedAidIsRefused()
        {
            var message = Signed();
            var input = message.Headers["Signature-Input"];
            message.Headers["Signature-Input"] = input.Substring(0, input.IndexOf(";keyid=", StringComparison.Ordinal)) + ";alg=\"ed25519\"";
            Assert.Equal(FikiErrorKind.MissingKey, message.Refused().Kind);
        }

        [Fact]
        public void AKeyidThatIsNotAKeyIsRefused()
        {
            var message = Signed();
            message.Headers["Signature-Input"] = message.Headers["Signature-Input"].Replace(KeyIdOf(message), "not-a-key");
            var caught = message.Refused();
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
            Assert.Equal("not-a-key", caught.KeyId);
        }

        // --- freshness (this.i @67shl6c5) ---

        private const long SignedAt = 1700000000;

        [Fact]
        public void MaxAgeIsARequiredDecisionRatherThanADefault()
        {
            // Both defaults are wrong, so fiki refuses to pick one: no public constructor exists, and
            // the two factories are the only ways to get options.
            Assert.Empty(typeof(VerifyOptions).GetConstructors());
            Assert.Equal(300, VerifyOptions.MaxAge(300).MaxAgeSeconds);
            Assert.Null(VerifyOptions.DecliningFreshness().MaxAgeSeconds);
        }

        [Fact]
        public void ASignatureWithinMaxAgeVerifies() =>
            Assert.Equal(TheKey.Aid, Signed(created: SignedAt).Verify(VerifyOptions.MaxAge(300).WithNow(SignedAt + 299)).Aid);

        [Fact]
        public void ASignatureOlderThanMaxAgeIsRefused()
        {
            var caught = Signed(created: SignedAt).Refused(VerifyOptions.MaxAge(300).WithNow(SignedAt + 400));
            Assert.Equal(FikiErrorKind.SignatureTooOld, caught.Kind);
            Assert.Equal(SignedAt, caught.Created);
            Assert.Equal(SignedAt + 400, caught.Now);
            Assert.Equal(300, caught.MaxAge);
        }

        [Fact]
        public void MaxAgeNoneDeclinesTheCheckExplicitly() =>
            Assert.Equal(TheKey.Aid, Signed(created: SignedAt).Verify(VerifyOptions.DecliningFreshness().WithNow(SignedAt + 1000000)).Aid);

        [Fact]
        public void ClockSkewIsToleratedSoASecondOfDisagreementIsNotAnAttack() =>
            Assert.Equal(TheKey.Aid, Signed(created: SignedAt).Verify(VerifyOptions.MaxAge(300).WithNow(SignedAt + 303)).Aid);

        [Fact]
        public void TheSkewAllowanceIsAdjustable() =>
            Assert.Equal(FikiErrorKind.SignatureTooOld,
                Signed(created: SignedAt).Refused(VerifyOptions.MaxAge(300).WithSkew(0).WithNow(SignedAt + 301)).Kind);

        [Fact]
        public void ASignatureCreatedInTheFutureBeyondSkewIsRefused() =>
            Assert.Equal(FikiErrorKind.SignatureTooOld,
                Signed(created: SignedAt).Refused(VerifyOptions.MaxAge(300).WithNow(SignedAt - 60)).Kind);

        [Fact]
        public void AnEnormousMaxAgeDoesNotOverflow() =>
            Assert.Equal(TheKey.Aid, Signed(created: SignedAt).Verify(VerifyOptions.MaxAge(long.MaxValue).WithSkew(long.MaxValue).WithNow(SignedAt)).Aid);

        [Fact]
        public void WithoutAnInjectedClockTheRealOneIsRead()
        {
            Assert.Equal(TheKey.Aid, Signed().Verify(VerifyOptions.MaxAge(300)).Aid);
            Assert.Equal(FikiErrorKind.SignatureTooOld, Signed(created: SignedAt).Refused(VerifyOptions.MaxAge(300)).Kind);
        }

        // --- expires: the signer's own declaration, honoured without being asked ---

        [Fact]
        public void ExpiresIsEnforcedEvenWhenMaxAgeIsDeclined()
        {
            var caught = Signed(created: SignedAt, expires: SignedAt + 60)
                .Refused(VerifyOptions.DecliningFreshness().WithNow(SignedAt + 61 + 5));
            Assert.Equal(FikiErrorKind.SignatureExpired, caught.Kind);
            Assert.Equal(SignedAt + 60, caught.Expires);
            Assert.Equal(SignedAt + 66, caught.Now);
        }

        [Fact]
        public void ASignatureBeforeItsExpiryVerifies() =>
            Assert.Equal(TheKey.Aid, Signed(created: SignedAt, expires: SignedAt + 60)
                .Verify(VerifyOptions.DecliningFreshness().WithNow(SignedAt + 30)).Aid);

        [Fact]
        public void ARequestDeclaringNoFreshnessAtAllVerifiesWithoutReadingAClock() =>
            Assert.Equal(TheKey.Aid, Signed(created: SignedAt).Verify().Aid);

        [Fact]
        public void ASignatureWithNoCreatedCannotBeAgedAndIsRefused()
        {
            // RFC 9421 makes created optional, so a foreign signer may omit it. The signature has to
            // be genuinely made that way, because freshness is checked after verification.
            var keyId = Bytes.B64Url(Key.VerifyingKey(TheKey.Aid).ToBytes());
            var input = "(\"@method\" \"@path\");keyid=\"" + keyId + "\"";
            var bas = "\"@method\": GET\n\"@path\": /a\n\"@signature-params\": " + input;
            var headers = new Dictionary<string, string>
            {
                { "Signature-Input", "sig=" + input },
                { "Signature", "sig=:" + Convert.ToBase64String(TheKey.Sign(Bytes.Utf8(bas))) + ":" },
            };
            Assert.Equal(TheKey.Aid, HttpSignatures.VerifyRequest("GET", "/a", headers, VerifyOptions.DecliningFreshness()).Aid);
            var caught = Assert.Throws<FikiException>(() =>
                HttpSignatures.VerifyRequest("GET", "/a", headers, VerifyOptions.MaxAge(300).WithNow(SignedAt)));
            Assert.Equal(FikiErrorKind.SignatureTooOld, caught.Kind);
            Assert.Null(caught.Created);
        }

        // --- the raw keyid is decoded strictly (bakobo/fiki#4 review) ---

        public static IEnumerable<object[]> LenientKeyIds()
        {
            var k = Bytes.B64Url(Key.VerifyingKey(TheKey.Aid).ToBytes());
            yield return new object[] { k + "!" };
            yield return new object[] { k.Substring(0, 10) + " " + k.Substring(10) };
            yield return new object[] { k + "=" };
            yield return new object[] { k.Substring(0, 10) + "+" + k.Substring(11) };
            yield return new object[] { k.Substring(0, k.Length - 1) };
            yield return new object[] { k.Substring(0, k.Length - 1) + (char)(k[k.Length - 1] + 1) };
        }

        [Theory]
        [MemberData(nameof(LenientKeyIds))]
        public void AKeyidThatOnlyDecodesLenientlyToTheKeyIsRefused(string keyId)
        {
            // A lenient decoder discards what it does not understand, so a keyid that is not the
            // key's encoding could otherwise verify as the key it happens to decode to.
            Assert.Equal(FikiErrorKind.MalformedKey, Signed(keyId: keyId).Refused().Kind);
        }

        [Fact]
        public void ARawKeyidThatIsNotACanonicalPointIsAMalformedKey()
        {
            // y = 2^255 - 1 is not below p, so this is no canonical encoding of any point. fiki-py
            // hands such bytes to OpenSSL and reports the failed verification as a mismatch; this
            // port refuses the key itself, with small-order keys (SmallOrderTests).
            var keyId = Bytes.B64Url(Enumerable.Repeat((byte)0xff, 31).Concat(new byte[] { 0x7f }).ToArray());
            Assert.Equal(FikiErrorKind.MalformedKey, Signed(keyId: keyId).Refused().Kind);
        }
    }
}
