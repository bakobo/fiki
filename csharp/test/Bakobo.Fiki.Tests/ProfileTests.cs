using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// What the KERI profile of RFC 9421 asks of a verifier (this.i @7f28p7xk), mirroring
    /// py/tests/test_profile.py: method case, every recognized digest, caller-chosen keyids with an
    /// authoritative resolver, responses bound to their request with req, the wire-side refusals,
    /// an optional minimum covered set, and the profile's section 9 refusal order.
    /// </summary>
    public class ProfileTests
    {
        private static readonly Key TheKey = Key.FromSeed(Bytes.Range(0, 32));
        private static readonly Key Other = Key.FromSeed(Bytes.Range(1, 32));
        private const string Url = "https://keria.example.com/identifiers?type=rot";
        private static readonly byte[] Body = Bytes.Utf8("{\"hello\": \"world\"}");
        private const long At = 1700000000;

        private static byte[] Raw(Key key) => Key.VerifyingKey(key.Aid).ToBytes();

        private static string Cesr(char code, byte[] raw) => Aids.Qb64(code, raw);

        private static byte[] Sha256(byte[] data)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(data);
        }

        private static byte[] Sha512(byte[] data)
        {
            using var sha = SHA512.Create();
            return sha.ComputeHash(data);
        }

        private static readonly string Aid = Cesr('E', Sha256(Bytes.Utf8("a transferable AID")));

        private static Func<string, byte[]?> Table(params (string KeyId, byte[] Raw)[] entries) =>
            keyId => entries.Where(e => e.KeyId == keyId).Select(e => e.Raw).FirstOrDefault();

        private static readonly IReadOnlyList<string> Minimum = HttpSignatures.RequestMinimum;

        private sealed class Msg
        {
            public string Method = "POST";
            public string Url = ProfileTests.Url;
            public byte[]? Body;
            public Dictionary<string, string> Headers = new Dictionary<string, string>();

            public Verdict Verify(Func<VerifyOptions, VerifyOptions>? with = null) =>
                HttpSignatures.VerifyRequest(Method, Url, Headers, (with ?? (o => o))(VerifyOptions.DecliningFreshness().WithBody(Body)));

            public FikiException Refused(Func<VerifyOptions, VerifyOptions>? with = null) =>
                Assert.Throws<FikiException>(() => Verify(with));

            public Msg Mangle(string old, string replacement)
            {
                Assert.Contains(old, Headers["Signature-Input"]);
                Headers["Signature-Input"] = Headers["Signature-Input"].Replace(old, replacement);
                return this;
            }

            public string KeyId => Headers["Signature-Input"].Split(new[] { "keyid=\"" }, StringSplitOptions.None)[1].Split('"')[0];
        }

        private static Msg Sign(Key? key = null, string method = "POST", string url = Url, Dictionary<string, string>? headers = null,
            byte[]? body = null, bool noBody = false, IEnumerable<string>? covered = null, string? keyId = null,
            long? expires = null, IEnumerable<string>? minimum = null)
        {
            var given = headers ?? new Dictionary<string, string>();
            var sent = noBody ? null : body ?? Body;
            var message = new Msg { Method = method, Url = url, Body = sent, Headers = new Dictionary<string, string>(given) };
            foreach (var h in HttpSignatures.SignRequest(key ?? TheKey, method, url, given, sent, covered, At, expires: expires, keyId: keyId, minimum: minimum))
            {
                message.Headers[h.Key] = h.Value;
            }
            return message;
        }

        // --- @method is the method as sent (@22g0xkr8, RFC 9421 section 2.2.1) ---

        [Fact]
        public void TheMethodIsNotUppercasedInTheBase() =>
            Assert.Equal("\"@method\": post", Bytes.Text(HttpSignatures.SignatureBase("post", Url, BaseTests.H(), new[] { "@method" }, At, "k")).Split('\n')[0]);

        [Fact]
        public void ARequestSignedWithALowercaseMethodDoesNotVerifyAsUppercase()
        {
            var message = Sign(method: "post");
            Assert.Equal(TheKey.Aid, message.Verify().Aid);
            message.Method = "POST";
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused().Kind);
        }

        // --- Content-Digest: every recognized member must match (RFC 9530) ---

        [Fact]
        public void TwoRecognizedDigestsMustBothMatch()
        {
            var bad512 = Convert.ToBase64String(Sha512(Bytes.Utf8("other")));
            var message = Sign(headers: new Dictionary<string, string> { { "Content-Digest", $"{HttpSignatures.ContentDigest(Body)}, sha-512=:{bad512}:" } });
            var caught = message.Refused();
            Assert.Equal(FikiErrorKind.DigestMismatch, caught.Kind);
            Assert.Equal("The body does not match its sha-512 Content-Digest, so the body is not the one that was signed.", caught.Message);
        }

        [Fact]
        public void TwoRecognizedDigestsThatBothMatchVerify()
        {
            var good512 = Convert.ToBase64String(Sha512(Body));
            var message = Sign(headers: new Dictionary<string, string> { { "Content-Digest", $"sha-512=:{good512}:, {HttpSignatures.ContentDigest(Body)}" } });
            Assert.Equal(TheKey.Aid, message.Verify().Aid);
        }

        [Fact]
        public void ARecognizedDigestThatIsNotAByteSequenceIsMalformed() =>
            Assert.Equal(FikiErrorKind.MalformedDigest,
                Sign(headers: new Dictionary<string, string> { { "Content-Digest", "sha-256=\"not bytes\"" } }).Refused().Kind);

        [Fact]
        public void ARecognizedDigestThatIsAnInnerListIsMalformed() =>
            Assert.Equal(FikiErrorKind.MalformedDigest,
                Sign(headers: new Dictionary<string, string> { { "Content-Digest", "sha-256=(:AAAA:)" } }).Refused().Kind);

        [Fact]
        public void AnUnparsableDigestIsMalformedEvenWhenNoBodyWasSupplied()
        {
            // Section 9 puts malformed-digest before digest-mismatch.
            var message = Sign(headers: new Dictionary<string, string> { { "Content-Digest", "((((" } });
            message.Body = null;
            Assert.Equal(FikiErrorKind.MalformedDigest, message.Refused().Kind);
        }

        // --- caller-chosen keyid and an authoritative resolver (@6g9zjsv9) ---

        [Fact]
        public void ACallerMaySignWithAnAidAsTheKeyid() =>
            Assert.Contains($"keyid=\"{Aid}\"", Sign(keyId: Aid).Headers["Signature-Input"]);

        [Fact]
        public void AResolverSuppliesTheKeyForATransferableAid()
        {
            var verdict = Sign(keyId: Aid).Verify(o => o.WithResolver(Table((Aid, Raw(TheKey)))));
            Assert.Equal(Aid, verdict.Aid);
            Assert.Equal(Aid, verdict.KeyId);
        }

        [Fact]
        public void WithoutAResolverTheVerdictStillReportsTheRawKeyid()
        {
            var verdict = Sign().Verify();
            Assert.Equal(TheKey.Aid, verdict.Aid);
            Assert.Equal(Bytes.B64Url(Raw(TheKey)), verdict.KeyId);
        }

        [Fact]
        public void AKeyidTheResolverDoesNotKnowIsAnUnknownKey()
        {
            var caught = Sign(keyId: Aid).Refused(o => o.WithResolver(Table()));
            Assert.Equal(FikiErrorKind.UnknownKey, caught.Kind);
            Assert.Equal(Aid, caught.KeyId);
        }

        [Fact]
        public void AResolverReturningSomethingOtherThan32BytesIsAMalformedKey() =>
            Assert.Equal(FikiErrorKind.MalformedKey, Sign(keyId: Aid).Refused(o => o.WithResolver(_ => Bytes.Utf8("short"))).Kind);

        [Fact]
        public void AResolverMayRefuseAMalformedKeyidItself()
        {
            var caught = Sign(keyId: "not-an-aid").Refused(o => o.WithResolver(k =>
                throw new FikiException(FikiErrorKind.MalformedKey, $"{k} is not an AID.", keyId: k)));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
            Assert.Equal("not-an-aid", caught.KeyId);
        }

        [Fact]
        public void ADPrefixedKeyidIsNeverDecodedAsAKeyWhenAResolverIsSupplied()
        {
            // Profile R1: D... embeds the inception key, so decoding it would undo pre-rotation.
            var inception = Cesr('D', Raw(TheKey));
            Assert.Equal(FikiErrorKind.SignatureMismatch, Sign(keyId: inception).Refused(o => o.WithResolver(Table((inception, Raw(Other))))).Kind);
            Assert.Equal(inception, Sign(key: Other, keyId: inception).Verify(o => o.WithResolver(Table((inception, Raw(Other))))).Aid);
        }

        [Fact]
        public void AResolverWithNoKeyidToResolveIsAMissingKey() =>
            Assert.Equal(FikiErrorKind.MissingKey,
                Sign(keyId: Aid).Mangle($";keyid=\"{Aid}\"", "").Refused(o => o.WithResolver(Table((Aid, Raw(TheKey))))).Kind);

        [Fact]
        public void ExpectedAidAndAResolverTogetherAreAProgrammingError() =>
            Assert.Throws<ArgumentException>(() => Sign().Verify(o => o.WithResolver(Table()).WithExpectedAid(TheKey.Aid)));

        // --- component identifiers with parameters ---

        [Fact]
        public void ACallerMayNameComponentsInTheirSerializedForm() =>
            Assert.Equal(new[] { "@method", "@path", "@query", "content-digest" },
                Sign(covered: new[] { "\"@method\"", "\"@PATH\"", "@query", "\"content-digest\"" }).Verify().Covered);

        [Fact]
        public void SigningADuplicateComponentIsRefused() =>
            Assert.Equal(FikiErrorKind.DuplicateComponent,
                Assert.Throws<FikiException>(() => Sign(covered: new[] { "@method", "@method", "content-digest" })).Kind);

        // --- responses (RFC 9421 section 2.4) ---

        private static readonly Request TheRequest = new Request("POST", Url,
            new Dictionary<string, string> { { "Content-Digest", HttpSignatures.ContentDigest(Body) } }, Body);

        private static readonly byte[] ResponseBody = Bytes.Utf8("{\"done\": true}");

        private static Dictionary<string, string> Respond(Key? key = null, int status = 200, Request? request = null, bool noRequest = false,
            Dictionary<string, string>? headers = null, byte[]? body = null, bool noBody = false, IEnumerable<string>? covered = null,
            string? keyId = null, IEnumerable<string>? minimum = null)
        {
            var given = headers ?? new Dictionary<string, string>();
            var result = new Dictionary<string, string>(given);
            foreach (var h in HttpSignatures.SignResponse(key ?? TheKey, status, noRequest ? null : request ?? TheRequest, given,
                noBody ? null : body ?? ResponseBody, covered, At, keyId: keyId, minimum: minimum))
            {
                result[h.Key] = h.Value;
            }
            return result;
        }

        private static Verdict Check(Dictionary<string, string> headers, int status = 200, byte[]? body = null, bool noBody = false,
            Request? request = null, bool noRequest = false, Func<VerifyOptions, VerifyOptions>? with = null)
        {
            var options = VerifyOptions.DecliningFreshness().WithBody(noBody ? null : body ?? ResponseBody);
            if (!noRequest)
            {
                options = options.WithRequest(request ?? TheRequest);
            }
            return HttpSignatures.VerifyResponse(status, headers, (with ?? (o => o))(options));
        }

        private static FikiException CheckRefused(Dictionary<string, string> headers, int status = 200, byte[]? body = null, bool noBody = false,
            Request? request = null, bool noRequest = false, Func<VerifyOptions, VerifyOptions>? with = null) =>
            Assert.Throws<FikiException>(() => Check(headers, status, body, noBody, request, noRequest, with));

        [Fact]
        public void ASignedResponseVerifiesAndBindsItsRequest()
        {
            var verdict = Check(Respond());
            Assert.Equal(TheKey.Aid, verdict.Aid);
            Assert.Equal(new[] { "@status", "\"@method\";req", "\"@path\";req", "\"@query\";req", "content-digest", "\"content-digest\";req" }, verdict.Covered);
        }

        [Fact]
        public void AResponseSignedWithNoHeadersOrTimestampGivenIsStampedNow()
        {
            var headers = HttpSignatures.SignResponse(TheKey, 204);
            Assert.Equal(new[] { "Signature-Input", "Signature" }, headers.Keys.ToArray());
            var verdict = HttpSignatures.VerifyResponse(204, headers, VerifyOptions.MaxAge(60));
            Assert.Equal(new[] { "@status" }, verdict.Covered);
        }

        [Fact]
        public void AnAlteredStatusIsRefused() => Assert.Equal(FikiErrorKind.SignatureMismatch, CheckRefused(Respond(), status: 201).Kind);

        [Fact]
        public void ASwappedResponseBodyIsRefused() =>
            Assert.Equal(FikiErrorKind.DigestMismatch, CheckRefused(Respond(), body: Bytes.Utf8("{\"done\": false}")).Kind);

        [Fact]
        public void AResponseCheckedAgainstADifferentRequestIsRefused()
        {
            var other = new Request("POST", "https://keria.example.com/other?type=rot", TheRequest.Headers, Body);
            Assert.Equal(FikiErrorKind.SignatureMismatch, CheckRefused(Respond(), request: other).Kind);
        }

        [Fact]
        public void AResponseWithNoRequestCoversOnlyItsOwnComponents() =>
            Assert.Equal(new[] { "@status", "content-digest" }, Check(Respond(noRequest: true), noRequest: true).Covered);

        [Fact]
        public void ABodylessResponseToABodylessRequestCoversNoDigest()
        {
            var get = new Request("GET", Url);
            Assert.Equal(new[] { "@status", "\"@method\";req", "\"@path\";req", "\"@query\";req" },
                Check(Respond(request: get, noBody: true), request: get, noBody: true).Covered);
        }

        [Fact]
        public void SigningAResponseBodyWithoutItsDigestIsRefused() =>
            Assert.Equal(FikiErrorKind.UncoveredBody, Assert.Throws<FikiException>(() => Respond(covered: new[] { "@status" })).Kind);

        [Fact]
        public void AReqComponentWithNoRequestToReadItFromIsMissing() =>
            Assert.Equal(FikiErrorKind.MissingComponent, Assert.Throws<FikiException>(() =>
                Respond(noRequest: true, covered: new[] { "@status", HttpSignatures.Req("@path"), "content-digest" })).Kind);

        [Fact]
        public void VerifyingAReqComponentWithNoRequestIsMissing() =>
            Assert.Equal(FikiErrorKind.MissingComponent, CheckRefused(Respond(), noRequest: true).Kind);

        [Fact]
        public void AReqFieldTheRequestLacksIsMissing() =>
            Assert.Equal(FikiErrorKind.MissingComponent, Assert.Throws<FikiException>(() =>
                Respond(request: new Request("POST", Url), covered: new[] { "@status", HttpSignatures.Req("content-digest"), "content-digest" })).Kind);

        // --- the covered list, as received ---

        [Theory]
        [InlineData("\"@method\";sf")]
        [InlineData("\"@method\";req")]
        [InlineData("\"@status\"")]
        [InlineData("\"@target-uri\"")]
        public void AnUnsupportedComponentInARequestIsRefusedNotDropped(string covered) =>
            Assert.Equal(FikiErrorKind.UnsupportedComponent, Sign().Mangle("\"@method\"", covered).Refused().Kind);

        [Theory]
        [InlineData("\"@status\"", "\"@status\";req")]
        [InlineData("\"@path\";req", "\"@path\"")]
        [InlineData("\"@path\";req", "\"@path\";req=?0")]
        [InlineData("\"@path\";req", "\"@path\";req;bs")]
        public void AnUnsupportedComponentInAResponseIsRefused(string old, string replacement)
        {
            var headers = Respond();
            headers["Signature-Input"] = headers["Signature-Input"].Replace(old, replacement);
            Assert.Equal(FikiErrorKind.UnsupportedComponent, CheckRefused(headers).Kind);
        }

        [Fact]
        public void ADuplicateComponentIsRefused() =>
            Assert.Equal(FikiErrorKind.DuplicateComponent, Sign().Mangle("\"@path\"", "\"@path\" \"@path\"").Refused().Kind);

        [Fact]
        public void ADuplicateIsFoundWhateverTheParameterOrderAndBeforeItIsUnsupported()
        {
            var headers = Respond();
            headers["Signature-Input"] = headers["Signature-Input"].Replace("\"content-digest\";req", "\"content-digest\";req;sf \"content-digest\";sf;req");
            Assert.Equal(FikiErrorKind.DuplicateComponent, CheckRefused(headers).Kind);
        }

        // --- Signature-Input, as received ---

        [Theory]
        [InlineData("\"content-digest\"", "\"Content-Digest\"")]
        [InlineData(";created=1700000000", ";created=1700000000;context=\"x\"")]
        [InlineData(";created=1700000000", ";created=\"soon\"")]
        [InlineData(";created=1700000000", ";created=?1")]
        [InlineData("alg=\"ed25519\"", "alg=ed25519")]
        [InlineData("\"@path\"", "path")]
        [InlineData("\"@path\"", "%\"@path\"")]
        public void AMalformedSignatureInputMemberIsRefused(string old, string replacement) =>
            Assert.Equal(FikiErrorKind.MalformedSignatureInput, Sign().Mangle(old, replacement).Refused().Kind);

        [Fact]
        public void ASignatureInputMemberThatIsNotAnInnerListIsRefused()
        {
            var message = Sign();
            message.Headers["Signature-Input"] = "sig=\"not a list\"";
            Assert.Equal(FikiErrorKind.MalformedSignatureInput, message.Refused().Kind);
        }

        [Fact]
        public void TwoLabelsInTheSignatureHeaderAreMalformed()
        {
            var message = Sign();
            message.Headers["Signature"] += ", other=" + message.Headers["Signature"].Substring(4);
            Assert.Equal(FikiErrorKind.MalformedSignatureLabel, message.Refused().Kind);
        }

        [Fact]
        public void ASignatureThatIsNot64BytesIsAMalformedValue()
        {
            var message = Sign();
            message.Headers["Signature"] = "sig=:" + Convert.ToBase64String(new byte[32]) + ":";
            Assert.Equal(FikiErrorKind.MalformedSignatureValue, message.Refused().Kind);
        }

        [Fact]
        public void ASignatureMemberThatIsAnInnerListOrABareKeyIsAMalformedValue()
        {
            var message = Sign();
            message.Headers["Signature"] = "sig=(:AAAA:)";
            Assert.Equal(FikiErrorKind.MalformedSignatureValue, message.Refused().Kind);
            message.Headers["Signature"] = "sig";
            Assert.Equal(FikiErrorKind.MalformedSignatureValue, message.Refused().Kind);
        }

        // --- the section 9 order ---

        [Fact]
        public void AnUnsignedMessageIsMissingItsSignatureFirst()
        {
            var message = Sign();
            message.Headers.Remove("Signature");
            message.Headers.Remove("Signature-Input");
            Assert.Equal(FikiErrorKind.MissingSignature, message.Refused().Kind);
        }

        [Fact]
        public void AnUnparsableSignatureIsReportedBeforeAnUnparsableInput()
        {
            var message = Sign();
            message.Headers["Signature"] = "((((";
            message.Headers["Signature-Input"] = "((((";
            Assert.Equal(FikiErrorKind.MalformedSignature, message.Refused().Kind);
        }

        [Fact]
        public void AMalformedKeyIsReportedBeforeAnUnsupportedAlgorithm()
        {
            var message = Sign();
            message.Mangle(message.KeyId, "not-a-key").Mangle("alg=\"ed25519\"", "alg=\"rsa-pss-sha512\"");
            Assert.Equal(FikiErrorKind.MalformedKey, message.Refused().Kind);
        }

        [Fact]
        public void StalenessIsReportedBeforeExpiry() =>
            Assert.Equal(FikiErrorKind.SignatureTooOld, Sign(expires: At + 10).Refused(o =>
                VerifyOptions.MaxAge(300).WithSkew(60).WithNow(At + 1000).WithBody(Body)).Kind);

        [Fact]
        public void AnUnparsableUrlIsACallerErrorBeforeAnythingElse()
        {
            var message = Sign();
            message.Url = "https://[::1/";
            message.Headers.Remove("Signature");
            Assert.Throws<ArgumentException>(() => message.Verify());
        }

        // --- the minimum covered set (profile section 3) ---

        [Fact]
        public void TheMinimumSetsAreTheProfiles()
        {
            Assert.Equal(new[] { "@method", "@path", "@query" }, HttpSignatures.RequestMinimum);
            Assert.Equal(new[] { "@status", HttpSignatures.Req("@method"), HttpSignatures.Req("@path"), HttpSignatures.Req("@query") }, HttpSignatures.ResponseMinimum);
        }

        [Fact]
        public void ARequestCoveringTheMinimumVerifies() => Assert.Equal(TheKey.Aid, Sign().Verify(o => o.WithMinimum(Minimum)).Aid);

        [Fact]
        public void ARequestCoveringLessThanTheMinimumIsRefusedEvenThoughItVerifies()
        {
            var message = Sign(covered: new[] { "@method", "@path", "content-digest" });
            Assert.Equal(TheKey.Aid, message.Verify().Aid);
            var caught = message.Refused(o => o.WithMinimum(Minimum));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
            Assert.Equal("@query", caught.Component);
        }

        [Fact]
        public void AMinimumMayBeNamedInSerializedForm() =>
            Assert.Equal(TheKey.Aid, Sign().Verify(o => o.WithMinimum(new[] { "\"@method\"", "\"@PATH\"", "\"@query\"" })).Aid);

        [Theory]
        [InlineData("Content-Length", "18", false)]
        [InlineData("Content-Length", "many", false)]
        [InlineData("Transfer-Encoding", "chunked", false)]
        [InlineData(null, null, true)]
        public void ABodyWithoutACoveredDigestIsInsufficientCoverage(string? name, string? value, bool bodyArrives)
        {
            var extra = name == null ? null : new Dictionary<string, string> { { name, value! } };
            var message = Sign(noBody: true, headers: extra);
            message.Body = bodyArrives ? Body : null;
            var caught = message.Refused(o => o.WithMinimum(Minimum));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
            Assert.Equal("content-digest", caught.Component);
        }

        [Fact]
        public void ABodylessRequestNeedsNoDigestUnderAMinimum() =>
            Assert.Equal(TheKey.Aid, Sign(method: "GET", noBody: true).Verify(o => o.WithMinimum(Minimum)).Aid);

        [Fact]
        public void AZeroContentLengthIsNoBody()
        {
            var message = Sign(noBody: true, headers: new Dictionary<string, string> { { "Content-Length", " 0 " } });
            message.Body = new byte[0];
            Assert.Equal(TheKey.Aid, message.Verify(o => o.WithMinimum(Minimum)).Aid);
        }

        [Fact]
        public void InsufficientCoverageIsReportedBeforeTheKey()
        {
            var message = Sign(covered: new[] { "@method", "@path", "content-digest" });
            message.Mangle(message.KeyId, "not-a-key");
            Assert.Equal(FikiErrorKind.InsufficientCoverage, message.Refused(o => o.WithMinimum(Minimum)).Kind);
        }

        [Fact]
        public void AResponseCoveringTheMinimumVerifies() =>
            Assert.Equal(TheKey.Aid, Check(Respond(), with: o => o.WithMinimum(HttpSignatures.ResponseMinimum)).Aid);

        [Fact]
        public void AResponseMissingAReqComponentIsRefused()
        {
            var headers = Respond(covered: new[] { "@status", HttpSignatures.Req("@method"), HttpSignatures.Req("@query"), "content-digest", HttpSignatures.Req("content-digest") });
            var caught = CheckRefused(headers, with: o => o.WithMinimum(HttpSignatures.ResponseMinimum));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
            Assert.Equal("\"@path\";req", caught.Component);
        }

        [Fact]
        public void AResponseBodyWithoutItsDigestIsRefused()
        {
            var headers = Respond(noBody: true, headers: new Dictionary<string, string> { { "Content-Length", "14" } });
            var caught = CheckRefused(headers, body: ResponseBody, with: o => o.WithMinimum(HttpSignatures.ResponseMinimum));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
            Assert.Equal("content-digest", caught.Component);
        }

        [Fact]
        public void AResponseToARequestWithABodyMustCoverTheRequestsDigest()
        {
            var headers = Respond(covered: HttpSignatures.ResponseMinimum.Concat(new[] { "content-digest" }));
            var caught = CheckRefused(headers, with: o => o.WithMinimum(HttpSignatures.ResponseMinimum));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
            Assert.Equal("\"content-digest\";req", caught.Component);
        }

        [Fact]
        public void AResponseJudgesItsRequestsBodyByContentNotHeaders()
        {
            // Profile section 3 (version 1): both sides hold the whole request by then (@7p9s3g9k).
            var chunked = new Request("POST", Url, new Dictionary<string, string>
                { { "Transfer-Encoding", "chunked" }, { "Content-Digest", HttpSignatures.ContentDigest(Body) } });
            var headers = Respond(request: chunked, covered: HttpSignatures.ResponseMinimum.Concat(new[] { "content-digest" }));
            Assert.Equal(TheKey.Aid, Check(headers, request: chunked, with: o => o.WithMinimum(HttpSignatures.ResponseMinimum)).Aid);
        }

        // --- the first review's findings and the profile's draft 6 (@2f227n4r) ---

        [Fact]
        public void ADefaultResponseDoesNotBindARequestBodyOnlyItsHeadersAnnounce()
        {
            var asked = new Request("POST", Url, new Dictionary<string, string>
                { { "Content-Length", "18" }, { "Content-Digest", HttpSignatures.ContentDigest(Body) } });
            var verdict = Check(Respond(request: asked), request: asked, with: o => o.WithMinimum(HttpSignatures.ResponseMinimum));
            Assert.DoesNotContain(HttpSignatures.Req("content-digest"), verdict.Covered);
        }

        [Fact]
        public void ADefaultResponseBindsTheDigestOfARequestWithContent() =>
            Assert.Contains(HttpSignatures.Req("content-digest"),
                Check(Respond(request: TheRequest), with: o => o.WithMinimum(HttpSignatures.ResponseMinimum)).Covered);

        [Fact]
        public void ADefaultResponseToABodyWithNoDigestToBindIsRefusedAtSigning() =>
            Assert.Equal(FikiErrorKind.UncoveredBody,
                Assert.Throws<FikiException>(() => Respond(request: new Request("POST", Url, body: Body))).Kind);

        [Fact]
        public void AMissingKeyidIsReportedBeforeTheCoveredList()
        {
            var message = Sign(covered: new[] { "@method", "content-digest" }, keyId: Aid).Mangle($";keyid=\"{Aid}\"", "");
            Assert.Equal(FikiErrorKind.MissingKey, message.Refused(o => o.WithResolver(Table((Aid, Raw(TheKey)))).WithMinimum(Minimum)).Kind);
        }

        [Fact]
        public void AMissingKeyidIsReportedBeforeTheLabels()
        {
            var message = Sign(keyId: Aid).Mangle($";keyid=\"{Aid}\"", "");
            message.Headers["Signature-Input"] += ", other=" + message.Headers["Signature-Input"].Substring(4);
            Assert.Equal(FikiErrorKind.MissingKey, message.Refused(o => o.WithResolver(Table((Aid, Raw(TheKey))))).Kind);
        }

        [Fact]
        public void AMissingKeyidIsFineWhenTheVerifierNamesTheKey()
        {
            var message = Sign();
            message.Mangle($";keyid=\"{message.KeyId}\"", "");
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused(o => o.WithExpectedAid(TheKey.Aid)).Kind);
        }

        [Fact]
        public void AVerdictWithAnExpectedAidAndNoKeyidReportsNoKeyid()
        {
            // The base does not depend on where the key came from, so a signature made without a
            // keyid verifies against the preregistered AID and reports a null keyid.
            var input = "(\"@method\");created=1700000000";
            var headers = new Dictionary<string, string>
            {
                { "Signature-Input", "sig=" + input },
                { "Signature", "sig=:" + Convert.ToBase64String(TheKey.Sign(Bytes.Utf8("\"@method\": GET\n\"@signature-params\": " + input))) + ":" },
            };
            var verdict = HttpSignatures.VerifyRequest("GET", "/", headers, VerifyOptions.DecliningFreshness().WithExpectedAid(TheKey.Aid));
            Assert.Equal(TheKey.Aid, verdict.Aid);
            Assert.Null(verdict.KeyId);
        }

        [Fact]
        public void AHeadResponseCarryingAContentLengthHasNoBody()
        {
            var head = new Request("HEAD", Url);
            var verdict = Check(Respond(request: head, noBody: true, headers: new Dictionary<string, string> { { "Content-Length", "898" } }),
                request: head, noBody: true, with: o => o.WithMinimum(HttpSignatures.ResponseMinimum));
            Assert.DoesNotContain("content-digest", verdict.Covered);
        }

        [Theory]
        [InlineData("-5")]
        [InlineData("18 bytes")]
        [InlineData("+3")]
        [InlineData("٣")]
        public void AContentLengthThatIsNotAPlainDecimalCountsAsABody(string length) =>
            Assert.Equal(FikiErrorKind.InsufficientCoverage,
                Sign(noBody: true, headers: new Dictionary<string, string> { { "Content-Length", length } }).Refused(o => o.WithMinimum(Minimum)).Kind);

        [Fact]
        public void AMalformedComponentSpecIsAFikiError() =>
            Assert.Equal(FikiErrorKind.UnsupportedComponent, Assert.Throws<FikiException>(() => Sign(covered: new[] { "\"@path" })).Kind);

        [Fact]
        public void ASignerGivenAMinimumRefusesACoveredListBelowIt()
        {
            Assert.Equal(FikiErrorKind.InsufficientCoverage,
                Assert.Throws<FikiException>(() => Sign(noBody: true, covered: new[] { "@method", "@path" }, minimum: Minimum)).Kind);
            Assert.Equal(TheKey.Aid, Sign(minimum: Minimum).Verify(o => o.WithMinimum(Minimum)).Aid);
        }

        [Fact]
        public void ASignerGivenAMinimumRefusesABodyItWouldNotCover() =>
            Assert.Equal(FikiErrorKind.InsufficientCoverage, Assert.Throws<FikiException>(() =>
                Sign(noBody: true, headers: new Dictionary<string, string> { { "Transfer-Encoding", "chunked" } }, minimum: Minimum)).Kind);

        [Fact]
        public void AResponseSignerGivenAMinimumRefusesACoveredListBelowIt()
        {
            Assert.Equal(FikiErrorKind.InsufficientCoverage, Assert.Throws<FikiException>(() =>
                Respond(covered: new[] { "@status", "content-digest" }, minimum: HttpSignatures.ResponseMinimum)).Kind);
            Assert.Equal(TheKey.Aid, Check(Respond(minimum: HttpSignatures.ResponseMinimum), with: o => o.WithMinimum(HttpSignatures.ResponseMinimum)).Aid);
        }

        [Fact]
        public void ASignerRefusesAnUnsupportedComponentParameter() =>
            Assert.Equal(FikiErrorKind.UnsupportedComponent, Assert.Throws<FikiException>(() =>
                Sign(covered: new[] { "\"@method\";sf", "@path", "content-digest" })).Kind);

        [Fact]
        public void AResponseFromAnAidOtherThanTheExpectedOneIsAnUnknownKey()
        {
            var headers = Respond(keyId: Aid);
            var resolve = Table((Aid, Raw(TheKey)));
            Assert.Equal(Aid, Check(headers, with: o => o.WithResolver(resolve).WithExpectedKeyId(Aid)).KeyId);
            var caught = CheckRefused(headers, with: o => o.WithResolver(resolve).WithExpectedKeyId(Cesr('E', new byte[32])));
            Assert.Equal(FikiErrorKind.UnknownKey, caught.Kind);
            Assert.Equal(Aid, caught.KeyId);
        }

        [Fact]
        public void AnExpectedKeyidRefusesASignatureThatCarriesNone()
        {
            var message = Sign();
            message.Mangle($";keyid=\"{message.KeyId}\"", "");
            var caught = message.Refused(o => o.WithExpectedAid(TheKey.Aid).WithExpectedKeyId("k"));
            Assert.Equal(FikiErrorKind.UnknownKey, caught.Kind);
            Assert.Null(caught.KeyId);
        }

        [Fact]
        public void ACoveredAuthorityOutsideTheServedSetIsASignatureMismatch()
        {
            var message = Sign(url: "/identifiers", headers: new Dictionary<string, string> { { "Host", "other.example.com" } });
            Assert.Equal(TheKey.Aid, message.Verify(o => o.WithAuthorities(new[] { "other.example.com" })).Aid);
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused(o => o.WithAuthorities(new[] { "keria.example.com" })).Kind);
        }

        [Fact]
        public void ServedAuthoritiesDoNotApplyWhenAuthorityIsNotCovered() =>
            Assert.Equal(TheKey.Aid, Sign(covered: new[] { "@method", "@path", "@query", "content-digest" })
                .Verify(o => o.WithAuthorities(new[] { "elsewhere.example.com" })).Aid);

        [Fact]
        public void AnUnsignedUnauthorizedResponseIsUnauthenticatedBeforeAnythingElse() =>
            Assert.Equal(FikiErrorKind.Unauthenticated, CheckRefused(new Dictionary<string, string> { { "Content-Type", "application/json" } },
                status: 401, body: Bytes.Utf8("{\"title\": \"no\"}")).Kind);

        [Fact]
        public void AnUnauthorizedResponseCarryingASignatureHeaderIsVerifiedNotDismissed() =>
            Assert.Equal(FikiErrorKind.MissingSignatureInput, CheckRefused(new Dictionary<string, string> { { "SIGNATURE", "sig=:AAAA:" } }, status: 401).Kind);

        [Fact]
        public void AnUnsignedOkResponseIsMissingItsSignature() =>
            Assert.Equal(FikiErrorKind.MissingSignature, CheckRefused(new Dictionary<string, string>()).Kind);

        [Fact]
        public void ASignedUnauthorizedResponseIsVerifiedLikeAnyOther() =>
            Assert.Equal(TheKey.Aid, Check(Respond(status: 401), status: 401).Aid);

        [Fact]
        public void AResolverMayRefuseAKeyStateWithNoSingleSigner()
        {
            var caught = Sign(keyId: Aid).Refused(o => o.WithResolver(k =>
                throw new FikiException(FikiErrorKind.UnsupportedSigner, $"{k} has no single effective signer.", keyId: k)));
            Assert.Equal(FikiErrorKind.UnsupportedSigner, caught.Kind);
        }

        [Theory]
        [InlineData("café")]
        [InlineData("two\nlines")]
        [InlineData("bell\u0007")]
        public void ABaseThatCannotBeBuiltIsASignatureMismatch(string value)
        {
            var message = Sign(headers: new Dictionary<string, string> { { "X-Note", "plain" } },
                covered: new[] { "@method", "@path", "@query", "x-note", "content-digest" });
            message.Headers["X-Note"] = value;
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused().Kind);
        }

        [Fact]
        public void ATabInAFieldValueStillBuilds() =>
            Assert.Equal(TheKey.Aid, Sign(headers: new Dictionary<string, string> { { "X-Note", "a\tb" } },
                covered: new[] { "@method", "@path", "@query", "x-note", "content-digest" }).Verify().Aid);

        [Fact]
        public void ASignatureMemberThatIsNotAByteSequenceIsFoundBeforeTheLabels()
        {
            var message = Sign();
            message.Headers["Signature-Input"] += ", other=" + message.Headers["Signature-Input"].Substring(4);
            message.Headers["Signature"] = "sig=\"not bytes\"";
            Assert.Equal(FikiErrorKind.MalformedSignatureValue, message.Refused().Kind);
        }

        [Fact]
        public void AnEmptyKeyidIsAMissingKey() =>
            Assert.Equal(FikiErrorKind.MissingKey, Sign(keyId: "").Refused(o => o.WithResolver(Table())).Kind);

        // --- @status is a three-digit status code (bakobo/fiki#4 review) ---

        [Theory]
        [InlineData(99)]
        [InlineData(1000)]
        [InlineData(-200)]
        public void AStatusThatIsNotThreeDigitsIsMissingWhenVerified(int status) =>
            Assert.Equal(FikiErrorKind.MissingComponent, CheckRefused(Respond(), status: status).Kind);

        // --- created is required under a minimum (@7p9s3g9k) ---

        private static Msg WithoutCreated() => Sign().Mangle($";created={At}", "");

        [Fact]
        public void AMinimumRequiresCreatedAsPartOfSignatureInput() =>
            Assert.Equal(FikiErrorKind.MalformedSignatureInput, WithoutCreated().Refused(o => o.WithMinimum(Minimum)).Kind);

        [Fact]
        public void AMissingCreatedUnderAMinimumIsReportedBeforeTheCoveredList() =>
            Assert.Equal(FikiErrorKind.MalformedSignatureInput,
                WithoutCreated().Mangle("\"@path\"", "\"@path\" \"@path\"").Refused(o => o.WithMinimum(Minimum)).Kind);

        [Fact]
        public void WithoutAMinimumCreatedStaysOptionalAsRfc9421MakesIt() =>
            Assert.Equal(FikiErrorKind.SignatureMismatch, WithoutCreated().Refused().Kind);

        // --- a covered "content-digest";req is recomputed over the request body (bakobo/fiki#4) ---

        private static readonly IEnumerable<string> BindsBoth =
            HttpSignatures.ResponseMinimum.Concat(new[] { HttpSignatures.Req("content-digest"), "content-digest" });

        [Fact]
        public void ASwappedRequestBodyIsRefusedWhenTheResponseBindsItsDigest()
        {
            var swapped = new Request(TheRequest.Method, TheRequest.Url, TheRequest.Headers, Bytes.Utf8("{\"hello\": \"mallory\"}"));
            Assert.Equal(FikiErrorKind.DigestMismatch, CheckRefused(Respond(), request: swapped).Kind);
        }

        [Fact]
        public void AnUnreadableRequestDigestIsMalformedWhenTheResponseBindsIt()
        {
            var covered = new[] { "@status", HttpSignatures.Req("@method"), HttpSignatures.Req("@path"), HttpSignatures.Req("@query"), HttpSignatures.Req("content-digest"), "content-digest" };
            var unread = new Request("POST", Url, new Dictionary<string, string> { { "Content-Digest", "((((" } });
            var odd = new Request("POST", Url, new Dictionary<string, string> { { "Content-Digest", "((((" } }, Body);
            Assert.Equal(FikiErrorKind.MalformedDigest, CheckRefused(Respond(request: unread, covered: covered), request: odd).Kind);
        }

        [Fact]
        public void ASignerWillNotBindARequestDigestItsBodyContradicts()
        {
            var swapped = new Request(TheRequest.Method, TheRequest.Url, TheRequest.Headers, Bytes.Utf8("{\"hello\": \"mallory\"}"));
            Assert.Equal(FikiErrorKind.DigestMismatch, Assert.Throws<FikiException>(() => Respond(request: swapped)).Kind);
            var odd = new Request("POST", Url, new Dictionary<string, string> { { "Content-Digest", "((((" } }, Body);
            Assert.Equal(FikiErrorKind.MalformedDigest, Assert.Throws<FikiException>(() => Respond(request: odd)).Kind);
        }

        [Fact]
        public void ASignerBindingARequestDigestTheRequestDoesNotCarryIsMalformed()
        {
            // py hands None to the digest parser, which raises, and so a MalformedDigest; it comes
            // before the base would have reported the field missing.
            var bare = new Request("POST", Url, body: Body);
            Assert.Equal(FikiErrorKind.MalformedDigest, Assert.Throws<FikiException>(() => Respond(request: bare, covered: BindsBoth)).Kind);
        }

        [Fact]
        public void ABoundRequestDigestWithNoRequestBodyToCheckIsACallerError()
        {
            var bodiless = new Request(TheRequest.Method, TheRequest.Url, TheRequest.Headers);
            Assert.Throws<ArgumentException>(() => Check(Respond(), request: bodiless));
        }

        // --- a supplied minimum can only add to the profile's (bakobo/fiki#4) ---

        public static IEnumerable<object[]> ShortRequestMinimums() => new[]
        {
            new object[] { new string[0] },
            new object[] { new[] { "@method", "@path" } },
            new object[] { new[] { HttpSignatures.Req("@method") } },
        };

        [Theory]
        [MemberData(nameof(ShortRequestMinimums))]
        public void ARequestMinimumBelowTheProfilesIsACallerError(string[] minimum)
        {
            var caught = Assert.Throws<ArgumentException>(() => Sign().Verify(o => o.WithMinimum(minimum)));
            Assert.StartsWith("A minimum covered set must include the profile's own, @method, @path, @query; this one leaves out", caught.Message, StringComparison.Ordinal);
            Assert.Throws<ArgumentException>(() => Sign(minimum: minimum));
        }

        public static IEnumerable<object[]> ShortResponseMinimums() => new[]
        {
            new object[] { new string[0] },
            new object[] { new[] { "@method", "@path", "@query" } },
            new object[] { new[] { "@status", HttpSignatures.Req("@method") } },
        };

        [Theory]
        [MemberData(nameof(ShortResponseMinimums))]
        public void AResponseMinimumBelowTheProfilesIsACallerError(string[] minimum)
        {
            Assert.Throws<ArgumentException>(() => Check(Respond(), with: o => o.WithMinimum(minimum)));
            Assert.Throws<ArgumentException>(() => Respond(minimum: minimum));
        }

        [Fact]
        public void AMinimumMayAddRequirementsBeyondTheProfiles()
        {
            var extended = Minimum.Concat(new[] { "@authority" }).ToArray();
            Assert.Equal(TheKey.Aid, Sign().Verify(o => o.WithMinimum(extended)).Aid);
            Assert.Equal(FikiErrorKind.InsufficientCoverage,
                Sign(covered: Minimum.Concat(new[] { "content-digest" })).Refused(o => o.WithMinimum(extended)).Kind);
        }

        // --- an AID-shaped keyid is spelled canonically before any resolver sees it (fiki#4, Codex #1) ---

        [Theory]
        [InlineData('B')]
        [InlineData('D')]
        [InlineData('E')]
        public void APaddingBitAliasIsMalformedEvenThroughAResolver(char code)
        {
            var alias = KeysTests.PaddingBitAlias(Cesr(code, Raw(TheKey)));
            var message = Sign(keyId: alias);
            Assert.Equal(FikiErrorKind.MalformedKey, message.Refused(o => o.WithResolver(_ => Raw(TheKey))).Kind);
            Assert.Equal(FikiErrorKind.MalformedKey, message.Refused(o => o.WithResolver(_ => null)).Kind);
        }

        [Fact]
        public void AnAidShapedKeyidOutsideTheAlphabetIsMalformedThroughAResolver() =>
            Assert.Equal(FikiErrorKind.MalformedKey, Sign(keyId: "E" + new string('!', 43)).Refused(o => o.WithResolver(_ => Raw(TheKey))).Kind);

        [Fact]
        public void ACanonicalAidStillReachesTheResolver() =>
            Assert.Equal(Aid, Sign(keyId: Aid).Verify(o => o.WithResolver(Table((Aid, Raw(TheKey))))).Aid);

        [Fact]
        public void ASignerChecksABoundRequestDigestAgainstAnEmptyBodyToo()
        {
            var empty = new Request("POST", Url, new Dictionary<string, string> { { "Content-Digest", HttpSignatures.ContentDigest(Body) } }, new byte[0]);
            Assert.Equal(FikiErrorKind.DigestMismatch, Assert.Throws<FikiException>(() => Respond(request: empty, covered: BindsBoth)).Kind);
        }

        [Fact]
        public void AMalformedRequestDigestOutranksAMismatchedResponseDigest()
        {
            var unread = new Request("POST", Url, new Dictionary<string, string> { { "Content-Digest", "((((" } });
            var headers = Respond(request: unread, covered: BindsBoth);
            var odd = new Request("POST", Url, new Dictionary<string, string> { { "Content-Digest", "((((" } }, Body);
            Assert.Equal(FikiErrorKind.MalformedDigest, CheckRefused(headers, request: odd, body: Bytes.Utf8("{\"done\": false}")).Kind);
        }

        [Fact]
        public void OptionsForTheOtherKindOfMessageAreACallerError()
        {
            // Python's keyword arguments make these unexpressible there; here they are refused
            // rather than silently ignored, since an ignored authority check is one nobody made.
            var message = Sign();
            Assert.Throws<ArgumentException>(() => message.Verify(o => o.WithRequest(TheRequest)));
            Assert.Throws<ArgumentException>(() => Check(Respond(), with: o => o.WithAuthorities(new[] { "keria.example.com" })));
        }

        [Fact]
        public void OptionsCarryWhatTheyWereGiven()
        {
            var options = VerifyOptions.MaxAge(30);
            var changed = options.WithSkew(7).WithNow(9).WithExpectedKeyId("k").WithAuthorities(new[] { "a" });
            Assert.Equal(30, changed.MaxAgeSeconds);
            Assert.Null(VerifyOptions.DecliningFreshness().WithNow(1).MaxAgeSeconds);
        }
    }
}
