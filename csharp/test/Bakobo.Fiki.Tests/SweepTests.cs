using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The 0.8.0 cross-port sweep (this.i @5zrf8gjk) at the port level: the rules no vector pins,
    /// because a caller error is API behaviour rather than a message, mirroring
    /// py/tests/test_sweep.py.
    /// </summary>
    public class SweepTests
    {
        private static readonly Key TheKey = SignVerifyTests.TheKey;
        private const string Url = "https://api.example.com/things?limit=1";
        private const long At = 1700000000;
        private static readonly byte[] Body = Bytes.Utf8("{\"hello\": \"world\"}");

        private static KeyValuePair<string, string> H(string name, string value) => new KeyValuePair<string, string>(name, value);

        private static Dictionary<string, string> Merged(IEnumerable<KeyValuePair<string, string>> given, IReadOnlyDictionary<string, string> signed)
        {
            var merged = given.ToDictionary(h => h.Key, h => h.Value);
            foreach (var header in signed)
            {
                merged[header.Key] = header.Value;
            }
            return merged;
        }

        private static FikiErrorKind KindOf(Action action) => Assert.Throws<FikiException>(action).Kind;

        // --- A4: null header names and values are the caller's mistake ---

        public static IEnumerable<object[]> NullHeaders() => new[]
        {
            new object[] { new[] { H(null!, "v") } },
            new object[] { new[] { H("x-a", null!) } },
        };

        [Theory]
        [MemberData(nameof(NullHeaders))]
        public void ANullHeaderNameOrValueIsTheCallersMistakeEverywhere(KeyValuePair<string, string>[] headers)
        {
            Assert.ThrowsAny<ArgumentException>(() => HttpSignatures.SignRequest(TheKey, "GET", Url, headers, created: At));
            Assert.ThrowsAny<ArgumentException>(() => HttpSignatures.VerifyRequest("GET", Url, headers, VerifyOptions.DecliningFreshness()));
            Assert.ThrowsAny<ArgumentException>(() => HttpSignatures.SignatureBase("GET", Url, headers, new[] { "@path" }, At, "k"));
            Assert.ThrowsAny<ArgumentException>(() => HttpSignatures.SignResponse(TheKey, 200, headers: headers, created: At));
            var request = new Request("GET", Url, headers);
            Assert.ThrowsAny<ArgumentException>(() => HttpSignatures.SignResponse(TheKey, 200, request, created: At));
            Assert.ThrowsAny<ArgumentException>(() => HttpSignatures.VerifyResponse(200, new Dictionary<string, string>(),
                VerifyOptions.DecliningFreshness().WithRequest(request)));
        }

        // --- A6: parsing is linear ---

        [Fact]
        public void ALongCoveredListIsBuiltInLinearTime()
        {
            var headers = new List<KeyValuePair<string, string>>();
            var covered = new List<string>();
            for (var i = 0; i < 50000; i++)
            {
                headers.Add(H("x-h" + i, "v"));
                covered.Add("x-h" + i);
            }
            var clock = Stopwatch.StartNew();
            HttpSignatures.SignatureBase("GET", Url, headers, covered, At, "k");
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"50000 components took {clock.Elapsed}");
        }

        [Fact]
        public void ManyParametersAreParsedInLinearTime()
        {
            var text = new StringBuilder("(\"@path\")");
            for (var i = 0; i < 50000; i++)
            {
                text.Append(";p").Append(i);
            }
            var clock = Stopwatch.StartNew();
            var parsed = Sfv.ParseDictionary("sig=" + text);
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"50000 parameters took {clock.Elapsed}");
            Assert.Equal(50000, parsed.Single().Value.Params.Count);
        }

        // --- A7 and E5: a supplied digest must be one a verifier accepts for the body ---

        [Theory]
        [InlineData("contradicted")]
        [InlineData("((((")]
        [InlineData("sha-1=:AAAA:")]
        public void ASuppliedDigestTheBodyDoesNotSupportIsTheCallersMistake(string digest)
        {
            if (digest == "contradicted")
            {
                digest = HttpSignatures.ContentDigest(Bytes.Utf8("another body"));
            }
            var headers = new[] { H("Content-Digest", digest) };
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(TheKey, "POST", Url, headers, Body, created: At));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignResponse(TheKey, 200, headers: headers, body: Body, created: At));
        }

        [Fact]
        public void ASuppliedDigestTheBodyMatchesIsSignedAsGiven()
        {
            var digest = HttpSignatures.ContentDigest(Body) + ", sha-512=:" + Convert.ToBase64String(System.Security.Cryptography.SHA512.Create().ComputeHash(Body)) + ":";
            var headers = new[] { H("Content-Digest", digest) };
            var signed = HttpSignatures.SignRequest(TheKey, "POST", Url, headers, Body, created: At);
            Assert.False(signed.ContainsKey("Content-Digest"));
            HttpSignatures.VerifyRequest("POST", Url, Merged(headers, signed), VerifyOptions.DecliningFreshness().WithBody(Body));
        }

        [Fact]
        public void TheRequestDigestASignedResponseBindsKeepsItsOwnRefusal()
        {
            // bakobo/fiki#4: that digest is the request's, not the caller's, so it stays a message defect.
            var request = new Request("POST", Url, new[] { H("Content-Digest", HttpSignatures.ContentDigest(Bytes.Utf8("other"))) }, Body);
            Assert.Equal(FikiErrorKind.DigestMismatch, KindOf(() => HttpSignatures.SignResponse(TheKey, 200, request, created: At)));
        }

        // --- A9: names an object would inherit are ordinary names ---

        [Fact]
        public void InheritedMemberNamesAreOrdinaryNames()
        {
            var headers = new[] { H("__proto__", "p"), H("constructor", "c"), H("tostring", "t"), H("Content-Digest", HttpSignatures.ContentDigest(Body) + ", constructor=:AAAA:") };
            var covered = new[] { "@method", "__proto__", "constructor", "tostring", "content-digest" };
            var signed = HttpSignatures.SignRequest(TheKey, "POST", Url, headers, Body, covered, At);
            var verdict = HttpSignatures.VerifyRequest("POST", Url, Merged(headers, signed), VerifyOptions.DecliningFreshness().WithBody(Body));
            Assert.Equal(covered, verdict.Covered.ToArray());
            Assert.Equal(FikiErrorKind.MissingComponent,
                KindOf(() => HttpSignatures.SignatureBase("GET", Url, new KeyValuePair<string, string>[0], new[] { "hasownproperty" }, At, "k")));
        }

        // --- A10: the keyid alone, then the expected keyid, then the resolver ---

        [Fact]
        public void AnUnexpectedKeyidNeverReachesTheResolver()
        {
            var keyId = Aids.Qb64('E', Bytes.Range(1, 32));
            var signed = HttpSignatures.SignRequest(TheKey, "GET", Url, created: At, keyId: keyId);
            var asked = 0;
            var options = VerifyOptions.DecliningFreshness()
                .WithResolver(k => { asked++; return null; })
                .WithExpectedKeyId(Aids.Qb64('E', Bytes.Range(2, 32)));
            Assert.Equal(FikiErrorKind.UnknownKey, KindOf(() => HttpSignatures.VerifyRequest("GET", Url, signed, options)));
            Assert.Equal(0, asked);
        }

        [Fact]
        public void AMalformedKeyidOutranksAnUnexpectedOne()
        {
            var resolved = HttpSignatures.SignRequest(TheKey, "GET", Url, created: At, keyId: KeysTests.PaddingBitAlias(Aids.Qb64('E', Bytes.Range(1, 32))));
            var asked = 0;
            Assert.Equal(FikiErrorKind.MalformedKey, KindOf(() => HttpSignatures.VerifyRequest("GET", Url, resolved,
                VerifyOptions.DecliningFreshness().WithResolver(k => { asked++; return null; }).WithExpectedKeyId("someone-else"))));
            Assert.Equal(0, asked);
            var raw = HttpSignatures.SignRequest(TheKey, "GET", Url, created: At, keyId: "not-a-raw-key");
            Assert.Equal(FikiErrorKind.MalformedKey, KindOf(() => HttpSignatures.VerifyRequest("GET", Url, raw,
                VerifyOptions.DecliningFreshness().WithExpectedKeyId("someone-else"))));
        }

        // --- B13: the method is a token wherever a request message is built ---

        [Theory]
        [InlineData("")]
        [InlineData("GET X")]
        [InlineData("GE\r\nT")]
        [InlineData("(GET)")]
        [InlineData("GÉT")]
        [InlineData("GET\t")]
        public void AMethodThatIsNotATokenIsTheCallersMistakeCoveredOrNot(string method)
        {
            var path = new[] { "@path" };
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(TheKey, method, Url, covered: path, created: At));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignatureBase(method, Url, new KeyValuePair<string, string>[0], path, At, "k"));
            var signed = HttpSignatures.SignRequest(TheKey, "GET", Url, covered: path, created: At);
            Assert.Throws<ArgumentException>(() => HttpSignatures.VerifyRequest(method, Url, signed, VerifyOptions.DecliningFreshness()));
            var request = new Request(method, Url);
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignResponse(TheKey, 200, request, covered: new[] { "@status" }, created: At));
            var response = HttpSignatures.SignResponse(TheKey, 200, covered: new[] { "@status" }, created: At);
            Assert.Throws<ArgumentException>(() => HttpSignatures.VerifyResponse(200, response, VerifyOptions.DecliningFreshness().WithRequest(request)));
        }

        [Theory]
        [InlineData("get")]
        [InlineData("PURGE")]
        [InlineData("M-SEARCH")]
        public void AnyTokenIsAMethodKeptAsSent(string method)
        {
            var signed = HttpSignatures.SignRequest(TheKey, method, Url, created: At);
            HttpSignatures.VerifyRequest(method, Url, signed, VerifyOptions.DecliningFreshness());
            Assert.StartsWith("\"@method\": " + method + "\n", Bytes.Text(HttpSignatures.SignatureBase(method, Url, new KeyValuePair<string, string>[0], new[] { "@method" }, At, "k")));
        }

        // --- B14 and E1, E2: ports, signing side, and the URL read only when needed ---

        [Theory]
        [InlineData("https://api.example.com:65536/x")]
        [InlineData("https://api.example.com:44x/x")]
        [InlineData("https://api.example.com:-1/x")]
        [InlineData("https://api.example.com:١/x")]
        [InlineData("https://[2001:db8::1]x/x")]
        public void AnUnreadableAuthorityIsTheSignersMistake(string url)
        {
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(TheKey, "GET", url, created: At));
            var request = new Request("GET", url);
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignResponse(TheKey, 200, request,
                covered: new[] { HttpSignatures.Req("@authority") }, created: At));
        }

        [Theory]
        [InlineData("https://api.example.com:65536/x")]
        [InlineData("https://api.example.com:44x/x")]
        public void AnUnreadableAuthorityIsAMismatchOnlyWhenItIsCovered(string url)
        {
            var path = HttpSignatures.SignRequest(TheKey, "GET", url, covered: new[] { "@path", "@query" }, created: At);
            Assert.Equal(new[] { "@path", "@query" }, HttpSignatures.VerifyRequest("GET", url, path, VerifyOptions.DecliningFreshness()).Covered.ToArray());
            var good = HttpSignatures.SignRequest(TheKey, "GET", "https://api.example.com/x", created: At);
            Assert.Equal(FikiErrorKind.SignatureMismatch, KindOf(() => HttpSignatures.VerifyRequest("GET", url, good, VerifyOptions.DecliningFreshness())));
            var request = new Request("GET", url);
            var response = HttpSignatures.SignResponse(TheKey, 200, new Request("GET", "https://api.example.com/x"),
                covered: new[] { "@status", HttpSignatures.Req("@authority") }, created: At);
            Assert.Equal(FikiErrorKind.SignatureMismatch, KindOf(() => HttpSignatures.VerifyResponse(200, response,
                VerifyOptions.DecliningFreshness().WithRequest(request))));
        }

        [Theory]
        [InlineData("https://api.example.com:08443/x", "api.example.com:8443")]
        [InlineData("https://api.example.com:000443/x", "api.example.com")]
        [InlineData("http://api.example.com:/x", "api.example.com")]
        [InlineData("https://API.example.com:0/x", "api.example.com:0")]
        [InlineData("https://[FE80::1%25EtH0]:443/x", "[fe80::1%25eth0]")]
        public void APortIsAnyRunOfDigitsReadAsANumber(string url, string authority)
        {
            var bas = Bytes.Text(HttpSignatures.SignatureBase("GET", url, new KeyValuePair<string, string>[0], new[] { "@authority" }, At, "k"));
            Assert.StartsWith("\"@authority\": " + authority + "\n", bas);
        }

        // --- B15: what the signer serializes must be serializable ---

        [Theory]
        [InlineData("keyid")]
        [InlineData("nonce")]
        [InlineData("tag")]
        public void ASerializedStringOutsidePrintableAsciiIsTheCallersMistake(string which)
        {
            foreach (var bad in new[] { "a\r\nb", "a\nb", "café", "a\u0000", "\u007f" })
            {
                // Before anything else is examined: the covered header here is missing too.
                Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(TheKey, "GET", Url, covered: new[] { "x-missing" }, created: At,
                    keyId: which == "keyid" ? bad : null, nonce: which == "nonce" ? bad : null, tag: which == "tag" ? bad : null));
                Assert.Throws<ArgumentException>(() => HttpSignatures.SignatureBase("GET", Url, new KeyValuePair<string, string>[0], new[] { "x-missing" }, At,
                    which == "keyid" ? bad : "k", nonce: which == "nonce" ? bad : null, tag: which == "tag" ? bad : null));
            }
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignatureBase("GET", Url, new KeyValuePair<string, string>[0], new[] { "x-missing" }, At, "k", alg: "ed\r\n25519"));
        }

        [Theory]
        [InlineData("Sig")]
        [InlineData("bad label")]
        [InlineData("sig\r\nx-evil: 1")]
        [InlineData("")]
        [InlineData("1sig")]
        public void ALabelThatIsNotAnSfKeyIsTheCallersMistake(string label)
        {
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(TheKey, "GET", Url, created: At, label: label));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignResponse(TheKey, 200, created: At, label: label));
        }

        [Theory]
        [InlineData("x-a\r\n")]
        [InlineData("x a")]
        [InlineData("")]
        [InlineData("x(a)")]
        [InlineData("\"x a\"")]
        [InlineData("\"\";req")]
        public void AComponentNameThatIsNotAFieldNameIsTheCallersMistake(string name)
        {
            var headers = new[] { H("x-a", "v") };
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(TheKey, "GET", Url, headers, covered: new[] { name }, created: At));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignatureBase("GET", Url, headers, new[] { name }, At, "k"));
        }

        [Fact]
        public void AFieldNameIsLoweredAndADerivedNameKeepsItsOwnRefusal()
        {
            var headers = new[] { H("X-Role", "member") };
            var signed = HttpSignatures.SignRequest(TheKey, "GET", Url, headers, covered: new[] { "X-Role" }, created: At);
            Assert.Equal(new[] { "x-role" }, HttpSignatures.VerifyRequest("GET", Url, Merged(headers, signed), VerifyOptions.DecliningFreshness()).Covered.ToArray());
            // E6: a derived component fiki does not build names itself in the refusal.
            Assert.Equal(FikiErrorKind.UnsupportedComponent, KindOf(() => HttpSignatures.SignRequest(TheKey, "GET", Url, covered: new[] { "@target-uri" }, created: At)));
        }

        // --- B16: created and expires fit RFC 8941's integers ---

        [Theory]
        [InlineData(-1L)]
        [InlineData(1_000_000_000_000_000L)]
        [InlineData(long.MinValue)]
        [InlineData(long.MaxValue)]
        public void ATimestampOutsideAnSfIntegerIsTheCallersMistake(long value)
        {
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(TheKey, "GET", Url, covered: new[] { "x-missing" }, created: value));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(TheKey, "GET", Url, covered: new[] { "x-missing" }, created: At, expires: value));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignatureBase("GET", Url, new KeyValuePair<string, string>[0], new[] { "x-missing" }, value, "k"));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignResponse(TheKey, 200, created: value));
        }

        [Theory]
        [InlineData(0L)]
        [InlineData(999_999_999_999_999L)]
        public void TheEndsOfTheSfIntegerRangeAreSigned(long value)
        {
            var signed = HttpSignatures.SignRequest(TheKey, "GET", Url, created: value, expires: value);
            Assert.Contains($";created={value};expires={value};", signed["Signature-Input"]);
        }

        // --- B17: freshness windows are positive, and nothing overflows ---

        [Theory]
        [InlineData(0L)]
        [InlineData(-1L)]
        [InlineData(long.MinValue)]
        public void AFreshnessWindowThatIsNotPositiveIsTheCallersMistake(long value)
        {
            Assert.ThrowsAny<ArgumentException>(() => VerifyOptions.MaxAge(value));
            Assert.ThrowsAny<ArgumentException>(() => VerifyOptions.DecliningFreshness().WithSkew(value));
            Assert.ThrowsAny<ArgumentException>(() => VerifyOptions.MaxAge(300).WithSkew(value));
        }

        [Fact]
        public void VastWindowsAndClocksDoNotOverflow()
        {
            var signed = HttpSignatures.SignRequest(TheKey, "GET", Url, created: 0, expires: 999_999_999_999_999);
            HttpSignatures.VerifyRequest("GET", Url, signed, VerifyOptions.MaxAge(long.MaxValue).WithSkew(long.MaxValue).WithNow(long.MaxValue));
            Assert.Equal(FikiErrorKind.SignatureTooOld, KindOf(() => HttpSignatures.VerifyRequest("GET", Url, signed,
                VerifyOptions.MaxAge(long.MaxValue - 2).WithSkew(1).WithNow(long.MaxValue))));
            Assert.Equal(FikiErrorKind.SignatureTooOld, KindOf(() => HttpSignatures.VerifyRequest("GET", Url,
                HttpSignatures.SignRequest(TheKey, "GET", Url, created: 999_999_999_999_999),
                VerifyOptions.MaxAge(1).WithSkew(1).WithNow(long.MinValue))));
            HttpSignatures.VerifyRequest("GET", Url, signed, VerifyOptions.DecliningFreshness().WithNow(long.MinValue));
        }

        // --- B18: the verdict's keyid is the wire's, and its AID is who vouched ---

        [Fact]
        public void TheVerdictReportsTheWireKeyidAndWhoVouched()
        {
            var signed = HttpSignatures.SignRequest(TheKey, "GET", Url, created: At, keyId: "claimed");
            var verdict = HttpSignatures.VerifyRequest("GET", Url, signed, VerifyOptions.DecliningFreshness().WithExpectedAid(TheKey.Aid));
            Assert.Equal("claimed", verdict.KeyId);
            Assert.Equal(TheKey.Aid, verdict.Aid);

            var bas = HttpSignatures.SignatureBase("GET", Url, new KeyValuePair<string, string>[0], HttpSignatures.DefaultCovered, At, "k", alg: "ed25519");
            var text = Bytes.Text(bas);
            var parameters = text.Substring(text.LastIndexOf("\"@signature-params\": ", StringComparison.Ordinal) + 21).Replace(";keyid=\"k\"", "");
            var unnamed = new Dictionary<string, string>
            {
                { "Signature-Input", "sig=" + parameters },
                { "Signature", "sig=:" + Convert.ToBase64String(TheKey.Sign(Bytes.Utf8(text.Replace(";keyid=\"k\"", "")))) + ":" },
            };
            verdict = HttpSignatures.VerifyRequest("GET", Url, unnamed, VerifyOptions.DecliningFreshness().WithExpectedAid(TheKey.Aid));
            Assert.Null(verdict.KeyId);
            Assert.Equal(TheKey.Aid, verdict.Aid);
        }

        [Fact]
        public void TheVerdictsDocCommentsSayWhatEachFieldIs()
        {
            var source = string.Join(" ", File.ReadAllText(Repo.PathTo("csharp", "src", "Bakobo.Fiki", "Verdict.cs"))
                .Replace("///", " ").Split(new[] { ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries));
            foreach (var want in new[] { "exactly as it appeared on the wire", "null when the signature had none", "identity that vouched for the key" })
            {
                Assert.Contains(want, source);
            }
        }

        // --- B19 and E3: both formats and the four bounds are exported ---

        [Fact]
        public void TheFormatsAndBoundsAreExported()
        {
            Assert.Equal(2, HttpSignatures.VectorsFormat);
            Assert.Equal(4, HttpSignatures.KeriVectorsFormat);
            Assert.Equal(8192, HttpSignatures.MaxFieldBytes);
            Assert.Equal(16, HttpSignatures.MaxDictionaryMembers);
            Assert.Equal(64, HttpSignatures.MaxInnerListItems);
            Assert.Equal(16, HttpSignatures.MaxParameters);
        }

        // --- B20 and E3: bounds before parsing, on the raw value ---

        [Fact]
        public void AFieldIsMeasuredInBytesAsReceivedBeforeAnyTrimming()
        {
            var signed = HttpSignatures.SignRequest(TheKey, "GET", Url, created: At).ToDictionary(h => h.Key, h => h.Value);
            signed["Signature"] += new string(' ', HttpSignatures.MaxFieldBytes + 1 - signed["Signature"].Length);
            Assert.Equal(FikiErrorKind.MalformedSignature, KindOf(() => HttpSignatures.VerifyRequest("GET", Url, signed, VerifyOptions.DecliningFreshness())));
        }

        [Fact]
        public void AnItemsParametersAreBoundedBeforeTheyAreRead()
        {
            // Seventeen parameters on one covered component: without the bound this is an
            // UnsupportedComponent, found later; with it, the header itself is malformed.
            var signed = HttpSignatures.SignRequest(TheKey, "GET", Url, created: At).ToDictionary(h => h.Key, h => h.Value);
            var many = string.Concat(Enumerable.Range(0, 17).Select(i => ";p" + i));
            signed["Signature-Input"] = signed["Signature-Input"].Replace("\"@path\"", "\"@path\"" + many);
            Assert.Equal(FikiErrorKind.MalformedSignatureInput, KindOf(() => HttpSignatures.VerifyRequest("GET", Url, signed, VerifyOptions.DecliningFreshness())));
        }
    }
}
