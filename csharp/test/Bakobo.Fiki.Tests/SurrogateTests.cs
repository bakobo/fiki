using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// A .NET string can hold a lone UTF-16 surrogate, which no JSON vector carries portably, so
    /// these are native (tick 7us4; #18 hostile finding 3, where fiki-py's size checks raised
    /// UnicodeEncodeError on one). Every untrusted string fiki measures or character-checks is fed
    /// a lone high and a lone low surrogate, and each must come back as the refusal fiki-py gives
    /// the same Python string, never as an exception from the BCL. Each case names the path py
    /// takes, found by running fiki-py 0.9.0 on the same input.
    /// </summary>
    public class SurrogateTests
    {
        private static readonly Key Signer = SignVerifyTests.TheKey;
        private const string Url = "https://api.example.com/things?limit=1";
        private static readonly byte[] Body = Bytes.Utf8("x");

        // Passed as code points: xunit serializes a theory's string arguments, and a lone surrogate
        // does not survive that, so both cases would collapse into one replaced by U+FFFD.
        public static IEnumerable<object[]> Lone() => new[] { new object[] { 0xD800 }, new object[] { 0xDC00 } };

        private static string Of(int code) => ((char)code).ToString();

        private static readonly Dictionary<string, string> Extra = new Dictionary<string, string>
        {
            { "X-Note", "a" },
            { "Host", "api.example.com" },
        };

        /// <summary>A POST covering the four derived components, a field and the body digest, with every header it needs.</summary>
        private static Dictionary<string, string> Signed()
        {
            var all = new Dictionary<string, string>(Extra);
            foreach (var header in HttpSignatures.SignRequest(Signer, "POST", Url, Extra, Body,
                new[] { "@method", "@authority", "@path", "@query", "x-note", "content-digest" }, created: 1))
            {
                all[header.Key] = header.Value;
            }
            return all;
        }

        private static Dictionary<string, string> With(string name, string value)
        {
            var headers = Signed();
            headers[name] = value;
            return headers;
        }

        private static FikiException Refused(string url, Dictionary<string, string> headers, VerifyOptions? options = null) =>
            Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("POST", url, headers, (options ?? Verifying.DecliningFreshness()).WithBody(Body)));

        private static void Mismatch(FikiException caught, string fragment)
        {
            Assert.Equal(FikiErrorKind.SignatureMismatch, caught.Kind);
            Assert.Contains(fragment, caught.Message, StringComparison.Ordinal);
        }

        private const string NotAscii = "contains a line break, a control character or a non-ASCII character";
        private const string OverBound = "over 8192 bytes";
        private const string NoUtf8 = "has no UTF-8 encoding";

        [Fact]
        public void TheSignedRequestTheseCasesBreakVerifiesUntouched() =>
            Assert.Equal(Signer.Aid, HttpSignatures.VerifyRequest("POST", Url, Signed(), Verifying.DecliningFreshness().WithBody(Body)).Aid);

        // --- the URL: py counts bytes first (surrogatepass, 3 bytes each), then checks characters ---

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInTheUrlPathIsANonAsciiPathAsInPy(int code) =>
            Mismatch(Refused("https://api.example.com/th" + Of(code), Signed()), "The value of @path " + NotAscii);

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInTheUrlQueryIsANonAsciiQueryAsInPy(int code) =>
            Mismatch(Refused("https://api.example.com/things?l=" + Of(code), Signed()), "The value of @query " + NotAscii);

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInTheUrlHostIsAHostThatIsNotAsciiAsInPy(int code) =>
            // py: "its host is not ASCII".
            Mismatch(Refused("https://api.exa" + Of(code) + "mple.com/things", Signed()), "outside ASCII");

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInTheUrlPortIsAHostThatIsNotAsciiAsInPy(int code) =>
            Mismatch(Refused("https://a:8" + Of(code) + "/", Signed()), "outside ASCII");

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInUserinfoIsUserinfoAsInPy(int code) =>
            Mismatch(Refused("https://u" + Of(code) + "@api.example.com/", Signed()), "user information");

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInTheSchemeIsNoAbsoluteUriAsInPy(int code) =>
            Mismatch(Refused("http" + Of(code) + "://a/", Signed()), "neither origin-form");

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInAnIpLiteralIsNoIpLiteralAsInPy(int code) =>
            // py: "'::1\ud800' does not appear to be an IPv4 or IPv6 address", its urlsplit's words.
            Mismatch(Refused("https://[::1" + Of(code) + "]/", Signed()), "does not appear to be an IPv6 address");

        [Fact]
        public void APairInTheUrlHostIsAHostThatIsNotAsciiAsInPy() =>
            Mismatch(Refused("https://api.exa\U00010000mple.com/things", Signed()), "outside ASCII");

        [Fact]
        public void NfkcLeavesALoneSurrogateInPlaceAsPythonDoes()
        {
            // string.Normalize throws on a lone surrogate, which urlsplit's netloc check reached as
            // a BCL ArgumentException; unicodedata.normalize keeps it and normalizes around it.
            Assert.Equal("a/c\ud800x\udc00\U00010000", PyText.NormalizeKC("\u2100\ud800x\udc00\U00010000"));
            Assert.Equal("a/c", PyText.NormalizeKC("\u2100"));
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void AUrlOf8191BytesWithSurrogatesIsCheckedForCharactersNotSize(int code)
        {
            // "/" and 2730 surrogates: 1 + 3 x 2730 = 8191 bytes, under the bound, so py refuses it
            // for its characters. An encoder that counted a surrogate as one byte would agree here.
            var caught = Refused("/" + new string((char)code, 2730), Signed());
            Mismatch(caught, "The value of @path " + NotAscii);
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void AUrlOf8194BytesWithSurrogatesIsOverTheBoundAsInPy(int code)
        {
            // 1 + 3 x 2731 = 8194 bytes. Counted as py counts, with a surrogate 3 bytes, this is over
            // the bound; counted as 1 byte each, as Java's getBytes would, it is 2732 and would pass
            // the size check to be refused for its characters instead.
            var caught = Refused("/" + new string((char)code, 2731), Signed());
            Mismatch(caught, "it is " + OverBound);
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void SigningAUrlWithASurrogateIsRefusedAsPyRefusesIt(int code)
        {
            // py raises SignatureMismatch from the signer too: the value check is shared.
            var caught = Assert.Throws<FikiException>(() => HttpSignatures.SignRequest(Signer, "GET", "https://api.example.com/" + Of(code), created: 1));
            Mismatch(caught, "The value of @path " + NotAscii);
        }

        // --- Host, read when the target is origin-form ---

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInHostIsANonAsciiAuthorityAsInPy(int code) =>
            Mismatch(Refused("/things?limit=1", With("Host", "api.example.com" + Of(code))), "The value of @authority " + NotAscii);

        [Theory]
        [MemberData(nameof(Lone))]
        public void AHostOf2731SurrogatesIsOverTheBoundAsInPy(int code) =>
            Mismatch(Refused("/things?limit=1", With("Host", new string((char)code, 2731))), "The value of @authority is " + OverBound);

        // --- a covered field value ---

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInACoveredFieldIsANonAsciiValueAsInPy(int code) =>
            Mismatch(Refused(Url, With("X-Note", "a" + Of(code))), "The value of x-note " + NotAscii);

        [Theory]
        [MemberData(nameof(Lone))]
        public void AFieldOf8192BytesWithSurrogatesIsCheckedForCharactersNotSize(int code) =>
            // "aa" and 2730 surrogates: 2 + 8190 = 8192 bytes, exactly the bound.
            Mismatch(Refused(Url, With("X-Note", "aa" + new string((char)code, 2730))), "The value of x-note " + NotAscii);

        [Theory]
        [MemberData(nameof(Lone))]
        public void AFieldOf2731SurrogatesIsOverTheBoundAsInPy(int code) =>
            // 8193 bytes as py counts; 2731 as a one-byte-per-surrogate count would have it.
            Mismatch(Refused(Url, With("X-Note", new string((char)code, 2731))), "The value of x-note is " + OverBound);

        [Theory]
        [MemberData(nameof(Lone))]
        public void SigningAFieldWithASurrogateIsRefusedAsPyRefusesIt(int code)
        {
            var caught = Assert.Throws<FikiException>(() => HttpSignatures.SignRequest(Signer, "GET", Url,
                new Dictionary<string, string> { { "X-Note", Of(code) } }, covered: new[] { "@method", "@path", "@query", "x-note" }, created: 1));
            Mismatch(caught, "The value of x-note " + NotAscii);
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInACoveredContentDigestIsANonAsciiValueAsInPy(int code)
        {
            // Covered, so its value is checked while the base is built, before it is ever parsed.
            var headers = Signed();
            headers["Content-Digest"] += Of(code);
            Mismatch(Refused(Url, headers), "The value of content-digest " + NotAscii);
            Mismatch(Refused(Url, With("Content-Digest", new string((char)code, 2731))), "The value of content-digest " + NotAscii);
        }

        // --- the three signature headers: py refuses a surrogate before it counts bytes ---

        public static IEnumerable<object[]> SignatureHeaders()
        {
            foreach (var code in new[] { 0xD800, 0xDC00 })
            {
                yield return new object[] { "Signature-Input", FikiErrorKind.MalformedSignatureInput, code };
                yield return new object[] { "Signature", FikiErrorKind.MalformedSignature, code };
            }
        }

        [Theory]
        [MemberData(nameof(SignatureHeaders))]
        public void ASurrogateInASignatureHeaderHasNoUtf8EncodingAsInPy(string name, FikiErrorKind kind, int code)
        {
            var caught = Refused(Url, With(name, Signed()[name] + Of(code)));
            Assert.Equal(kind, caught.Kind);
            Assert.Contains($"The {name} header holds a character that {NoUtf8}", caught.Message, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(SignatureHeaders))]
        public void ASignatureHeaderOf2731SurrogatesIsRefusedForTheSurrogateNotItsSize(string name, FikiErrorKind kind, int code)
        {
            // py's _parse encodes strictly first, so even past the bound the refusal is the
            // encoding, never "8193 bytes".
            var caught = Refused(Url, With(name, new string((char)code, 2731)));
            Assert.Equal(kind, caught.Kind);
            Assert.Contains(NoUtf8, caught.Message, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(SignatureHeaders))]
        public void ASurrogatePastTheBoundIsNeverReachedSoTheHeaderIsRefusedForItsSize(string name, FikiErrorKind kind, int code)
        {
            // A divergence in the message only: fiki-py encodes the whole header and says "no UTF-8
            // encoding"; this port stops counting at the bound (tick 7xbw), so a header refused
            // for its size is never read to its end. The kind is the same.
            var caught = Refused(Url, With(name, new string('a', 8193) + Of(code)));
            Assert.Equal(kind, caught.Kind);
            Assert.Contains("is " + OverBound, caught.Message, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInAContentDigestReachingTheParserHasNoUtf8EncodingAsInPy(int code)
        {
            // Through the verifier a surrogate in Content-Digest is refused as a covered value
            // first; the parser's own refusal is py's _parse on the same string.
            var caught = Assert.Throws<FikiException>(() => Messages.Parse("sha-256=:AAAA:" + Of(code), "Content-Digest", FikiErrorKind.MalformedDigest));
            Assert.Equal(FikiErrorKind.MalformedDigest, caught.Kind);
            Assert.Contains("The Content-Digest header holds a character that " + NoUtf8, caught.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void AWellFormedPairIsEncodableSoItIsRefusedByTheGrammarInstead()
        {
            // A pair has a UTF-8 spelling, so the parser reads it and refuses it as text the grammar
            // does not allow, as http_sfv does.
            var caught = Refused(Url, With("Signature-Input", Signed()["Signature-Input"] + "\U00010000"));
            Assert.Equal(FikiErrorKind.MalformedSignatureInput, caught.Kind);
            Assert.DoesNotContain(NoUtf8, caught.Message, StringComparison.Ordinal);
        }

        // --- a keyid ---

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASurrogateInAKeyidOnTheWireIsAnUnencodableSignatureInputAsInPy(int code)
        {
            var headers = Signed();
            var caught = Refused(Url, With("Signature-Input", headers["Signature-Input"].Replace("keyid=\"", "keyid=\"" + Of(code))));
            Assert.Equal(FikiErrorKind.MalformedSignatureInput, caught.Kind);
            Assert.Contains(NoUtf8, caught.Message, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASignersKeyidNonceOrTagWithASurrogateIsACallerErrorAsInPy(int code)
        {
            foreach (var (name, call) in new (string, Action)[]
            {
                ("keyid", () => HttpSignatures.SignRequest(Signer, "GET", Url, created: 1, keyId: "k" + Of(code))),
                ("nonce", () => HttpSignatures.SignRequest(Signer, "GET", Url, created: 1, nonce: "k" + Of(code))),
                ("tag", () => HttpSignatures.SignRequest(Signer, "GET", Url, created: 1, tag: "k" + Of(code))),
            })
            {
                var caught = Assert.Throws<ArgumentException>(call);
                Assert.Contains($"The {name} ", caught.Message, StringComparison.Ordinal);
                Assert.Contains("holds a character outside printable ASCII", caught.Message, StringComparison.Ordinal);
            }
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void AnExpectedKeyidWithASurrogateIsUnknownKeyAsInPy(int code)
        {
            var caught = Refused(Url, Signed(), Verifying.DecliningFreshness().WithExpectedKeyId("k" + Of(code)));
            Assert.Equal(FikiErrorKind.UnknownKey, caught.Kind);
            Assert.Contains("and the one expected is", caught.Message, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void AnExpectedAidWithASurrogateIsMalformedKeyAsInPy(int code)
        {
            var caught = Refused(Url, Signed(), Verifying.DecliningFreshness().WithExpectedAid("k" + Of(code)));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
        }

        // --- a caller-supplied label, component name or method ---

        [Theory]
        [MemberData(nameof(Lone))]
        public void ALabelWithASurrogateIsACallerErrorAsInPy(int code)
        {
            var caught = Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(Signer, "GET", Url, created: 1, label: "s" + Of(code)));
            Assert.Contains("is not an RFC 8941 dictionary key", caught.Message, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void APlainComponentNameWithASurrogateIsACallerErrorAsInPy(int code)
        {
            var covered = new[] { "@method", "@path", "@query", "x-" + Of(code) };
            var caught = Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(Signer, "GET", Url, covered: covered, created: 1));
            Assert.Contains("is not a component fiki can name", caught.Message, StringComparison.Ordinal);
            var minimum = Assert.Throws<ArgumentException>(() => HttpSignatures.VerifyRequest("POST", Url, Signed(),
                VerifyOptions.DecliningFreshness().DecliningAuthorityCheck().WithMinimum(covered).WithBody(Body)));
            Assert.Contains("is not a component fiki can name", minimum.Message, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void ASerializedComponentWithASurrogateIsUnsupportedComponentAsInPy(int code)
        {
            foreach (var spec in new[] { "\"x-" + Of(code) + "\"", "\"x\";" + Of(code) })
            {
                var caught = Assert.Throws<FikiException>(() =>
                    HttpSignatures.SignRequest(Signer, "GET", Url, covered: new[] { "@method", "@path", "@query", spec }, created: 1));
                Assert.Equal(FikiErrorKind.UnsupportedComponent, caught.Kind);
                Assert.Contains("as a component identifier", caught.Message, StringComparison.Ordinal);
            }
        }

        [Theory]
        [MemberData(nameof(Lone))]
        public void AMethodWithASurrogateIsACallerErrorAsInPy(int code)
        {
            var caught = Assert.Throws<ArgumentException>(() => HttpSignatures.VerifyRequest("P" + Of(code), Url, Signed(), Verifying.DecliningFreshness()));
            Assert.Contains("is not an HTTP method", caught.Message, StringComparison.Ordinal);
        }

        // --- what reaches a message is escaped, never raw ---

        [Theory]
        [MemberData(nameof(Lone))]
        public void ALoneSurrogateNeverReachesARefusalsMessageRaw(int code)
        {
            var caught = Refused(Url, Signed(), Verifying.DecliningFreshness().WithExpectedKeyId("k" + Of(code)));
            Assert.DoesNotContain(Of(code), caught.Message, StringComparison.Ordinal);
            Assert.Contains("\\u" + code.ToString("x4"), caught.Message, StringComparison.Ordinal);
        }
    }
}
