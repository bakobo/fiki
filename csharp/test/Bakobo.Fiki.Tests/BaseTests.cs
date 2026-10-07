using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The signature base builder beyond what RFC 9421's own vector reaches (this.i @2hwvpm42),
    /// mirroring py/tests/test_base.py: @query, the authority's normalization, and the refusals.
    /// </summary>
    public class BaseTests
    {
        internal static KeyValuePair<string, string>[] H(params string[] pairs)
        {
            var headers = new KeyValuePair<string, string>[pairs.Length / 2];
            for (var i = 0; i < headers.Length; i++)
            {
                headers[i] = new KeyValuePair<string, string>(pairs[2 * i], pairs[2 * i + 1]);
            }
            return headers;
        }

        /// <summary>The one base line for a single covered component.</summary>
        private static string LineFor(string component, string method = "POST",
            string url = "https://example.com/foo?param=Value&Pet=dog", KeyValuePair<string, string>[]? headers = null)
        {
            var bas = HttpSignatures.SignatureBase(method, url, headers ?? H(), new[] { component }, 1618884473, "test-key-ed25519");
            return Bytes.Text(bas).Split('\n')[0];
        }

        [Fact]
        public void QueryCarriesItsLeadingQuestionMark() =>
            Assert.Equal("\"@query\": ?param=Value&Pet=dog", LineFor("@query"));

        [Fact]
        public void QueryOfARequestWithNoQueryIsABareQuestionMark() =>
            Assert.Equal("\"@query\": ?", LineFor("@query", url: "https://example.com/foo"));

        [Fact]
        public void PercentEncodingInTheQueryIsNotDecoded() =>
            Assert.Equal("\"@query\": ?baz=bat%2Dman", LineFor("@query", url: "https://example.com/p?baz=bat%2Dman"));

        [Fact]
        public void AnEmptyPathIsTheSlashTheOriginServerSees() =>
            Assert.Equal("\"@path\": /", LineFor("@path", url: "https://example.com"));

        [Fact]
        public void AuthorityLowercasesTheHostAndOmitsADefaultPort() =>
            Assert.Equal("\"@authority\": example.com", LineFor("@authority", url: "https://EXAMPLE.com:443/f"));

        [Fact]
        public void AuthorityKeepsANonDefaultPort() =>
            Assert.Equal("\"@authority\": example.com:8443", LineFor("@authority", url: "https://example.com:8443/f"));

        [Fact]
        public void AuthorityNormalizesThePortsSpelling() =>
            Assert.Equal("\"@authority\": example.com:8443", LineFor("@authority", url: "https://example.com:08443/f"));

        [Fact]
        public void AuthorityOmitsTheDefaultPortOfEachSchemeAndOnlyThatOne()
        {
            Assert.Equal("\"@authority\": h", LineFor("@authority", url: "http://h:80/"));
            Assert.Equal("\"@authority\": h", LineFor("@authority", url: "wss://h:443/"));
            Assert.Equal("\"@authority\": h:443", LineFor("@authority", url: "http://h:443/"));
            Assert.Equal("\"@authority\": h:80", LineFor("@authority", url: "ftp://h:80/"));
        }

        [Fact]
        public void AuthorityDropsIPv6BracketsAsFikiPyDoes()
        {
            // py builds f"{host}:{port}" from urlsplit's .hostname, which carries no brackets.
            Assert.Equal("\"@authority\": ::1:8080", LineFor("@authority", url: "https://[::1]:8080/"));
        }

        [Fact]
        public void AnAuthorityWithNoHostIsItsPortAlone()
        {
            // urlsplit gives no hostname for "https://:8080/x", and py builds f"{''}:{8080}".
            Assert.Equal("\"@authority\": :8080", LineFor("@authority", url: "https://:8080/x"));
            Assert.Equal("\"@authority\": ", LineFor("@authority", url: "https://u@/x"));
        }

        [Fact]
        public void AnUnreadablePortIsACallerError()
        {
            Assert.Throws<ArgumentException>(() => LineFor("@authority", url: "https://h:x/"));
            Assert.Throws<ArgumentException>(() => LineFor("@path", url: "https://[::1/"));
        }

        [Fact]
        public void MethodIsTheMethodAsSentWithNoCaseTransformation()
        {
            // RFC 9421 section 2.2.1 and @22g0xkr8: "post" and "POST" are different methods.
            Assert.Equal("\"@method\": post", LineFor("@method", method: "post"));
        }

        [Fact]
        public void HeaderValuesAreStrippedAndNamedInLowercase() =>
            Assert.Equal("\"content-type\": application/json",
                LineFor("Content-Type", headers: H("Content-Type", "  application/json  ")));

        [Fact]
        public void ALaterHeaderOfTheSameNameInAnotherCaseWins() =>
            Assert.Equal("\"x-a\": second", LineFor("x-a", headers: H("X-A", "first", "x-a", "second")));

        [Fact]
        public void ADerivedComponentFikiCannotBuildIsRefusedRatherThanSkipped()
        {
            var caught = Assert.Throws<FikiException>(() => LineFor("@target-uri"));
            Assert.Equal(FikiErrorKind.UnsupportedComponent, caught.Kind);
            Assert.Equal("@target-uri", caught.Component);
            Assert.Equal("@method, @authority, @path, @query", caught.Supported);
        }

        [Fact]
        public void ACoveredHeaderTheRequestLacksIsRefused()
        {
            var caught = Assert.Throws<FikiException>(() => LineFor("x-absent"));
            Assert.Equal(FikiErrorKind.MissingComponent, caught.Kind);
            Assert.Equal("x-absent", caught.Component);
        }

        [Fact]
        public void SignatureParamsSerializesTheOptionalParametersInAFixedOrder()
        {
            var bas = HttpSignatures.SignatureBase("POST", "https://example.com/foo", H(), new[] { "@method" },
                1618884473, "k", alg: "ed25519", expires: 1618884573, nonce: "abc", tag: "app");
            var lines = Bytes.Text(bas).Split('\n');
            Assert.Equal(
                "\"@signature-params\": (\"@method\");created=1618884473;expires=1618884573;" +
                "nonce=\"abc\";alg=\"ed25519\";keyid=\"k\";tag=\"app\"",
                lines[lines.Length - 1]);
        }

        [Fact]
        public void AParameterOutsideRfc8941IsACallerError()
        {
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignatureBase("GET", "/", H(), new[] { "@method" }, 1, "café"));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignatureBase("GET", "/", H(), new[] { "@method" }, 1000000000000000, "k"));
        }

        // --- authority when the caller has a path rather than a full URL ---

        [Fact]
        public void AuthorityFallsBackToTheHostHeaderWhenTheUrlHasNone() =>
            Assert.Equal("\"@authority\": api.example.com",
                LineFor("@authority", url: "/things?limit=1", headers: H("Host", "API.example.com")));

        [Fact]
        public void ARelativeUrlStillYieldsPathAndQuery()
        {
            Assert.Equal("\"@path\": /things", LineFor("@path", url: "/things?limit=1"));
            Assert.Equal("\"@query\": ?limit=1", LineFor("@query", url: "/things?limit=1"));
        }

        [Fact]
        public void AHostHeaderPortIsPreservedBecauseNoSchemeDeclaresItDefault() =>
            Assert.Equal("\"@authority\": example.com:8443",
                LineFor("@authority", url: "/x", headers: H("Host", "example.com:8443")));

        [Fact]
        public void CoveringAuthorityWithNeitherAUrlAuthorityNorAHostHeaderIsRefused()
        {
            var caught = Assert.Throws<FikiException>(() => LineFor("@authority", url: "/things"));
            Assert.Equal(FikiErrorKind.MissingComponent, caught.Kind);
            Assert.Equal("@authority", caught.Component);
        }

        // --- component identifiers ---

        [Fact]
        public void ReqNamesARequestComponentFromAResponse()
        {
            Assert.Equal("\"@method\";req", HttpSignatures.Req("@Method"));
            Assert.Equal("\"content-digest\";req", HttpSignatures.Req("Content-Digest"));
        }

        [Fact]
        public void TheDerivedAndDefaultSetsAreFikiPys()
        {
            Assert.Equal(new[] { "@method", "@authority", "@path", "@query" }, HttpSignatures.Derived);
            Assert.Equal(new[] { "@method", "@authority", "@path", "@query" }, HttpSignatures.DefaultCovered);
        }

        [Fact]
        public void AMalformedSerializedComponentIsUnsupported()
        {
            var caught = Assert.Throws<FikiException>(() => LineFor("\"@path"));
            Assert.Equal(FikiErrorKind.UnsupportedComponent, caught.Kind);
            Assert.Equal("\"@path", caught.Component);
            Assert.Equal("@method, @authority, @path, @query, @status", caught.Supported);
        }

        [Fact]
        public void ASerializedComponentIsLowercasedAsAPlainOneIs() =>
            Assert.Equal("\"@path\": /foo", LineFor("\"@PATH\""));

        [Fact]
        public void AValueThatCannotBeSerializedTheSameWayEverywhereIsASignatureMismatch()
        {
            foreach (var value in new[] { "café", "two\nlines", "bell\u0007" })
            {
                var caught = Assert.Throws<FikiException>(() => LineFor("x-note", headers: H("X-Note", value)));
                Assert.Equal(FikiErrorKind.SignatureMismatch, caught.Kind);
            }
            Assert.Equal("\"x-note\": a\tb", LineFor("x-note", headers: H("X-Note", "a\tb")));
        }

        // --- responses ---

        private static string StatusLine(int status) => Bytes.Text(HttpSignatures.ResponseSignatureBase(
            status, H(), new[] { "@status" }, 1700000000, "k")).Split('\n')[0];

        [Theory]
        [InlineData(100)]
        [InlineData(204)]
        [InlineData(999)]
        public void TheStatusLineIsThreeDigits(int status) =>
            Assert.Equal($"\"@status\": {status}", StatusLine(status));

        [Theory]
        [InlineData(99)]
        [InlineData(1000)]
        [InlineData(-200)]
        public void AStatusThatIsNotThreeDigitsHasNoStatusLine(int status)
        {
            var caught = Assert.Throws<FikiException>(() => StatusLine(status));
            Assert.Equal(FikiErrorKind.MissingComponent, caught.Kind);
            Assert.Equal("@status", caught.Component);
        }

        [Fact]
        public void TheReqLinesCarryTheRequestValues()
        {
            var request = new Request("POST", "https://keria.example.com/identifiers?type=rot",
                H("Content-Digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"));
            var lines = Bytes.Text(HttpSignatures.ResponseSignatureBase(200, H(),
                new[] { "@status", HttpSignatures.Req("@method"), HttpSignatures.Req("@path"), HttpSignatures.Req("@query"), HttpSignatures.Req("content-digest") },
                1700000000, "k", request: request)).Split('\n');
            Assert.Equal(new[]
            {
                "\"@status\": 200",
                "\"@method\";req: POST",
                "\"@path\";req: /identifiers",
                "\"@query\";req: ?type=rot",
                "\"content-digest\";req: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
            }, lines.Take(5).ToArray());
        }

        [Fact]
        public void AReqComponentWithNoRequestToReadItFromIsMissing()
        {
            var caught = Assert.Throws<FikiException>(() => HttpSignatures.ResponseSignatureBase(
                200, H(), new[] { "@status", HttpSignatures.Req("@path") }, 1700000000, "k"));
            Assert.Equal(FikiErrorKind.MissingComponent, caught.Kind);
            Assert.Equal("\"@path\";req", caught.Component);
        }

        [Fact]
        public void AResponseRefusesARequestComponentNamedWithoutReq()
        {
            var caught = Assert.Throws<FikiException>(() => HttpSignatures.ResponseSignatureBase(
                200, H(), new[] { "@status", "@path" }, 1700000000, "k"));
            Assert.Equal(FikiErrorKind.UnsupportedComponent, caught.Kind);
            Assert.Equal("@status", caught.Supported);
        }

        [Fact]
        public void ARequestRefusesAComponentParameter()
        {
            var caught = Assert.Throws<FikiException>(() => LineFor(HttpSignatures.Req("@path")));
            Assert.Equal(FikiErrorKind.UnsupportedComponent, caught.Kind);
            Assert.Equal("req", caught.Supported);
            Assert.Equal("\"@path\";req", caught.Component);
        }

        [Fact]
        public void ADuplicateComponentIsRefusedBeforeAnUnsupportedOne()
        {
            var caught = Assert.Throws<FikiException>(() => HttpSignatures.SignatureBase(
                "GET", "/", H(), new[] { "@target-uri", "@target-uri" }, 1, "k"));
            Assert.Equal(FikiErrorKind.DuplicateComponent, caught.Kind);
            Assert.Equal("@target-uri", caught.Component);
        }

        [Theory]
        [InlineData("\"@path\";req", "\"@path\";req", true)]
        [InlineData("\"@path\";req;sf", "\"@path\";sf;req", true)]
        [InlineData("\"@path\";req", "\"@path\";req=1", true)]
        [InlineData("\"@path\";req", "\"@path\";sf", false)]
        [InlineData("\"@path\";req", "\"@path\";req=?0", false)]
        [InlineData("\"@path\";req", "\"@path\"", false)]
        [InlineData("\"@path\";req", "\"@query\";req", false)]
        public void TwoIdentifiersNameOneComponentWhenValueAndParametersAgreeInAnyOrder(string a, string b, bool same)
        {
            // py's identity(): the value and the sorted parameters, compared as Python compares
            // them, so req=1 is req (True == 1).
            Assert.Equal(same, Components.SameComponent(Components.Component(a), Components.Component(b)));
        }

        [Fact]
        public void ARequestCarriesWhatItWasGiven()
        {
            var body = Bytes.Utf8("x");
            var request = new Request("GET", "/", H("A", "1"), body);
            body[0] = (byte)'y';
            Assert.Equal("GET", request.Method);
            Assert.Equal("/", request.Url);
            Assert.Equal(H("A", "1"), request.Headers);
            Assert.Equal(Bytes.Utf8("x"), request.Body);
            Assert.Null(new Request("GET", "/").Body);
            Assert.Empty(new Request("GET", "/").Headers);
        }
    }
}
