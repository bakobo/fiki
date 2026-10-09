using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>Findings from a hostile review of the port (bakobo/fiki#7), each pinned by a test.</summary>
    public class HostileTests
    {
        private static readonly Key Signer = Key.FromSeed(Bytes.Range(0, 32));
        private const string Url = "https://api.example.com/things?limit=1";
        private static readonly byte[] Signed = Bytes.Utf8("{\"hello\": \"world\"}");
        private static readonly byte[] Swapped = Bytes.Utf8("{\"hello\": \"mallory\"}");

        /// <summary>
        /// Headers that change between enumerations: the first pass serves what was signed, every
        /// later pass serves a Content-Digest that matches a swapped body. A verifier that reads the
        /// headers twice builds its base from one and checks the body against the other.
        /// </summary>
        private sealed class Shifting : IEnumerable<KeyValuePair<string, string>>
        {
            private readonly List<KeyValuePair<string, string>> _first;
            private readonly List<KeyValuePair<string, string>> _later;

            public Shifting(IEnumerable<KeyValuePair<string, string>> first, string laterDigest)
            {
                _first = first.ToList();
                _later = _first.Select(h => h.Key == "Content-Digest" ? new KeyValuePair<string, string>(h.Key, laterDigest) : h).ToList();
            }

            public int Enumerations { get; private set; }

            public IEnumerator<KeyValuePair<string, string>> GetEnumerator() => (Enumerations++ == 0 ? _first : _later).GetEnumerator();

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }

        // --- 1: the caller's headers are read exactly once ---

        [Fact]
        public void AVerifierReadsARequestsHeadersOnceSoTheyCannotChangeUnderIt()
        {
            var headers = new Shifting(HttpSignatures.SignRequest(Signer, "POST", Url, body: Signed), HttpSignatures.ContentDigest(Swapped));
            var caught = Assert.Throws<FikiException>(() =>
                HttpSignatures.VerifyRequest("POST", Url, headers, Verifying.DecliningFreshness().WithBody(Swapped)));
            Assert.Equal(FikiErrorKind.DigestMismatch, caught.Kind);
            Assert.Equal(1, headers.Enumerations);
        }

        [Fact]
        public void AVerifierReadsAResponsesHeadersOnceSoTheyCannotChangeUnderIt()
        {
            var headers = new Shifting(HttpSignatures.SignResponse(Signer, 200, body: Signed), HttpSignatures.ContentDigest(Swapped));
            var caught = Assert.Throws<FikiException>(() =>
                HttpSignatures.VerifyResponse(200, headers, Verifying.DecliningFreshness().WithBody(Swapped)));
            Assert.Equal(FikiErrorKind.DigestMismatch, caught.Kind);
            Assert.Equal(1, headers.Enumerations);
        }

        [Fact]
        public void AnUnsignedUnauthorizedResponseIsJudgedOnTheSameSingleReading()
        {
            var headers = new Shifting(new[] { new KeyValuePair<string, string>("Content-Digest", "x") }, "y");
            Assert.Equal(FikiErrorKind.Unauthenticated, Assert.Throws<FikiException>(() =>
                HttpSignatures.VerifyResponse(401, headers, Verifying.DecliningFreshness())).Kind);
            Assert.Equal(1, headers.Enumerations);
        }

        [Fact]
        public void SignersAndBaseBuildersReadTheHeadersOnce()
        {
            var given = new[] { new KeyValuePair<string, string>("X-Note", "a") };
            var request = new Shifting(given, "unused");
            HttpSignatures.SignRequest(Signer, "POST", Url, request, Signed);
            Assert.Equal(1, request.Enumerations);
            var response = new Shifting(given, "unused");
            HttpSignatures.SignResponse(Signer, 200, headers: response, body: Signed);
            Assert.Equal(1, response.Enumerations);
            var bas = new Shifting(given, "unused");
            HttpSignatures.SignatureBase("GET", Url, bas, new[] { "x-note" }, 1, "k");
            Assert.Equal(1, bas.Enumerations);
            var responseBase = new Shifting(given, "unused");
            HttpSignatures.ResponseSignatureBase(200, responseBase, new[] { "x-note" }, 1, "k");
            Assert.Equal(1, responseBase.Enumerations);
            var answered = new Shifting(given, "unused");
            new Request("GET", Url, answered);
            Assert.Equal(1, answered.Enumerations);
        }

        // --- 2: a long covered list costs linear work ---

        private static string[] Distinct(int count) => Enumerable.Range(0, count).Select(i => $"x-{i}").ToArray();

        private static double Seconds(Action action)
        {
            var clock = Stopwatch.StartNew();
            action();
            return clock.Elapsed.TotalSeconds;
        }

        [Fact]
        public void FiftyThousandDistinctCoveredComponentsAreCheckedInWellUnderASecond()
        {
            // A received Signature-Input this long is over MaxFieldBytes and refused before it is
            // parsed (@5zrf8gjk); a caller's own list is not bounded, and the work is linear, as py's
            // set in check_covered makes it.
            var covered = Distinct(50000);
            var input = "sig=(" + string.Join(" ", covered.Select(c => "\"" + c + "\"")) + ");created=1;keyid=\"k\"";
            var headers = new Dictionary<string, string> { { "Signature-Input", input }, { "Signature", "sig=:" + Convert.ToBase64String(new byte[64]) + ":" } };
            var verify = Seconds(() => Assert.Equal(FikiErrorKind.MalformedSignatureInput, Assert.Throws<FikiException>(() =>
                HttpSignatures.VerifyRequest("GET", Url, headers, Verifying.DecliningFreshness().WithExpectedAid(Signer.Aid))).Kind));
            var sign = Seconds(() => Assert.Equal(FikiErrorKind.MissingComponent, Assert.Throws<FikiException>(() =>
                HttpSignatures.SignatureBase("GET", Url, new Dictionary<string, string>(), covered, 1, "k")).Kind));
            Assert.True(verify < 1, $"verifying took {verify}s");
            Assert.True(sign < 1, $"building the base took {sign}s");
        }

        [Fact]
        public void FiftyThousandParametersOrMembersParseInWellUnderASecond()
        {
            var parameters = "sig=(\"@method\")" + string.Concat(Enumerable.Range(0, 50000).Select(i => $";p{i}=1"));
            var members = string.Join(", ", Enumerable.Range(0, 50000).Select(i => $"m{i}=:AAAA:"));
            Assert.True(Seconds(() => Sfv.ParseDictionary(parameters)) < 1);
            Assert.True(Seconds(() => Sfv.ParseDictionary(members)) < 1);
        }

        [Fact]
        public void ADuplicateAtTheEndOfALongListIsStillFoundWhateverItsParameterOrder()
        {
            var covered = Distinct(50000).Concat(new[] { "\"x-7\";req;sf", "\"x-7\";sf;req" }).ToArray();
            var caught = Assert.Throws<FikiException>(() =>
                HttpSignatures.ResponseSignatureBase(200, new Dictionary<string, string>(), covered, 1, "k"));
            Assert.Equal(FikiErrorKind.DuplicateComponent, caught.Kind);
            Assert.Equal("\"x-7\";sf;req", caught.Component);
        }

        // --- 3: a signer refuses a label that would make its own headers unparseable ---

        [Theory]
        [InlineData("bad label")]
        [InlineData("Sig")]
        [InlineData("")]
        [InlineData("1sig")]
        [InlineData("sig=")]
        [InlineData("s\u00e9g")]
        public void ASignerRefusesALabelThatIsNotAnRfc8941Key(string label)
        {
            // fiki-py writes any label it is given; this port refuses one its own verifier, and
            // every other, could not parse back (a divergence, and no wire change).
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(Signer, "GET", Url, label: label));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignResponse(Signer, 200, label: label));
        }

        [Theory]
        [InlineData("sig")]
        [InlineData("a-b")]
        [InlineData("x*1")]
        [InlineData("*")]
        [InlineData("signify")]
        public void AValidLabelSignsAndVerifies(string label)
        {
            var request = HttpSignatures.SignRequest(Signer, "POST", Url, body: Signed, label: label);
            Assert.StartsWith(label + "=(", request["Signature-Input"], StringComparison.Ordinal);
            Assert.Equal(Signer.Aid, HttpSignatures.VerifyRequest("POST", Url, request, Verifying.MaxAge(60).WithBody(Signed)).Aid);
            var response = HttpSignatures.SignResponse(Signer, 200, body: Signed, label: label);
            Assert.Equal(Signer.Aid, HttpSignatures.VerifyResponse(200, response, Verifying.MaxAge(60).WithBody(Signed)).Aid);
        }

        // --- a Request's headers cannot change after it is checked ---

        [Fact]
        public void ARequestsHeadersCannotBeChangedThroughACast()
        {
            // HeaderSnapshot.Check validates a Request's headers once and later steps read them
            // again, which is sound only if nothing can change them in between.
            var request = new Request("POST", Url, new[] { new KeyValuePair<string, string>("X-Role", "member") });
            Assert.False(request.Headers is List<KeyValuePair<string, string>>);
            var list = Assert.IsAssignableFrom<IList<KeyValuePair<string, string>>>(request.Headers);
            Assert.Throws<NotSupportedException>(() => list.Add(new KeyValuePair<string, string>("x-role", "admin")));
            Assert.Throws<NotSupportedException>(() => list[0] = new KeyValuePair<string, string>("X-Role", "admin"));
            Assert.Equal("member", request.Headers.Single().Value);
        }
    }
}
