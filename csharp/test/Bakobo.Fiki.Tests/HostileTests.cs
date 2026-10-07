using System;
using System.Collections;
using System.Collections.Generic;
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
                HttpSignatures.VerifyRequest("POST", Url, headers, VerifyOptions.DecliningFreshness().WithBody(Swapped)));
            Assert.Equal(FikiErrorKind.DigestMismatch, caught.Kind);
            Assert.Equal(1, headers.Enumerations);
        }

        [Fact]
        public void AVerifierReadsAResponsesHeadersOnceSoTheyCannotChangeUnderIt()
        {
            var headers = new Shifting(HttpSignatures.SignResponse(Signer, 200, body: Signed), HttpSignatures.ContentDigest(Swapped));
            var caught = Assert.Throws<FikiException>(() =>
                HttpSignatures.VerifyResponse(200, headers, VerifyOptions.DecliningFreshness().WithBody(Swapped)));
            Assert.Equal(FikiErrorKind.DigestMismatch, caught.Kind);
            Assert.Equal(1, headers.Enumerations);
        }

        [Fact]
        public void AnUnsignedUnauthorizedResponseIsJudgedOnTheSameSingleReading()
        {
            var headers = new Shifting(new[] { new KeyValuePair<string, string>("Content-Digest", "x") }, "y");
            Assert.Equal(FikiErrorKind.Unauthenticated, Assert.Throws<FikiException>(() =>
                HttpSignatures.VerifyResponse(401, headers, VerifyOptions.DecliningFreshness())).Kind);
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
    }
}
