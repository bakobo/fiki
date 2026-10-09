using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>Cross-port rulings from the hostile reviews of bakobo/fiki#6 and #8, each pinned.</summary>
    public class RulingTests
    {
        private static readonly Key Signer = Key.FromSeed(Bytes.Range(0, 32));
        private const string Url = "https://api.example.com/things?limit=1";
        private static readonly byte[] Body = Bytes.Utf8("{\"hello\": \"world\"}");

        private static KeyValuePair<string, string> H(string name, string value) => new KeyValuePair<string, string>(name, value);

        // --- A (D-Q9ZT): two field names equal case-insensitively are refused, not collapsed ---

        public static IEnumerable<object[]> Twins() => new[]
        {
            // A covered field, an uncovered one, the body's digest, and one name given twice alike.
            new object[] { "X-Role", "x-role", true },
            new object[] { "X-Other", "X-OTHER", false },
            new object[] { "Content-Digest", "content-digest", true },
            new object[] { "X-Role", "X-Role", true },
        };

        private static List<KeyValuePair<string, string>> With(IEnumerable<KeyValuePair<string, string>> headers, string first, string second) =>
            headers.Concat(new[] { H(first, "member"), H(second, "admin") }).ToList();

        private static string[] Covered(bool coverRole) =>
            coverRole ? new[] { "@method", "@path", "@query", "x-role", "content-digest" } : new[] { "@method", "@path", "@query", "content-digest" };

        private static void Refused(Action action) =>
            Assert.Contains("more than once", Assert.Throws<ArgumentException>(action).Message);

        private static bool CoversRole(string first, bool covered) => covered && first == "X-Role";

        private static KeyValuePair<string, string>[] Given(string first) =>
            first == "Content-Digest" ? new KeyValuePair<string, string>[0] : new[] { H(first, "member") };

        /// <summary>The signed message's headers plus a second field whose name equals the first's case-insensitively.</summary>
        private static List<KeyValuePair<string, string>> Twinned(string first, string second, IReadOnlyDictionary<string, string> signed)
        {
            var headers = Given(first).Concat(signed).ToList();
            headers.Add(H(second, first == "Content-Digest" ? signed["Content-Digest"] : "admin"));
            return headers;
        }

        [Theory]
        [MemberData(nameof(Twins))]
        public void SigningARequestRefusesTwinNames(string first, string second, bool covered) =>
            Refused(() => HttpSignatures.SignRequest(Signer, "POST", Url, With(new KeyValuePair<string, string>[0], first, second), Body,
                CoversRole(first, covered) ? Covered(true) : null));

        [Theory]
        [MemberData(nameof(Twins))]
        public void VerifyingARequestRefusesTwinNames(string first, string second, bool covered)
        {
            var signed = HttpSignatures.SignRequest(Signer, "POST", Url, Given(first), Body, CoversRole(first, covered) ? Covered(true) : null);
            Assert.Equal(Signer.Aid, HttpSignatures.VerifyRequest("POST", Url, Given(first).Concat(signed), Verifying.DecliningFreshness().WithBody(Body)).Aid);
            Refused(() => HttpSignatures.VerifyRequest("POST", Url, Twinned(first, second, signed), Verifying.DecliningFreshness().WithBody(Body)));
        }

        [Theory]
        [MemberData(nameof(Twins))]
        public void SigningAndVerifyingAResponseRefuseTwinNames(string first, string second, bool covered)
        {
            var coveredList = CoversRole(first, covered) ? new[] { "@status", "x-role", "content-digest" } : null;
            Refused(() => HttpSignatures.SignResponse(Signer, 200, headers: With(new KeyValuePair<string, string>[0], first, second), body: Body, covered: coveredList));
            var signed = HttpSignatures.SignResponse(Signer, 200, headers: Given(first), body: Body, covered: coveredList);
            Assert.Equal(Signer.Aid, HttpSignatures.VerifyResponse(200, Given(first).Concat(signed), Verifying.DecliningFreshness().WithBody(Body)).Aid);
            Refused(() => HttpSignatures.VerifyResponse(200, Twinned(first, second, signed), Verifying.DecliningFreshness().WithBody(Body)));
        }

        [Fact]
        public void AnUnsignedUnauthorizedResponseWithTwinNamesIsRefusedForTheTwins() =>
            Refused(() => HttpSignatures.VerifyResponse(401, new[] { H("X-Role", "a"), H("x-role", "b") }, Verifying.DecliningFreshness()));

        [Fact]
        public void ThePairedRequestIsHeldToTheSameRule()
        {
            var twins = new Request("POST", Url, new[] { H("X-Role", "member"), H("x-role", "admin") });
            Refused(() => HttpSignatures.SignResponse(Signer, 200, twins));
            var plain = new Request("POST", Url, new[] { H("X-Role", "member") });
            var signed = HttpSignatures.SignResponse(Signer, 200, plain);
            Refused(() => HttpSignatures.VerifyResponse(200, signed, Verifying.DecliningFreshness().WithRequest(twins)));
            Refused(() => HttpSignatures.ResponseSignatureBase(200, new KeyValuePair<string, string>[0], new[] { "@status" }, 1, "k", twins));
        }

        [Fact]
        public void TheBaseBuildersRefuseTwinNames()
        {
            Refused(() => HttpSignatures.SignatureBase("GET", Url, new[] { H("X-Role", "a"), H("x-role", "b") }, new[] { "@method" }, 1, "k"));
            Refused(() => HttpSignatures.ResponseSignatureBase(200, new[] { H("X-Role", "a"), H("x-role", "b") }, new[] { "@status" }, 1, "k"));
        }

        [Fact]
        public void DistinctNamesStillSignAndVerify()
        {
            var given = new[] { H("X-Role", "member"), H("X-Other", "y") };
            var signed = HttpSignatures.SignRequest(Signer, "POST", Url, given, Body, Covered(true));
            var headers = given.Concat(signed).ToList();
            Assert.Equal(Signer.Aid, HttpSignatures.VerifyRequest("POST", Url, headers, Verifying.DecliningFreshness().WithBody(Body)).Aid);
        }
    }
}
