using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// Every implementation runs the shared vectors at the repository root (this.i @5gf6r08f),
    /// mirroring py/tests/test_vectors.py. A thin driver: everything a port needs is in the JSON.
    /// </summary>
    public class VectorsTests
    {
        private static readonly string[] Files = { "aid-lens.json", "signature-base.json", "accepts.json", "refusals.json" };

        private static JsonElement Load(string name) => Repo.Json("vectors", name);

        private static IEnumerable<object[]> Cases(string name) =>
            Load(name).GetProperty("cases").EnumerateArray().Select(c => new object[] { c.GetProperty("id").GetString()! });

        private static JsonElement Case(string name, string id) =>
            Load(name).GetProperty("cases").EnumerateArray().Single(c => c.GetProperty("id").GetString() == id);

        public static IEnumerable<object[]> FileNames() => Files.Select(f => new object[] { f });

        public static IEnumerable<object[]> AidLens() => Cases("aid-lens.json");

        public static IEnumerable<object[]> SignatureBases() => Cases("signature-base.json");

        public static IEnumerable<object[]> Accepts() => Cases("accepts.json");

        public static IEnumerable<object[]> Refusals() => Cases("refusals.json");

        internal static List<KeyValuePair<string, string>> Headers(JsonElement headers) =>
            headers.EnumerateObject().Select(p => new KeyValuePair<string, string>(p.Name, p.Value.GetString()!)).ToList();

        internal static byte[]? Body(JsonElement message) =>
            message.GetProperty("body").ValueKind == JsonValueKind.Null ? null : Bytes.Utf8(message.GetProperty("body").GetString()!);

        private static string? Optional(JsonElement c, string name) =>
            c.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value.GetString() : null;

        private static long? OptionalLong(JsonElement c, string name) =>
            c.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value.GetInt64() : (long?)null;

        [Theory]
        [MemberData(nameof(FileNames))]
        public void ThisPortSatisfiesTheVectorsFormatItIsRunning(string name)
        {
            // A port running newer vectors fails here rather than passing a subset (@4fhrre0m).
            Assert.Equal(HttpSignatures.VectorsFormat, Load(name).GetProperty("vectors_format").GetInt32());
        }

        [Fact]
        public void TheVectorsAreWhereEveryPortCanReachThem()
        {
            // Found by what the directory holds, never by its name (tick 32mh): this worktree is
            // not named "fiki", and neither is every clone.
            Assert.True(Directory.Exists(Repo.PathTo("vectors")));
            Assert.True(File.Exists(Repo.PathTo("this.i")));
            Assert.True(Directory.Exists(Repo.PathTo("csharp")));
        }

        [Fact]
        public void TheRootIsFoundByWhatItHoldsAndAMissingOneIsSaidPlainly()
        {
            Assert.Equal(Repo.Root, Repo.FindRoot(Path.Combine(Repo.Root, "csharp", "test")));
            Assert.Throws<DirectoryNotFoundException>(() => Repo.FindRoot(Path.GetTempPath()));
        }

        [Theory]
        [MemberData(nameof(AidLens))]
        public void TheAidLens(string id)
        {
            // A seed to its AID and back: the one thing here RFC 9421 knows nothing about.
            var c = Case("aid-lens.json", id);
            var key = Key.FromSeed(Bytes.FromHex(c.GetProperty("seed_hex").GetString()!));
            Assert.Equal(c.GetProperty("aid").GetString(), key.Aid);
            Assert.Equal(c.GetProperty("keyid").GetString(), Bytes.B64Url(Bytes.FromHex(c.GetProperty("public_key_hex").GetString()!)));
            Assert.Equal(c.GetProperty("public_key_hex").GetString(), Bytes.ToHex(Key.VerifyingKey(key.Aid).ToBytes()));
        }

        private static byte[] BaseOf(JsonElement c) => HttpSignatures.SignatureBase(
            c.GetProperty("method").GetString()!,
            c.GetProperty("url").GetString()!,
            Headers(c.GetProperty("headers")),
            c.GetProperty("covered").EnumerateArray().Select(x => x.GetString()!),
            c.GetProperty("created").GetInt64(),
            c.GetProperty("keyid").GetString()!,
            alg: Optional(c, "alg"));

        [Theory]
        [MemberData(nameof(SignatureBases))]
        public void SignatureBaseVectors(string id)
        {
            // Byte equality on the base, which is where two implementations actually disagree.
            var c = Case("signature-base.json", id);
            Assert.Equal(c.GetProperty("base").GetString(), Bytes.Text(BaseOf(c)));
        }

        [Theory]
        [MemberData(nameof(SignatureBases))]
        public void SignatureVectors(string id)
        {
            // Ed25519 is deterministic, so a port that builds the right base produces the right bytes.
            var c = Case("signature-base.json", id);
            var signature = Key.FromSeed(Bytes.FromHex(c.GetProperty("seed_hex").GetString()!)).Sign(BaseOf(c));
            Assert.Equal(c.GetProperty("signature").GetString(), Convert.ToBase64String(signature));
        }

        private static VerifyOptions Options(JsonElement c)
        {
            var maxAge = OptionalLong(c, "max_age");
            var options = maxAge == null ? VerifyOptions.DecliningFreshness() : VerifyOptions.MaxAge(maxAge.Value);
            var now = OptionalLong(c, "now");
            options = now == null ? options : options.WithNow(now.Value);
            return options.WithBody(Body(c));
        }

        [Theory]
        [MemberData(nameof(Refusals))]
        public void RefusalVectors(string id)
        {
            // Every entry names the error fiki raises, so a port maps its own type onto the same
            // condition rather than inventing a taxonomy of its own.
            var c = Case("refusals.json", id);
            var caught = Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest(
                c.GetProperty("method").GetString()!, c.GetProperty("url").GetString()!, Headers(c.GetProperty("headers")), Options(c)));
            Assert.Equal(c.GetProperty("error").GetString(), caught.Kind.ToString());
        }

        [Theory]
        [MemberData(nameof(Accepts))]
        public void AcceptVectors(string id)
        {
            // Between the others, nothing said a well-formed request must VERIFY, with the right AID
            // and the right covered set.
            var c = Case("accepts.json", id);
            var verdict = HttpSignatures.VerifyRequest(
                c.GetProperty("method").GetString()!, c.GetProperty("url").GetString()!, Headers(c.GetProperty("headers")), Options(c));
            Assert.Equal(c.GetProperty("aid").GetString(), verdict.Aid);
            // Format 2 (@5zrf8gjk): the keyid exactly as it arrived, beside the identity that vouched.
            Assert.Equal(c.GetProperty("keyid").GetString(), verdict.KeyId);
            Assert.Equal(c.GetProperty("covered").EnumerateArray().Select(x => x.GetString()).ToArray(), verdict.Covered.ToArray());
        }

        [Fact]
        public void EveryRefusalNamesAKindThisPortHas()
        {
            var kinds = Enum.GetNames(typeof(FikiErrorKind));
            foreach (var c in Load("refusals.json").GetProperty("cases").EnumerateArray())
            {
                Assert.Contains(c.GetProperty("error").GetString(), kinds);
            }
        }
    }
}
