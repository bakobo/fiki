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
        private static readonly string[] Files =
        {
            "aid-lens.json", "signature-base.json", "accepts.json", "refusals.json", "misuse.json", "signs.json", "responses.json",
        };

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

        public static IEnumerable<object[]> Misuses() => Cases("misuse.json");

        public static IEnumerable<object[]> Signs() => Cases("signs.json");

        public static IEnumerable<object[]> Responses() => Cases("responses.json");

        public static IEnumerable<object[]> VerifyFiles() =>
            new[] { "accepts.json", "refusals.json", "misuse.json", "signs.json", "responses.json" }.Select(f => new object[] { f });

        internal static List<KeyValuePair<string, string>> Headers(JsonElement headers) =>
            headers.EnumerateObject().Select(p => new KeyValuePair<string, string>(p.Name, p.Value.GetString()!)).ToList();

        internal static byte[]? Body(JsonElement message) =>
            message.GetProperty("body").ValueKind == JsonValueKind.Null ? null : Bytes.Utf8(message.GetProperty("body").GetString()!);

        private static string? Optional(JsonElement c, string name) =>
            c.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value.GetString() : null;

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

        // Every field a verify case may carry. A field this driver does not know fails the case
        // rather than being ignored, so a field added to the vectors cannot be silently dropped by a
        // port that never learned it (review V-M8). Mirrors py/tests/test_vectors.py.
        private static readonly HashSet<string> VerifyFields = new HashSet<string>(StringComparer.Ordinal)
        {
            "id", "method", "url", "headers", "body", "max_age", "now", "minimum", "authorities", "expected_aid",
            "note", "error", "aid", "keyid", "covered", "omit", "kind", "status", "request", "expected_keyid",
        };

        // Every field a sign case may carry, refused the same way when unknown.
        private static readonly HashSet<string> SignFields = new HashSet<string>(StringComparer.Ordinal)
        {
            "id", "kind", "seed_hex", "method", "url", "headers", "body", "covered", "created", "expires", "nonce", "tag",
            "minimum", "status", "request", "expected_headers", "error", "note", "keyid", "label",
        };

        private static void KnownFields(JsonElement c, HashSet<string> known)
        {
            var unknown = c.EnumerateObject().Select(p => p.Name).Where(n => !known.Contains(n)).ToList();
            Assert.True(unknown.Count == 0, $"unknown fields {string.Join(", ", unknown)}");
        }

        /// <summary>
        /// Every refusal's message holds no control character and is at most 1024 characters, so an
        /// untrusted value is quoted escaped and cut (this.i @524c8qgv); py's <c>_well_formed</c>.
        /// </summary>
        internal static void WellFormed(Exception error)
        {
            Assert.True(error.Message.Length <= 1024, $"a message of {error.Message.Length} characters");
            Assert.DoesNotContain(error.Message, c => c < 0x20 || c == 0x7f);
        }

        private static string? Text(JsonElement c, string name) =>
            c.GetProperty(name).ValueKind == JsonValueKind.Null ? null : c.GetProperty(name).GetString();

        private static long? Integer(JsonElement c, string name) =>
            c.GetProperty(name).ValueKind == JsonValueKind.Null ? (long?)null : c.GetProperty(name).GetInt64();

        private static IEnumerable<string>? List(JsonElement c, string name) =>
            c.GetProperty(name).ValueKind == JsonValueKind.Null ? null : c.GetProperty(name).EnumerateArray().Select(x => x.GetString()!).ToList();

        private static Request? RequestOf(JsonElement message) => message.ValueKind == JsonValueKind.Null
            ? null
            : new Request(message.GetProperty("method").GetString()!, message.GetProperty("url").GetString()!,
                Headers(message.GetProperty("headers")), Body(message));

        /// <summary>
        /// The verifier's stated policy (format 3, this.i @524c8qgv): a minimum of "default" leaves it
        /// unstated, null is <see cref="VerifyOptions.WithoutMinimum"/>, a list is that minimum;
        /// authorities null is <see cref="VerifyOptions.DecliningAuthorityCheck"/>, a list is those
        /// hosts. Every field named in "omit" is left out of the call.
        /// </summary>
        private static VerifyOptions Options(JsonElement c, bool response)
        {
            KnownFields(c, VerifyFields);
            var omit = c.TryGetProperty("omit", out var o) ? o.EnumerateArray().Select(x => x.GetString()!).ToList() : new List<string>();
            Assert.All(omit, name => Assert.Contains(name, new[] { "authorities", "minimum", "expected_aid", "expected_keyid" }));

            var maxAge = c.GetProperty("max_age");
            var options = maxAge.ValueKind == JsonValueKind.Null ? VerifyOptions.DecliningFreshness() : VerifyOptions.MaxAge(maxAge.GetInt64());
            var now = c.GetProperty("now");
            options = now.ValueKind == JsonValueKind.Null ? options : options.WithNow(now.GetInt64());
            options = options.WithBody(Body(c));

            if (!omit.Contains("minimum"))
            {
                var minimum = c.GetProperty("minimum");
                if (minimum.ValueKind == JsonValueKind.Null)
                {
                    options = options.WithoutMinimum();
                }
                else if (minimum.ValueKind == JsonValueKind.Array)
                {
                    options = options.WithMinimum(minimum.EnumerateArray().Select(x => x.GetString()!));
                }
                else
                {
                    Assert.Equal("default", minimum.GetString());
                }
            }
            if (response)
            {
                // A response's own policy (format 3, this.i @524c8qgv): expected_keyid null is
                // DecliningKeyidCheck, an AID is WithExpectedKeyId, and omitted is neither.
                var request = RequestOf(c.GetProperty("request"));
                options = request == null ? options : options.WithRequest(request);
                if (!omit.Contains("expected_keyid"))
                {
                    var keyId = c.GetProperty("expected_keyid");
                    options = keyId.ValueKind == JsonValueKind.Null ? options.DecliningKeyidCheck() : options.WithExpectedKeyId(keyId.GetString()!);
                }
                return options;
            }
            if (!omit.Contains("expected_aid"))
            {
                var aid = c.GetProperty("expected_aid");
                options = aid.ValueKind == JsonValueKind.Null ? options : options.WithExpectedAid(aid.GetString()!);
            }
            if (!omit.Contains("authorities"))
            {
                options = WithAuthorities(options, c.GetProperty("authorities"));
            }
            return options;
        }

        /// <summary>
        /// A JSON string is the one shape C# refuses at compile time, through an overload marked
        /// Obsolete as an error, so it is reached here by reflection, as the caller's mistake it
        /// models; a member that is not a string becomes a null, the only non-host an
        /// <c>IEnumerable&lt;string&gt;</c> can hold.
        /// </summary>
        private static VerifyOptions WithAuthorities(VerifyOptions options, JsonElement authorities)
        {
            switch (authorities.ValueKind)
            {
                case JsonValueKind.Null:
                    return options.DecliningAuthorityCheck();
                case JsonValueKind.String:
                    var single = typeof(VerifyOptions).GetMethod(nameof(VerifyOptions.WithAuthorities), new[] { typeof(string) })!;
                    try
                    {
                        return (VerifyOptions)single.Invoke(options, new object[] { authorities.GetString()! })!;
                    }
                    catch (System.Reflection.TargetInvocationException ex)
                    {
                        System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.InnerException!).Throw();
                        throw;
                    }
                default:
                    return options.WithAuthorities(authorities.EnumerateArray()
                        .Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() : null).ToList()!);
            }
        }

        /// <summary>
        /// A request, or a response: every case in responses.json, and a misuse case whose kind
        /// says so.
        /// </summary>
        private static Verdict Verify(JsonElement c, bool response = false)
        {
            response |= c.TryGetProperty("kind", out var kind) && kind.GetString() == "response";
            if (response)
            {
                return HttpSignatures.VerifyResponse(c.GetProperty("status").GetInt32(), Headers(c.GetProperty("headers")), Options(c, response));
            }
            return HttpSignatures.VerifyRequest(
                c.GetProperty("method").GetString()!, c.GetProperty("url").GetString()!, Headers(c.GetProperty("headers")), Options(c, response));
        }

        [Theory]
        [MemberData(nameof(VerifyFiles))]
        public void TheVerifyVectorsAreNotEmpty(string name) =>
            Assert.True(Load(name).GetProperty("cases").GetArrayLength() >= 5);

        [Theory]
        [MemberData(nameof(Responses))]
        public void ResponseVectors(string id)
        {
            // verify_response's own policy (format 3): ResponseMinimum by default, the keyid decided.
            var c = Case("responses.json", id);
            if (c.TryGetProperty("error", out var error))
            {
                var caught = Assert.Throws<FikiException>(() => Verify(c, response: true));
                Assert.Equal(error.GetString(), caught.Kind.ToString());
                WellFormed(caught);
                return;
            }
            var verdict = Verify(c, response: true);
            Assert.Equal(c.GetProperty("keyid").GetString(), verdict.KeyId);
            Assert.Equal(c.GetProperty("covered").EnumerateArray().Select(x => x.GetString()).ToArray(), verdict.Covered.ToArray());
        }

        [Theory]
        [MemberData(nameof(Signs))]
        public void SignVectors(string id)
        {
            // What the signer emits, byte for byte (review V-C4).
            var c = Case("signs.json", id);
            KnownFields(c, SignFields);
            var key = Key.FromSeed(Bytes.FromHex(c.GetProperty("seed_hex").GetString()!));
            IReadOnlyDictionary<string, string> Sign() => c.GetProperty("kind").GetString() == "request"
                ? HttpSignatures.SignRequest(key, c.GetProperty("method").GetString()!, c.GetProperty("url").GetString()!,
                    Headers(c.GetProperty("headers")), Body(c), List(c, "covered"), Integer(c, "created"), c.GetProperty("label").GetString()!,
                    Integer(c, "expires"), Text(c, "nonce"), Text(c, "tag"), Text(c, "keyid"), List(c, "minimum"))
                : HttpSignatures.SignResponse(key, c.GetProperty("status").GetInt32(), RequestOf(c.GetProperty("request")),
                    Headers(c.GetProperty("headers")), Body(c), List(c, "covered"), Integer(c, "created"), c.GetProperty("label").GetString()!,
                    Integer(c, "expires"), Text(c, "nonce"), Text(c, "tag"), Text(c, "keyid"), List(c, "minimum"));

            if (c.TryGetProperty("error", out var error))
            {
                if (error.GetString() == "caller")
                {
                    var mistake = Assert.ThrowsAny<ArgumentException>(Sign);
                    Assert.IsNotType<FikiException>(mistake);
                    return;
                }
                var caught = Assert.Throws<FikiException>(Sign);
                Assert.Equal(error.GetString(), caught.Kind.ToString());
                WellFormed(caught);
                return;
            }
            var expected = c.GetProperty("expected_headers").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);
            Assert.Equal(expected.OrderBy(p => p.Key, StringComparer.Ordinal), Sign().OrderBy(p => p.Key, StringComparer.Ordinal));
        }

        [Theory]
        [MemberData(nameof(Misuses))]
        public void MisuseVectors(string id)
        {
            // A mistake in the call is an ArgumentException, never a FikiException (this.i @5zrf8gjk).
            var c = Case("misuse.json", id);
            Assert.Equal("caller", c.GetProperty("error").GetString());
            var caught = Assert.ThrowsAny<ArgumentException>(() => Verify(c));
            Assert.IsNotType<FikiException>(caught);
        }

        [Theory]
        [MemberData(nameof(Refusals))]
        public void RefusalVectors(string id)
        {
            // Every entry names the error fiki raises, so a port maps its own type onto the same
            // condition rather than inventing a taxonomy of its own.
            var c = Case("refusals.json", id);
            var caught = Assert.Throws<FikiException>(() => Verify(c));
            Assert.Equal(c.GetProperty("error").GetString(), caught.Kind.ToString());
            WellFormed(caught);
        }

        [Theory]
        [MemberData(nameof(Accepts))]
        public void AcceptVectors(string id)
        {
            // Between the others, nothing said a well-formed request must VERIFY, with the right AID
            // and the right covered set.
            var c = Case("accepts.json", id);
            var verdict = Verify(c);
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
