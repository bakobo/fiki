using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The key-spelling vectors, vectors/keys/keys.json (this.i @0mvgkwnl), mirroring
    /// py/tests/test_key_formats.py.
    /// </summary>
    /// <remarks>
    /// <see cref="Key.AidFrom"/> turns any of the public-key spellings into the canonical AID, and
    /// <see cref="Key.FromOpenSsh"/> loads an unencrypted OpenSSH private key. Neither touches the
    /// wire: a fiki-signed request still carries the raw key in its keyid (@7xrx5evg), and a verifier
    /// still compares AIDs.
    /// </remarks>
    public class KeyVectorsTests
    {
        private static readonly JsonElement Vectors = Repo.Json("vectors", "keys", "keys.json");

        // Every section's case count at key_vectors_format 1, read from keys.json once and never at
        // test time, so a section emptied or cut short fails rather than passing on what it holds.
        private static readonly Dictionary<string, int> Pinned = new Dictionary<string, int>
        {
            { "public/accepts", 18 }, { "public/refusals", 72 }, { "private/accepts", 7 }, { "private/refusals", 43 },
        };

        private static JsonElement Section(string name)
        {
            var parts = name.Split('/');
            return Vectors.GetProperty(parts[0]).GetProperty(parts[1]);
        }

        private static JsonElement Case(string section, string id) =>
            Section(section).EnumerateArray().Single(c => c.GetProperty("id").GetString() == id);

        private static IEnumerable<object[]> Ids(string section) =>
            Section(section).EnumerateArray().Select(c => new object[] { c.GetProperty("id").GetString()! });

        public static IEnumerable<object[]> SectionNames() => Pinned.Keys.Select(k => new object[] { k });

        public static IEnumerable<object[]> PublicAccepts() => Ids("public/accepts");

        public static IEnumerable<object[]> PublicRefusals() => Ids("public/refusals");

        public static IEnumerable<object[]> PrivateAccepts() => Ids("private/accepts");

        public static IEnumerable<object[]> PrivateRefusals() => Ids("private/refusals");

        private static readonly Dictionary<string, Func<IEnumerable<object[]>>> Sources = new Dictionary<string, Func<IEnumerable<object[]>>>
        {
            { "public/accepts", PublicAccepts }, { "public/refusals", PublicRefusals },
            { "private/accepts", PrivateAccepts }, { "private/refusals", PrivateRefusals },
        };

        [Theory]
        [MemberData(nameof(SectionNames))]
        public void EachSectionHoldsExactlyItsPinnedCasesAndEveryOneRuns(string name)
        {
            Assert.Equal(Pinned[name], Section(name).GetArrayLength());
            var ids = Sources[name]().Select(row => (string)row[0]).ToList();
            Assert.Equal(Pinned[name], ids.Count);
            // Two cases under one id would run as one, so every id is distinct.
            Assert.Equal(Pinned[name], ids.Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public void TheFileDeclaresTheFormatThisPortSatisfies()
        {
            Assert.Equal(1, HttpSignatures.KeyVectorsFormat);
            Assert.Equal(HttpSignatures.KeyVectorsFormat, Vectors.GetProperty("key_vectors_format").GetInt32());
        }

        private static string Input(string section, string id) => Case(section, id).GetProperty("input").GetString()!;

        [Theory]
        [MemberData(nameof(PublicAccepts))]
        public void APublicSpellingConvertsToItsAid(string id)
        {
            var c = Case("public/accepts", id);
            Assert.Equal(c.GetProperty("aid").GetString(), Key.AidFrom(c.GetProperty("input").GetString()!));
        }

        /// <summary>Whether the error carries the text, or any run of it long enough to hold key material.</summary>
        private static bool Echoes(FikiException error, string text)
        {
            if (error.KeyId != "")
            {
                return true;
            }
            var whole = text.Length >= 12 && error.Message.Contains(text);
            return whole || Regex.Matches(text, "[A-Za-z0-9+/=_-]{12,}").Cast<Match>().Any(m => error.Message.Contains(m.Value));
        }

        private static FikiException Malformed(Action act)
        {
            var caught = Assert.Throws<FikiException>(act);
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
            Assert.Null(caught.InnerException);
            return caught;
        }

        [Theory]
        [MemberData(nameof(PublicRefusals))]
        public void AMalformedPublicSpellingIsRefusedWithoutEchoingIt(string id)
        {
            // Never echoed, because what a caller hands AidFrom by mistake can be a private key: the
            // .key file instead of the .pub, or a seed in base64url, 43 characters like a raw key.
            var c = Case("public/refusals", id);
            Assert.Equal("MalformedKey", c.GetProperty("error").GetString());
            var text = c.GetProperty("input").GetString()!;
            Assert.False(Echoes(Malformed(() => Key.AidFrom(text)), text));
        }

        [Theory]
        [MemberData(nameof(PrivateAccepts))]
        public void AnOpenSshKeyLoadsAndSignsAsItsSeed(string id)
        {
            var c = Case("private/accepts", id);
            var key = Key.FromOpenSsh(c.GetProperty("input").GetString()!);
            Assert.Equal(c.GetProperty("aid").GetString(), key.Aid);
            var signature = key.Sign(Bytes.Utf8(Vectors.GetProperty("signed_message").GetString()!));
            Assert.Equal(c.GetProperty("signature").GetString(), Bytes.B64Url(signature));
        }

        [Theory]
        [MemberData(nameof(PrivateRefusals))]
        public void AMalformedOpenSshKeyIsRefusedWithoutEchoingIt(string id)
        {
            var c = Case("private/refusals", id);
            Assert.Equal("MalformedKey", c.GetProperty("error").GetString());
            var text = c.GetProperty("input").GetString()!;
            var caught = Malformed(() => Key.FromOpenSsh(text));
            // A private key never reaches an error: not its text, not any run of its base64 body
            // long enough to carry key material, and not the keyid a consumer might log.
            Assert.Equal("", caught.KeyId);
            foreach (Match run in Regex.Matches(text, "[A-Za-z0-9+/=]{16,}"))
            {
                Assert.DoesNotContain(run.Value, caught.Message, StringComparison.Ordinal);
            }
        }

        public static IEnumerable<object[]> WeakPublics() =>
            Section("public/refusals").EnumerateArray()
                .Select(c => c.GetProperty("id").GetString()!)
                .Where(id => id.EndsWith("small-order", StringComparison.Ordinal) || id.EndsWith("not-on-curve", StringComparison.Ordinal))
                .Select(id => new object[] { id });

        [Theory]
        [MemberData(nameof(WeakPublics))]
        public void AWeakKeyIsRefusedForItsWeaknessWhateverItsSpelling(string id)
        {
            // Not merely refused: refused by the point check, so the spelling parsed and the key
            // reached it (@37wdchu5). A parser bug that refused these earlier would pass the vector.
            var caught = Malformed(() => Key.AidFrom(Input("public/refusals", id)));
            Assert.Matches("small order|canonical encoding of a point", caught.Message);
        }

        [Fact]
        public void APrivateKeyWithAWeakPublicKeyIsRefused()
        {
            var caught = Malformed(() => Key.FromOpenSsh(Input("private/refusals", "public-small-order")));
            Assert.Matches("does not derive|small order", caught.Message);
        }

        [Fact]
        public void ANullKeyIsACallerErrorNotARefusal()
        {
            // The guide's "Handling errors": a mistake in the call is reported in the platform's own
            // idiom, so that catching FikiException for a bad key cannot swallow a bug in the caller.
            Assert.Throws<ArgumentNullException>(() => Key.AidFrom(null!));
            Assert.Throws<ArgumentNullException>(() => Key.FromOpenSsh(null!));
        }

        [Theory]
        [InlineData("aid-transferable")]
        [InlineData("aid-digest")]
        public void ACanonicalTransferableOrDigestAidIsToldToResolveIt(string id) =>
            Assert.Contains("resolve it", Malformed(() => Key.AidFrom(Input("public/refusals", id))).Message, StringComparison.Ordinal);

        [Theory]
        [InlineData("aid-transferable-not-base64")]
        [InlineData("aid-transferable-misspelled")]
        public void AMalformedDPrefixIsNotCalledAnAid(string id) =>
            // Shape before meaning: text that merely starts with D is not told it is an AID.
            Assert.DoesNotContain("resolve it", Malformed(() => Key.AidFrom(Input("public/refusals", id))).Message, StringComparison.Ordinal);

        [Fact]
        public void ASeedMistakenForARawKeyIsNotEchoedWhenRefused()
        {
            // About half of all seeds, written as 43 characters of base64url, are not a valid point
            // and so are refused by the curve check rather than by the parser. That refusal must not
            // quote it. The seed is one RFC 8032 section 6's own decoding refuses, not one AidFrom picked.
            var seed = Enumerable.Range(0, 256).Select(n => Enumerable.Repeat((byte)n, 32).ToArray())
                .First(s => Ed25519Cofactorless.Decompress(s, 0) == null);
            var text = Bytes.B64Url(seed);
            var caught = Malformed(() => Key.AidFrom(text));
            Assert.Contains("canonical encoding of a point", caught.Message, StringComparison.Ordinal);
            Assert.False(Echoes(caught, text));
        }

        [Fact]
        public void TheEncryptedRefusalSaysToKeepADedicatedKey() =>
            Assert.Contains("dedicated", Malformed(() => Key.FromOpenSsh(Input("private/refusals", "encrypted"))).Message, StringComparison.Ordinal);

        [Fact]
        public void AnSshKeySignsARequestThatVerifiesAgainstItsRegisteredPublicLine()
        {
            var key = Key.FromOpenSsh(Input("private/accepts", "ssh-keygen"));
            var registered = Key.AidFrom(Input("public/accepts", "ssh-keygen-pub"));
            var headers = HttpSignatures.SignRequest(key, "GET", "https://example.com/x");
            var verdict = HttpSignatures.VerifyRequest("GET", "https://example.com/x", headers,
                VerifyOptions.MaxAge(60).DecliningAuthorityCheck().WithExpectedAid(registered));
            Assert.Equal(registered, verdict.Aid);
        }

        // --- native: shapes the vectors leave to each port, written with a minimal openssh-key-v1 writer ---

        private static readonly byte[] Seed = Bytes.Range(0, 32);

        private static byte[] Raw(Key key) => Key.VerifyingKey(key.Aid).ToBytes();

        private static byte[] Wire(params object[] fields)
        {
            var bytes = new List<byte>();
            foreach (var field in fields)
            {
                var data = field is string text ? Bytes.Utf8(text) : field is uint n
                    ? new[] { (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n }
                    : (byte[])field;
                if (field is uint)
                {
                    bytes.AddRange(data);
                    continue;
                }
                var length = (uint)data.Length;
                bytes.AddRange(new[] { (byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length });
                bytes.AddRange(data);
            }
            return bytes.ToArray();
        }

        private static byte[] Joined(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

        /// <summary>Padded with 1, 2, 3, ... to a multiple of eight, as OpenSSH pads a private section.</summary>
        private static byte[] Padded(byte[] section) =>
            section.Concat(Enumerable.Range(1, (8 - section.Length % 8) % 8).Select(i => (byte)i)).ToArray();

        private static string Armored(byte[] blob)
        {
            var body = Convert.ToBase64String(blob);
            var lines = Enumerable.Range(0, (body.Length + 69) / 70).Select(i => body.Substring(i * 70, Math.Min(70, body.Length - i * 70)));
            return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + string.Join("\n", lines) + "\n-----END OPENSSH PRIVATE KEY-----\n";
        }

        private static readonly byte[] Magic = Bytes.Utf8("openssh-key-v1\0");

        private static string Private(byte[] section)
        {
            var raw = Raw(Key.FromSeed(Seed));
            return Armored(Joined(Magic, Wire("none", "none", new byte[0], 1u, Wire("ssh-ed25519", raw), section)));
        }

        [Fact]
        public void TheWriterHereWritesAKeyFikiLoads()
        {
            // So that each refusal below is refused for the one field it changes.
            var raw = Raw(Key.FromSeed(Seed));
            var key = Key.FromOpenSsh(Private(Padded(Wire(7u, 7u, "ssh-ed25519", raw, Seed.Concat(raw).ToArray(), "c"))));
            Assert.Equal(Key.FromSeed(Seed).Aid, key.Aid);
        }

        public static IEnumerable<object[]> TruncatedPrivates()
        {
            var raw = Raw(Key.FromSeed(Seed));
            return new[]
            {
                new object[] { "shorter than the magic", Armored(new byte[] { 1, 2, 3 }) },
                new object[] { "no cipher", Armored(Magic) },
                new object[] { "no kdf", Armored(Joined(Magic, Wire("none"))) },
                new object[] { "no kdf options", Armored(Joined(Magic, Wire("none", "none"))) },
                new object[] { "no secret", Private(Padded(Wire(7u, 7u, "ssh-ed25519", raw))) },
                new object[] { "no comment", Private(Padded(Wire(7u, 7u, "ssh-ed25519", raw, Seed.Concat(raw).ToArray()))) },
            };
        }

        [Theory]
        [MemberData(nameof(TruncatedPrivates))]
        public void AnOpenSshKeyCutShortAtAnyFieldIsRefused(string why, string text)
        {
            Assert.NotEmpty(why);
            Assert.Equal("", Malformed(() => Key.FromOpenSsh(text)).KeyId);
        }

        [Fact]
        public void MoreThanTwoPaddingCharactersAreNotBase64InEitherFunction()
        {
            // "====" passes a check for the alphabet followed by padding and a multiple of four, and
            // a decoder that saw it would throw rather than refuse, so it is refused by shape first.
            var line = Input("public/accepts", "ssh");
            Malformed(() => Key.AidFrom(line.Substring(0, line.Length - 4) + "===="));
            var key = Input("private/accepts", "ssh-keygen").Split('\n');
            key[1] = key[1].Substring(0, key[1].Length - 4) + "====";
            Malformed(() => Key.FromOpenSsh(string.Join("\n", key)));
        }

        [Theory]
        [InlineData("did:key:z")]
        [InlineData("did:peer:0z")]
        public void AnEmptyBase58ValueIsRefused(string text) => Malformed(() => Key.AidFrom(text));

        // --- native: a lone UTF-16 surrogate, which no JSON vector carries portably ---

        private static IEnumerable<string> WithLoneSurrogates(string text)
        {
            foreach (var code in new[] { '\uD800', '\uDC00' })
            {
                for (var i = 0; i <= text.Length; i++)
                {
                    yield return text.Insert(i, code.ToString());
                    if (i < text.Length)
                    {
                        yield return text.Substring(0, i) + code + text.Substring(i + 1);
                    }
                }
            }
        }

        [Fact]
        public void ALoneSurrogateAnywhereInAPublicSpellingIsMalformedKeyNotACrash()
        {
            foreach (var row in PublicAccepts())
            {
                foreach (var text in WithLoneSurrogates(Input("public/accepts", (string)row[0])))
                {
                    Assert.False(Echoes(Malformed(() => Key.AidFrom(text)), text));
                }
            }
        }

        [Fact]
        public void ALoneSurrogateAnywhereInAnOpenSshKeyIsMalformedKeyNotACrash()
        {
            foreach (var row in PrivateAccepts())
            {
                foreach (var text in WithLoneSurrogates(Input("private/accepts", (string)row[0])))
                {
                    Assert.Equal("", Malformed(() => Key.FromOpenSsh(text)).KeyId);
                }
            }
        }
    }
}
