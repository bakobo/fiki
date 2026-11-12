using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The KERI profile's vector set, vectors/keri/ (this.i @8vwrexxc), mirroring
    /// py/tests/test_keri_vectors.py.
    /// </summary>
    /// <remarks>
    /// A separate contract from the shared vectors: its own format number, and refusals named by the
    /// profile's neutral section 9 codes rather than fiki's kind names. The only thing this driver
    /// adds is the class-to-code table, which py imports from vectors/keri/generate.py and which is
    /// checked here against the generator's own text so the two cannot drift; the well-formedness
    /// rule the keys table is checked against; and the resolver a KERI verifier would back with key
    /// event logs, with the policy-applying verifier, written from the files alone.
    /// </remarks>
    public class KeriVectorsTests
    {
        private static readonly string[] Files = { "rfc9421.json", "requests.json", "responses.json", "refusals.json", "legacy.json" };
        private static readonly string[] PolicyFiles = { "requests.json", "responses.json", "refusals.json" };

        // vectors/keri/generate.py's CODES: fiki's kinds to the profile's section 9 codes. MissingKey
        // has no code of its own: keyid is REQUIRED there, so its absence is a malformed input.
        internal static readonly Dictionary<string, string> Codes = new Dictionary<string, string>
        {
            { "MissingSignature", "missing-signature" },
            { "MissingSignatureInput", "missing-signature-input" },
            { "MalformedSignature", "malformed-signature" },
            { "MalformedSignatureInput", "malformed-signature-input" },
            { "MissingKey", "malformed-signature-input" },
            { "MalformedSignatureLabel", "malformed-signature-label" },
            { "MissingSignatureLabel", "missing-signature-label" },
            { "MalformedSignatureValue", "malformed-signature-value" },
            { "DuplicateComponent", "duplicate-component" },
            { "UnsupportedComponent", "unsupported-component" },
            { "InsufficientCoverage", "insufficient-coverage" },
            { "MalformedKey", "malformed-key" },
            { "UnknownKey", "unknown-key" },
            { "UnsupportedSigner", "unsupported-signer" },
            { "UnsupportedAlgorithm", "unsupported-algorithm" },
            { "MissingComponent", "missing-component" },
            { "SignatureMismatch", "signature-mismatch" },
            { "SignatureTooOld", "signature-stale" },
            { "SignatureExpired", "signature-expired" },
            { "MalformedDigest", "malformed-digest" },
            { "DigestMismatch", "digest-mismatch" },
            { "UncoveredBody", "uncovered-body" },
            { "Unauthenticated", "unauthenticated" },
        };

        private static JsonElement Load(string name) => Repo.Json("vectors", "keri", name);

        private static JsonElement Case(string name, string id) =>
            Load(name).GetProperty("cases").EnumerateArray().Single(c => c.GetProperty("id").GetString() == id);

        private static IEnumerable<object[]> Ids(string name) =>
            Load(name).GetProperty("cases").EnumerateArray().Select(c => new object[] { c.GetProperty("id").GetString()! });

        public static IEnumerable<object[]> FileNames() => Files.Select(f => new object[] { f });

        public static IEnumerable<object[]> PolicyFileNames() => PolicyFiles.Select(f => new object[] { f });

        public static IEnumerable<object[]> RequestCases() => Ids("requests.json");

        public static IEnumerable<object[]> ResponseCases() => Ids("responses.json");

        public static IEnumerable<object[]> RefusalCases() => Ids("refusals.json");

        public static IEnumerable<object[]> LegacyCases() => Ids("legacy.json");

        // Cases per file at keri_vectors_format 8, read from the files once and never at test time (tick
        // 7xbw, review T8). rfc9421.json's one case is the RFC's own, run by name below.
        private static readonly Dictionary<string, int> Pinned = new Dictionary<string, int>
        {
            { "rfc9421.json", 1 }, { "requests.json", 25 }, { "responses.json", 4 }, { "refusals.json", 78 }, { "legacy.json", 12 },
        };

        private static readonly Dictionary<string, Func<IEnumerable<object[]>>> Sources = new Dictionary<string, Func<IEnumerable<object[]>>>
        {
            { "rfc9421.json", () => Ids("rfc9421.json") }, { "requests.json", RequestCases }, { "responses.json", ResponseCases },
            { "refusals.json", RefusalCases }, { "legacy.json", LegacyCases },
        };

        [Theory]
        [MemberData(nameof(FileNames))]
        public void EachFileHoldsExactlyItsPinnedCasesAndEveryOneRuns(string name)
        {
            Assert.Equal(Files.OrderBy(f => f), Pinned.Keys.OrderBy(f => f));
            Assert.Equal(Pinned[name], Load(name).GetProperty("cases").GetArrayLength());
            var ids = Sources[name]().Select(row => (string)row[0]).ToList();
            Assert.Equal(Pinned[name], ids.Count);
            // Two cases under one id would run as one, so every id is distinct.
            Assert.Equal(Pinned[name], ids.Distinct(StringComparer.Ordinal).Count());
        }

        private static string[] Strings(JsonElement array) => array.EnumerateArray().Select(x => x.GetString()!).ToArray();

        // --- generate.py's rules, ported ---

        // generate.py's PREFIX_CODES, keripy's PreDex with the raw size each code encodes, in the
        // generator's order, which its prefix test walks; checked against the generator's text below.
        internal static readonly List<KeyValuePair<string, int>> PrefixCodes = new List<KeyValuePair<string, int>>
        {
            new KeyValuePair<string, int>("B", 32), new KeyValuePair<string, int>("D", 32), new KeyValuePair<string, int>("E", 32),
            new KeyValuePair<string, int>("F", 32), new KeyValuePair<string, int>("G", 32), new KeyValuePair<string, int>("H", 32),
            new KeyValuePair<string, int>("I", 32),
            new KeyValuePair<string, int>("0D", 64), new KeyValuePair<string, int>("0E", 64), new KeyValuePair<string, int>("0F", 64),
            new KeyValuePair<string, int>("0G", 64),
            new KeyValuePair<string, int>("1AAA", 33), new KeyValuePair<string, int>("1AAB", 33), new KeyValuePair<string, int>("1AAI", 33),
            new KeyValuePair<string, int>("1AAJ", 33),
            new KeyValuePair<string, int>("1AAC", 57), new KeyValuePair<string, int>("1AAD", 57), new KeyValuePair<string, int>("1AAE", 114),
        };

        /// <summary>
        /// KEYS_RULE's test (keri_vectors_format 8): the canonical qb64 spelling of one of keripy's
        /// PreDex codes, the bytes padded in front with zero bytes to a multiple of three,
        /// base64url-encoded, and the code written over the characters the padding became, so
        /// re-encoding gives the keyid back. Written against System.Convert rather than fiki's own
        /// decoder, as the generator's is independent of fiki's.
        /// </summary>
        internal static bool WellFormedAid(string keyId)
        {
            foreach (var entry in PrefixCodes)
            {
                if (!keyId.StartsWith(entry.Key, StringComparison.Ordinal))
                {
                    continue;
                }
                var pad = (3 - entry.Value % 3) % 3;
                var standard = new string('A', pad) + keyId.Substring(entry.Key.Length).Replace('-', '+').Replace('_', '/');
                byte[] decoded;
                try
                {
                    decoded = Convert.FromBase64String(standard);
                }
                catch (FormatException)
                {
                    return false;
                }
                return decoded.Length == pad + entry.Value && Qb64(entry.Key, decoded.Skip(pad).ToArray()) == keyId;
            }
            return false;
        }

        /// <summary>generate.py's cesr: any PreDex code over its raw bytes.</summary>
        private static string Qb64(string code, byte[] raw)
        {
            var pad = (3 - raw.Length % 3) % 3;
            return code + Bytes.B64Url(new byte[pad].Concat(raw).ToArray()).Substring(pad);
        }

        /// <summary>
        /// What a KERI verifier's key lookup does, for a keys table: authoritative, never a decode, and
        /// knowing key state alone (keri_vectors_format 6, this.i @7w7nv94j). It looks every keyid up
        /// in the table, answers null for a keyid it has no key state for, and says UnsupportedSigner
        /// for a key state with no single effective signer. It knows nothing of B keyids: since
        /// keri_vectors_format 8 the library takes their key from the prefix and never asks
        /// (@37rktct3), and the case whose B keyid the table does not list would fail if it did. It
        /// carries no well-formedness check: a keyid that is not an AID, or a weak B key, is fiki's to
        /// refuse, so the refusal vectors for them test the library rather than this file.
        /// </summary>
        internal static Func<string, byte[]?> Resolver(JsonElement keys)
        {
            var table = keys.EnumerateArray().Where(e => e.GetProperty("kind").GetString() == "transferable")
                .ToDictionary(e => e.GetProperty("keyid").GetString()!, e => e);
            return keyId =>
            {
                if (!table.TryGetValue(keyId, out var entry))
                {
                    return null;
                }
                var effective = entry.GetProperty("effective_key");
                if (effective.ValueKind == JsonValueKind.Null)
                {
                    throw new FikiException(FikiErrorKind.UnsupportedSigner,
                        $"The key state of \"{keyId}\" has no single key that satisfies its threshold.", keyId: keyId);
                }
                return Bytes.FromB64Url(effective.GetString()!);
            };
        }

        /// <summary>The key a signature is checked with when the base is rebuilt: a B prefix's own, else the table's.</summary>
        private static byte[] KeyFor(string keyId, JsonElement keys) =>
            keyId[0] == 'B' ? Bytes.FromB64Url("A" + keyId.Substring(1)).Skip(1).ToArray() : Resolver(keys)(keyId)!;

        /// <summary>
        /// A case's now. fiki's clock is whole seconds, and the profile rounds a fractional one down
        /// (section 6), so a fractional now is rounded down here.
        /// </summary>
        private static long Now(JsonElement c) => (long)Math.Floor(c.GetProperty("now").GetDouble());

        private static Request AsRequest(JsonElement message) => new Request(
            message.GetProperty("method").GetString()!, message.GetProperty("url").GetString()!,
            VectorsTests.Headers(message.GetProperty("headers")), VectorsTests.Body(message));

        /// <summary>Verify as a KERI verifier would, under the file's policy extended by the case's.</summary>
        private static Verdict Verify(JsonElement request, JsonElement? response, long now, JsonElement filePolicy, JsonElement? casePolicy, JsonElement keys)
        {
            JsonElement Policy(string name, out bool found)
            {
                if (casePolicy.HasValue && casePolicy.Value.TryGetProperty(name, out var value))
                {
                    found = true;
                    return value;
                }
                found = filePolicy.TryGetProperty(name, out value);
                return value;
            }

            var options = Verifying.MaxAge(Policy("max_age", out _).GetInt64())
                .WithSkew(Policy("skew", out _).GetInt64())
                .WithNow(now)
                .WithResolver(Resolver(keys));
            var expectedKeyId = Policy("expected_keyid", out var hasExpected);
            // A policy with no expected_keyid states the decline, which a response requires
            // (keri_vectors_format 5, this.i @524c8qgv).
            options = hasExpected ? options.WithExpectedKeyId(expectedKeyId.GetString()!) : options.DecliningKeyidCheck();
            if (response.HasValue)
            {
                var r = response.Value;
                return HttpSignatures.VerifyResponse(r.GetProperty("status").GetInt32(), VectorsTests.Headers(r.GetProperty("headers")),
                    options.WithBody(VectorsTests.Body(r)).WithRequest(AsRequest(request)).WithMinimum(Strings(Policy("response_minimum", out _))));
            }
            var authorities = Policy("authorities", out var hasAuthorities);
            if (hasAuthorities)
            {
                options = options.WithAuthorities(Strings(authorities));
            }
            return HttpSignatures.VerifyRequest(request.GetProperty("method").GetString()!, request.GetProperty("url").GetString()!,
                VectorsTests.Headers(request.GetProperty("headers")),
                options.WithBody(VectorsTests.Body(request)).WithMinimum(Strings(Policy("request_minimum", out _))));
        }

        private static Verdict Run(JsonElement c, JsonElement data) => Verify(
            c.GetProperty("request"), c.TryGetProperty("response", out var response) ? response : (JsonElement?)null,
            Now(c), data.GetProperty("policy"),
            c.TryGetProperty("policy", out var policy) ? policy : (JsonElement?)null, data.GetProperty("keys"));

        /// <summary>
        /// The base a signer builds from the parameters its Signature-Input carries, and its signature,
        /// rebuilt through the signing-side base functions and checked against the message's signature.
        /// </summary>
        private static (string Base, string Signature) ExpectedBase(JsonElement request, JsonElement? response, JsonElement keys)
        {
            var message = response ?? request;
            var headers = message.GetProperty("headers");
            var parsed = Sfv.ParseDictionary(headers.GetProperty("Signature-Input").GetString()!);
            var inner = (SfInnerList)parsed.Single().Value;
            string? Text(string name) => inner.Params.TryGet(name, out var v) ? v!.Text : null;
            long? Integer(string name) => inner.Params.TryGet(name, out var v) ? v!.Integer : (long?)null;
            var covered = inner.Items.Select(i => i.Serialize()).ToArray();
            var created = Integer("created")!.Value;
            var keyId = Text("keyid")!;
            var bas = response.HasValue
                ? HttpSignatures.ResponseSignatureBase(response.Value.GetProperty("status").GetInt32(), VectorsTests.Headers(headers), covered,
                    created, keyId, AsRequest(request), Text("alg"), Integer("expires"), Text("nonce"), Text("tag"))
                : HttpSignatures.SignatureBase(request.GetProperty("method").GetString()!, request.GetProperty("url").GetString()!,
                    VectorsTests.Headers(headers), covered, created, keyId, Text("alg"), Integer("expires"), Text("nonce"), Text("tag"));
            var header = headers.GetProperty("Signature").GetString()!;
            var signature = header.Substring(header.IndexOf('=') + 1).Trim(':');
            Assert.True(new PublicKey(KeyFor(keyId, keys)).Verify(Convert.FromBase64String(signature), bas));
            return (Bytes.Text(bas), signature);
        }

        private static string[] Serialized(IEnumerable<string> covered) => covered.Select(spec => Components.Component(spec).Serialize()).ToArray();

        // --- the files themselves ---

        [Theory]
        [MemberData(nameof(FileNames))]
        public void ThisPortSatisfiesTheKeriVectorsFormatItIsRunning(string name)
        {
            // The same guard @4fhrre0m gives the shared set, against its own number.
            var data = Load(name);
            Assert.Equal(HttpSignatures.KeriVectorsFormat, data.GetProperty("keri_vectors_format").GetInt32());
            Assert.False(data.TryGetProperty("vectors_format", out _));
            Assert.NotEmpty(data.GetProperty("cases").EnumerateArray());
        }

        [Theory]
        [MemberData(nameof(FileNames))]
        public void EachFileNamesThePublishedProfileItPins(string name)
        {
            // The contract is a document anyone can read, beside these files (@997vxdu7).
            var profile = Load(name).GetProperty("profile");
            Assert.Equal("1.2", profile.GetProperty("version").GetString());
            Assert.Equal("https://github.com/bakobo/fiki/blob/keri-profile-v1.2/docs/keri-profile.md", profile.GetProperty("where").GetString());
            var doc = File.ReadAllText(Repo.PathTo("docs", "keri-profile.md")).Replace("\r\n", "\n");
            Assert.StartsWith(
                $"# {profile.GetProperty("title").GetString()}\n\nVersion 1.2, {profile.GetProperty("date").GetString()}.",
                doc, StringComparison.Ordinal);
        }

        [Theory]
        [MemberData(nameof(PolicyFileNames))]
        public void EachFileStatesThePolicyItAssumes(string name)
        {
            var policy = Load(name).GetProperty("policy");
            Assert.Equal(300, policy.GetProperty("max_age").GetInt32());
            Assert.Equal(60, policy.GetProperty("skew").GetInt32());
            Assert.Equal(new[] { "\"@method\"", "\"@path\"", "\"@query\"" }, Strings(policy.GetProperty("request_minimum")));
            Assert.Equal(new[] { "\"@status\"", "\"@method\";req", "\"@path\";req", "\"@query\";req" }, Strings(policy.GetProperty("response_minimum")));
            Assert.Equal(Serialized(HttpSignatures.RequestMinimum), Strings(policy.GetProperty("request_minimum")));
            Assert.Equal(Serialized(HttpSignatures.ResponseMinimum), Strings(policy.GetProperty("response_minimum")));
        }

        [Theory]
        [MemberData(nameof(PolicyFileNames))]
        public void TheKeysTableAgreesWithItsSeedsAndKeyStates(string name)
        {
            // A table entry that disagrees with its own seed would make every case using it a lie.
            var data = Load(name);
            Assert.False(string.IsNullOrEmpty(data.GetProperty("keys_rule").GetString()));
            foreach (var entry in data.GetProperty("keys").EnumerateArray())
            {
                var keyId = entry.GetProperty("keyid").GetString()!;
                Assert.True(WellFormedAid(keyId));
                var signer = Key.FromSeed(Bytes.FromHex(entry.GetProperty("seed_hex").GetString()!));
                var signerRaw = Key.VerifyingKey(signer.Aid).ToBytes();
                if (entry.GetProperty("kind").GetString() == "non-transferable")
                {
                    Assert.Equal(signer.Aid, keyId);
                    continue;
                }
                var stateKeys = Strings(entry.GetProperty("key_state").GetProperty("keys"));
                Assert.All(stateKeys, k => Assert.True(k[0] == 'D' && k.Length == 44));
                var state = stateKeys.Select(k => Bytes.FromB64Url("A" + k.Substring(1)).Skip(1).ToArray()).ToList();
                var effective = entry.GetProperty("effective_key");
                if (entry.TryGetProperty("weak_key", out var weak) && weak.GetBoolean())
                {
                    // A key no seed yields, there to be refused as it is resolved (profile R1).
                    Assert.Equal(state.Single(), Bytes.FromB64Url(effective.GetString()!));
                    Assert.Equal(FikiErrorKind.MalformedKey, Assert.Throws<FikiException>(() => Key.VerifyingKey("B" + effective.GetString())).Kind);
                    continue;
                }
                if (effective.ValueKind == JsonValueKind.Null)
                {
                    Assert.Equal(state[0], signerRaw);
                }
                else
                {
                    Assert.Equal(Bytes.FromB64Url(effective.GetString()!), signerRaw);
                    Assert.Contains(state, s => s.SequenceEqual(signerRaw));
                }
            }
        }

        [Fact]
        public void TheWellFormednessRuleRefusesNearMisses()
        {
            Assert.False(WellFormedAid("E" + new string('!', 43)));
            Assert.False(WellFormedAid("A" + new string('A', 43)));
            Assert.False(WellFormedAid("not-an-aid"));
        }

        [Fact]
        public void TheWellFormednessRuleRefusesAPaddingBitAlias()
        {
            // bakobo/fiki#4: a B keyid spelled with a non-zero pad bit would alias the same key.
            foreach (var entry in Load("requests.json").GetProperty("keys").EnumerateArray())
            {
                var keyId = entry.GetProperty("keyid").GetString()!;
                Assert.True(WellFormedAid(keyId));
                Assert.False(WellFormedAid(KeysTests.PaddingBitAlias(keyId)));
            }
        }

        [Fact]
        public void TheWellFormednessRuleAcceptsEveryPrefixCodeAndRefusesItsNearMisses()
        {
            foreach (var entry in PrefixCodes)
            {
                var keyId = Qb64(entry.Key, Enumerable.Range(1, entry.Value).Select(i => (byte)i).ToArray());
                Assert.True(WellFormedAid(keyId), entry.Key);
                Assert.False(WellFormedAid(keyId.Substring(0, keyId.Length - 1)), entry.Key);
                Assert.False(WellFormedAid(keyId + "AAAA"), entry.Key);
            }
            Assert.False(WellFormedAid("0D" + "g" + new string('A', 85)));
        }

        [Fact]
        public void ThePrefixCodeTableIsTheGeneratorsOwn()
        {
            var source = File.ReadAllText(Repo.PathTo("vectors", "keri", "generate.py"));
            var block = source.Substring(source.IndexOf("PREFIX_CODES = {", StringComparison.Ordinal));
            block = block.Substring(0, block.IndexOf('}'));
            var table = Regex.Matches(block, "\"(\\w+)\": (\\d+)").Cast<Match>()
                .Select(m => new KeyValuePair<string, int>(m.Groups[1].Value, int.Parse(m.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture)))
                .ToList();
            Assert.Equal(PrefixCodes, table);
        }

        [Fact]
        public void TheCodeTableIsTheGeneratorsOwn()
        {
            // py's driver imports CODES from generate.py; this port cannot, so it reads the table
            // out of the generator's text and fails if the two have drifted.
            var source = File.ReadAllText(Repo.PathTo("vectors", "keri", "generate.py"));
            var block = source.Substring(source.IndexOf("CODES = {", StringComparison.Ordinal));
            block = block.Substring(0, block.IndexOf('}'));
            var table = Regex.Matches(block, "\"(\\w+)\": \"([a-z-]+)\"").Cast<Match>()
                .ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Value);
            Assert.Equal(Codes.OrderBy(p => p.Key), table.OrderBy(p => p.Key));
        }

        [Fact]
        public void EveryRefusalNamesAProfileCodeAndEveryProfileCodeIsExercised()
        {
            var data = Load("refusals.json");
            var named = new HashSet<string>(data.GetProperty("cases").EnumerateArray().Select(c => c.GetProperty("error").GetString()!));
            Assert.True(named.SetEquals(Strings(data.GetProperty("codes"))));
            Assert.True(named.IsSupersetOf(Codes.Values));
        }

        [Fact]
        public void EveryFikiErrorKindHasAProfileCode()
        {
            // The same totality heti's boundary test enforces (@8zw78n0v), against the profile's codes.
            Assert.True(new HashSet<string>(Enum.GetNames(typeof(FikiErrorKind))).SetEquals(Codes.Keys));
        }

        [Fact]
        public void TheRefusalCodesAreNeutralRatherThanFikiKindNames()
        {
            foreach (var c in Load("refusals.json").GetProperty("cases").EnumerateArray())
            {
                var error = c.GetProperty("error").GetString()!;
                Assert.Equal(error.ToLowerInvariant(), error);
                Assert.False(Codes.ContainsKey(error));
            }
        }

        // --- RFC 9421 B.2.6, which anchors the set to something no Bakobo party wrote ---

        [Fact]
        public void Rfc9421B26IsTheRfcsOwnBaseAndSignature()
        {
            var c = Load("rfc9421.json").GetProperty("cases").EnumerateArray().Single();
            Assert.Equal(RfcConformanceTests.RfcBase, c.GetProperty("expected").GetProperty("base").GetString());
            Assert.Equal(RfcConformanceTests.RfcSignature, c.GetProperty("expected").GetProperty("signature").GetString());
            var request = c.GetProperty("request");
            var bas = HttpSignatures.SignatureBase(request.GetProperty("method").GetString()!, request.GetProperty("url").GetString()!,
                VectorsTests.Headers(request.GetProperty("headers")), Strings(c.GetProperty("covered")),
                c.GetProperty("created").GetInt64(), c.GetProperty("keyid").GetString()!);
            Assert.Equal(RfcConformanceTests.RfcBase, Bytes.Text(bas));
            var signature = Key.FromSeed(Bytes.FromHex(c.GetProperty("seed_hex").GetString()!)).Sign(bas);
            Assert.Equal(RfcConformanceTests.RfcSignature, Convert.ToBase64String(signature));
        }

        // --- the accept cases ---

        [Theory]
        [MemberData(nameof(RequestCases))]
        public void RequestAcceptVectors(string id)
        {
            var data = Load("requests.json");
            var c = Case("requests.json", id);
            if (c.TryGetProperty("verified_by_fiki", out var verified) && !verified.GetBoolean())
            {
                // Carried as data: fiki's own vectors refuse missing padding (@2g4xxev9, @7ve9r2c6). The
                // base and signature are still the ones the message carries.
                Assert.False(string.IsNullOrEmpty(c.GetProperty("why").GetString()));
                Assert.Contains(id, Strings(data.GetProperty("verify_only")));
                var stated = c.GetProperty("expected");
                var unpadded = stated.GetProperty("signature").GetString()!;
                Assert.True(new PublicKey(KeyFor(stated.GetProperty("keyid").GetString()!, data.GetProperty("keys"))).Verify(
                    Convert.FromBase64String(unpadded.PadRight(unpadded.Length + (4 - unpadded.Length % 4) % 4, '=')),
                    Bytes.Utf8(stated.GetProperty("base").GetString()!)));
                return;
            }
            var verdict = Run(c, data);
            var expected = c.GetProperty("expected");
            Assert.Equal(expected.GetProperty("keyid").GetString(), verdict.KeyId);
            Assert.Equal(Strings(expected.GetProperty("covered")), Serialized(verdict.Covered));
            var (bas, signature) = ExpectedBase(c.GetProperty("request"), null, data.GetProperty("keys"));
            Assert.Equal(expected.GetProperty("base").GetString(), bas);
            Assert.Equal(expected.GetProperty("signature").GetString(), signature);
        }

        [Theory]
        [MemberData(nameof(ResponseCases))]
        public void ResponseAcceptVectors(string id)
        {
            var data = Load("responses.json");
            var c = Case("responses.json", id);
            Verify(c.GetProperty("request"), null, Now(c), data.GetProperty("policy"), null, data.GetProperty("keys"));
            var verdict = Run(c, data);
            var expected = c.GetProperty("expected");
            Assert.Equal(expected.GetProperty("keyid").GetString(), verdict.KeyId);
            Assert.Equal(Strings(expected.GetProperty("covered")), Serialized(verdict.Covered));
            var (bas, signature) = ExpectedBase(c.GetProperty("request"), c.GetProperty("response"), data.GetProperty("keys"));
            Assert.Equal(expected.GetProperty("base").GetString(), bas);
            Assert.Equal(expected.GetProperty("signature").GetString(), signature);
        }

        [Fact]
        public void TheSha512CasesAreMarkedVerifyOnly()
        {
            var data = Load("requests.json");
            var ids = new HashSet<string>(data.GetProperty("cases").EnumerateArray().Select(c => c.GetProperty("id").GetString()!));
            var verifyOnly = Strings(data.GetProperty("verify_only"));
            Assert.True(ids.IsSupersetOf(verifyOnly));
            foreach (var c in data.GetProperty("cases").EnumerateArray())
            {
                var digest = c.GetProperty("request").GetProperty("headers").TryGetProperty("Content-Digest", out var d) ? d.GetString()! : "";
                if ((digest.Length > 0 && !digest.StartsWith("sha-256=", StringComparison.Ordinal)) || digest.Contains(","))
                {
                    Assert.Contains(c.GetProperty("id").GetString(), verifyOnly);
                }
            }
        }

        // --- the refusals ---

        [Theory]
        [MemberData(nameof(RefusalCases))]
        public void RefusalVectors(string id)
        {
            // Each case has one defect and so one correct code under the profile's section 9 order.
            var data = Load("refusals.json");
            var c = Case("refusals.json", id);
            if (c.TryGetProperty("verified_by_fiki", out var verified) && !verified.GetBoolean())
            {
                // Carried as data (@4tkkp50h): fiki has no legacy mode to detect it with.
                Assert.Equal("mode-mismatch", c.GetProperty("error").GetString());
                Assert.False(string.IsNullOrEmpty(c.GetProperty("why").GetString()));
                return;
            }
            var caught = Assert.Throws<FikiException>(() =>
            {
                if (c.GetProperty("kind").GetString() == "sign-request")
                {
                    var request = c.GetProperty("request");
                    HttpSignatures.SignRequest(Key.FromSeed(Bytes.FromHex(c.GetProperty("seed_hex").GetString()!)),
                        request.GetProperty("method").GetString()!, request.GetProperty("url").GetString()!,
                        VectorsTests.Headers(request.GetProperty("headers")), VectorsTests.Body(request),
                        Strings(c.GetProperty("covered")), keyId: c.GetProperty("keyid").GetString()!,
                        minimum: Strings(data.GetProperty("policy").GetProperty("request_minimum")));
                }
                else
                {
                    Run(c, data);
                }
            });
            Assert.Equal(c.GetProperty("error").GetString(), Codes[caught.Kind.ToString()]);
        }

        // --- legacy material, which fiki carries and never verifies ---

        [Fact]
        public void LegacyVectorsCarryWhatALegacyVerifierNeedsAndTheirProvenance()
        {
            foreach (var c in Load("legacy.json").GetProperty("cases").EnumerateArray())
            {
                var source = c.GetProperty("source");
                if (source.GetProperty("repo").GetString() == "bakobo/fiki")
                {
                    // Generated, not pinned (keri_vectors_format 7): the seed reproduces the signature.
                    // Since format 8 each carries sufficient_keys, every key that alone satisfies the
                    // threshold, in place of format 7's effective_key.
                    Assert.Equal("vectors/keri/generate.py", source.GetProperty("file").GetString());
                    Assert.False(string.IsNullOrEmpty(source.GetProperty("generated").GetString()));
                    Assert.True(c.TryGetProperty("seed_hex", out _) && c.TryGetProperty("key_state", out _) && c.TryGetProperty("sufficient_keys", out _));
                    Assert.False(c.TryGetProperty("effective_key", out _));
                }
                else
                {
                    Assert.Contains(source.GetProperty("repo").GetString(), new[] { "WebOfTrust/keria", "WebOfTrust/signify-ts" });
                    Assert.Equal(40, source.GetProperty("commit").GetString()!.Length);
                    Assert.False(string.IsNullOrEmpty(source.GetProperty("file").GetString()));
                    Assert.False(string.IsNullOrEmpty(source.GetProperty("lines").GetString()));
                    Assert.False(c.TryGetProperty("key_state", out _) || c.TryGetProperty("error", out _));
                }
                foreach (var field in new[] { "kind", "method", "path", "headers", "key", "keyid", "created" })
                {
                    Assert.True(c.TryGetProperty(field, out _), field);
                }
                var headers = c.GetProperty("headers");
                Assert.StartsWith("signify=", headers.GetProperty("Signature-Input").GetString(), StringComparison.Ordinal);
                Assert.StartsWith("indexed=\"?0\";signify=\"0B", headers.GetProperty("Signature").GetString(), StringComparison.Ordinal);
            }
        }

        [Theory]
        [MemberData(nameof(LegacyCases))]
        public void EachLegacySignatureVerifiesOverItsStatedBase(string id)
        {
            // Transcription check only: pure Ed25519 over the base the file states, no legacy logic.
            var c = Case("legacy.json", id);
            var header = c.GetProperty("headers").GetProperty("Signature").GetString()!;
            var signature = header.Substring(header.IndexOf("signify=\"", StringComparison.Ordinal) + 9).TrimEnd('"');
            var rawSignature = Bytes.FromB64Url("AA" + signature.Substring(2)).Skip(2).ToArray();
            var rawKey = Bytes.FromB64Url("A" + c.GetProperty("key").GetString()!.Substring(1)).Skip(1).ToArray();
            Assert.True(new PublicKey(rawKey).Verify(rawSignature, Bytes.Utf8(c.GetProperty("base").GetString()!)));
        }

        [Theory]
        [MemberData(nameof(LegacyCases))]
        public void EachLegacyOutcomeAgreesWithItsKeyState(string id)
        {
            // Profile section 8 at version 1.2: any key that alone satisfies the threshold may sign.
            // fiki has no legacy verifier, so this checks the data: the key state reduces to the
            // sufficient_keys the case states, and the error follows from them and from who signed.
            var c = Case("legacy.json", id);
            if (!c.TryGetProperty("key_state", out var state))
            {
                return; // pinned from KERIA or signify-ts: accepted under its stated key
            }
            var error = c.TryGetProperty("error", out var e) ? e.GetString() : null;
            if (state.ValueKind == JsonValueKind.Null)
            {
                // Legacy mode never takes a key from a prefix, so no key state is no key.
                Assert.Equal(JsonValueKind.Null, c.GetProperty("sufficient_keys").ValueKind);
                Assert.Equal("unknown-key", error);
                return;
            }
            // Written out here rather than ported from the generator, which made the case with its own.
            var keys = state.GetProperty("keys").EnumerateArray().Select(k => k.GetString()!).ToList();
            var threshold = state.GetProperty("threshold");
            var alone = new List<string>();
            if (threshold.ValueKind == JsonValueKind.String)
            {
                if (Convert.ToInt32(threshold.GetString(), 16) == 1)
                {
                    alone.AddRange(keys);
                }
            }
            else
            {
                var weights = threshold.EnumerateArray().Select(w => w.GetString()!).ToList();
                Assert.Equal(keys.Count, weights.Count);
                for (var i = 0; i < keys.Count; i++)
                {
                    var parts = weights[i].Split('/');
                    var n = long.Parse(parts[0], System.Globalization.CultureInfo.InvariantCulture);
                    var d = parts.Length == 2 ? long.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture) : 1;
                    if (n >= d)
                    {
                        alone.Add(keys[i]);
                    }
                }
            }
            var raws = alone.Select(k => Bytes.FromB64Url("A" + k.Substring(1)).Skip(1).ToArray()).ToList();
            var stated = c.GetProperty("sufficient_keys").EnumerateArray().Select(k => Bytes.FromB64Url(k.GetString()!)).ToList();
            Assert.Equal(raws, stated);
            var header = c.GetProperty("headers").GetProperty("Signature").GetString()!;
            var signature = header.Substring(header.IndexOf("signify=\"", StringComparison.Ordinal) + 9).TrimEnd('"');
            var rawSignature = Bytes.FromB64Url("AA" + signature.Substring(2)).Skip(2).ToArray();
            var signer = c.GetProperty("key").GetString();
            if (alone.Count == 0)
            {
                Assert.Equal("unsupported-signer", error);
            }
            else if (error == "signature-mismatch")
            {
                Assert.DoesNotContain(signer, alone);
                Assert.All(raws, raw => Assert.False(new PublicKey(raw).Verify(rawSignature, Bytes.Utf8(c.GetProperty("base").GetString()!))));
            }
            else
            {
                // Accepted, or a header refused before any key is tried, whose key state would accept.
                Assert.Contains(signer, alone);
                Assert.True(error == null || Strings(Load("refusals.json").GetProperty("codes")).Contains(error));
            }
        }
    }
}
