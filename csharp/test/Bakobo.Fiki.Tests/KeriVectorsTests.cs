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
    /// adds is what py's imports from vectors/keri/generate.py: the class-to-code table, the
    /// well-formedness rule, the resolver a KERI verifier would back with key event logs, and the
    /// policy-applying verifier. They are ported below, and the code table is checked against the
    /// generator's own text so the two cannot drift.
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

        private static string[] Strings(JsonElement array) => array.EnumerateArray().Select(x => x.GetString()!).ToArray();

        // --- generate.py's rules, ported ---

        /// <summary>
        /// KEYS_RULE's test: 44 characters, a B, D or E code, and 43 base64url characters that decode
        /// behind one pad character to 32 bytes with a zero pad byte, so re-encoding gives the keyid
        /// back. Written against System.Convert rather than fiki's own decoder, as the generator's is
        /// independent of fiki's.
        /// </summary>
        internal static bool WellFormedAid(string keyId)
        {
            if (keyId.Length != 44 || "BDE".IndexOf(keyId[0]) < 0)
            {
                return false;
            }
            byte[] decoded;
            try
            {
                decoded = Convert.FromBase64String("A" + keyId.Substring(1).Replace('-', '+').Replace('_', '/'));
            }
            catch (FormatException)
            {
                return false;
            }
            return decoded.Length == 33 && Qb64(keyId[0], decoded.Skip(1).ToArray()) == keyId;
        }

        private static string Qb64(char code, byte[] raw) => code + Bytes.B64Url(new byte[] { 0 }.Concat(raw).ToArray()).Substring(1);

        /// <summary>What a KERI verifier's key lookup does, for a keys table: authoritative, never a decode.</summary>
        internal static Func<string, byte[]?> Resolver(JsonElement keys)
        {
            var table = keys.EnumerateArray().Where(e => e.GetProperty("kind").GetString() == "transferable")
                .ToDictionary(e => e.GetProperty("keyid").GetString()!, e => e);
            return keyId =>
            {
                if (!WellFormedAid(keyId))
                {
                    throw new FikiException(FikiErrorKind.MalformedKey, $"\"{keyId}\" is not a well-formed AID.", keyId: keyId);
                }
                if (keyId[0] == 'B')
                {
                    return Key.VerifyingKey(keyId).ToBytes();
                }
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

            var options = VerifyOptions.MaxAge(Policy("max_age", out _).GetInt64())
                .WithSkew(Policy("skew", out _).GetInt64())
                .WithNow(now)
                .WithResolver(Resolver(keys));
            var expectedKeyId = Policy("expected_keyid", out var hasExpected);
            if (hasExpected)
            {
                options = options.WithExpectedKeyId(expectedKeyId.GetString()!);
            }
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
            c.GetProperty("now").GetInt64(), data.GetProperty("policy"),
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
            Assert.True(new PublicKey(Resolver(keys)(keyId)!).Verify(Convert.FromBase64String(signature), bas));
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
            Assert.Equal(1, profile.GetProperty("version").GetInt32());
            Assert.Equal("https://github.com/bakobo/fiki/blob/main/docs/keri-profile.md", profile.GetProperty("where").GetString());
            var doc = File.ReadAllText(Repo.PathTo("docs", "keri-profile.md")).Replace("\r\n", "\n");
            Assert.StartsWith($"# {profile.GetProperty("title").GetString()}\n\nVersion 1, ", doc, StringComparison.Ordinal);
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
            Verify(c.GetProperty("request"), null, c.GetProperty("now").GetInt64(), data.GetProperty("policy"), null, data.GetProperty("keys"));
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
                Assert.Contains(source.GetProperty("repo").GetString(), new[] { "WebOfTrust/keria", "WebOfTrust/signify-ts" });
                Assert.Equal(40, source.GetProperty("commit").GetString()!.Length);
                Assert.False(string.IsNullOrEmpty(source.GetProperty("file").GetString()));
                Assert.False(string.IsNullOrEmpty(source.GetProperty("lines").GetString()));
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
    }
}
