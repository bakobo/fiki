using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The C# samples in docs/user-guide.md, run, mirroring py/tests/test_guide.py. A guide whose
    /// code does not compile is worse than no guide: a reader trusts it, pastes it, and loses an hour
    /// to an API that moved. So the samples below are the guide's own text, and a test checks that
    /// every C# block in the guide appears here line for line.
    /// </summary>
    public class GuideTests
    {
        [Fact]
        public void TheGuidesSigningSampleRuns()
        {
            // guide: signing
            var key = Key.Generate();                  // or Key.FromSeed(seed)
            Console.WriteLine(key.Aid);                // register this
            byte[] seed = key.Seed;                    // 32 bytes: store them where only you can read them

            var url = "https://api.example.com/things?limit=1";
            var body = Encoding.UTF8.GetBytes("{\"hello\": \"world\"}");
            var headers = HttpSignatures.SignRequest(key, "POST", url, body: body);
            // headers -> Signature-Input, Signature, Content-Digest
            // end guide

            Assert.Equal(key.Aid, Key.FromSeed(seed).Aid);
            Assert.StartsWith("B", key.Aid, StringComparison.Ordinal);
            Assert.Equal(32, key.Seed.Length);
            Assert.Equal(new[] { "Signature-Input", "Signature", "Content-Digest" }, headers.Keys.ToArray());
        }

        [Fact]
        public void TheGuidesVerifyingSampleRuns()
        {
            var key = Key.Generate();
            var method = "POST";
            var url = "https://api.example.com/things?limit=1";
            var body = Encoding.UTF8.GetBytes("{\"hello\": \"world\"}");
            var headers = HttpSignatures.SignRequest(key, method, url, body: body);
            var registeredAidForThisClient = key.Aid;

            // guide: verifying
            Verdict verdict;
            try
            {
                verdict = HttpSignatures.VerifyRequest(method, url, headers,
                    VerifyOptions.MaxAge(300).WithBody(body));
            }
            catch (FikiException e)
            {
                throw new UnauthorizedAccessException(e.Message, e);   // a 401
            }

            if (verdict.Aid != registeredAidForThisClient)
            {
                throw new UnauthorizedAccessException("not the client we expected");   // a 403
            }
            // end guide

            Assert.Equal(key.Aid, verdict.Aid);

            // Preregistration, and declining the freshness check, both as the guide spells them.
            Assert.Equal(key.Aid, HttpSignatures.VerifyRequest(method, url, headers,
                VerifyOptions.DecliningFreshness().WithExpectedAid(key.Aid).WithBody(body)).Aid);

            var caught = Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest(method, url, headers,
                VerifyOptions.DecliningFreshness().WithBody(Encoding.UTF8.GetBytes("tampered"))));
            Assert.Equal(FikiErrorKind.DigestMismatch, caught.Kind);
        }

        // The synthetic controller and agent of vectors/keri/, so the values are real, not placeholders.
        private static readonly Key Controller = Key.FromSeed(Bytes.FromHex("02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"));
        private const string ControllerAid = "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx";
        private static readonly Key Agent = Key.FromSeed(Bytes.FromHex("030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122"));
        private const string AgentAid = "EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6";

        /// <summary>The verifier's own key state: each AID to the raw bytes of its current signing key.</summary>
        private static Dictionary<string, byte[]> KeyState() => new Dictionary<string, byte[]>
        {
            [ControllerAid] = Key.VerifyingKey(Controller.Aid).ToBytes(),
            [AgentAid] = Key.VerifyingKey(Agent.Aid).ToBytes(),
        };

        private const string KeriUrl = "https://keria.example.com/identifiers";
        private static readonly byte[] KeriBody = Encoding.UTF8.GetBytes("{\"name\": \"alice\"}");

        private static IReadOnlyDictionary<string, string> KeriRequest()
        {
            var key = Controller;
            var aid = ControllerAid;
            var url = KeriUrl;
            var body = KeriBody;

            // guide: signing with a KERI identifier
            var headers = HttpSignatures.SignRequest(key, "POST", url, body: body,
                keyId: aid,                                  // the AID; the verifier resolves it
                minimum: HttpSignatures.RequestMinimum);     // refuse what a profile verifier would refuse
            // end guide

            return headers;
        }

        [Fact]
        public void TheGuidesKeriSigningSampleNamesTheAid()
        {
            var headers = KeriRequest();
            Assert.Contains($"keyid=\"{ControllerAid}\"", headers["Signature-Input"], StringComparison.Ordinal);
            Assert.True(headers.ContainsKey("Content-Digest"));
        }

        [Fact]
        public void TheGuidesResolverSampleRuns()
        {
            var keyState = KeyState();
            var url = KeriUrl;
            var body = KeriBody;
            var headers = KeriRequest();

            // guide: verifying with a resolver
            Func<string, byte[]?> resolve = keyid =>
                keyState.TryGetValue(keyid, out var current) ? current : null;   // null: UnknownKey

            var verdict = HttpSignatures.VerifyRequest("POST", url, headers,
                VerifyOptions.MaxAge(300).WithSkew(60).WithBody(body)
                    .WithResolver(resolve)
                    .WithMinimum(HttpSignatures.RequestMinimum)
                    .WithAuthorities(new[] { "keria.example.com" }));   // the authorities this server answers for
            // verdict.Aid is the AID the resolver vouched for
            // end guide

            Assert.Equal(ControllerAid, verdict.Aid);
            Assert.Equal(ControllerAid, verdict.KeyId);

            var caught = Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("POST", url, headers,
                VerifyOptions.MaxAge(300).WithBody(body).WithResolver(_ => null).WithMinimum(HttpSignatures.RequestMinimum)));
            Assert.Equal(FikiErrorKind.UnknownKey, caught.Kind);
            Assert.Equal(ControllerAid, caught.KeyId);
        }

        [Fact]
        public void TheGuidesResponseSamplesRun()
        {
            var keyState = KeyState();
            Func<string, byte[]?> resolve = keyid => keyState.TryGetValue(keyid, out var current) ? current : null;
            var url = KeriUrl;
            var body = KeriBody;
            var requestHeaders = KeriRequest();
            var agent = Agent;
            var agentAid = AgentAid;
            var responseBody = Encoding.UTF8.GetBytes("{\"done\": true}");

            // guide: signing a response
            var request = new Request("POST", url, requestHeaders, body);   // the request it answers
            var responseHeaders = HttpSignatures.SignResponse(agent, 201, request,
                body: responseBody, keyId: agentAid,
                minimum: HttpSignatures.ResponseMinimum);
            // end guide

            // guide: verifying a response
            var answer = HttpSignatures.VerifyResponse(201, responseHeaders,
                VerifyOptions.MaxAge(300).WithBody(responseBody).WithRequest(request)
                    .WithResolver(resolve)
                    .WithExpectedKeyId(agentAid)                 // the AID this client is talking to
                    .WithMinimum(HttpSignatures.ResponseMinimum));
            // end guide

            Assert.Equal(AgentAid, answer.KeyId);
            Assert.Contains("\"content-digest\";req", answer.Covered);

            var caught = Assert.Throws<FikiException>(() => HttpSignatures.VerifyResponse(201, responseHeaders,
                VerifyOptions.MaxAge(300).WithBody(responseBody).WithRequest(request).WithResolver(resolve)
                    .WithExpectedKeyId(ControllerAid).WithMinimum(HttpSignatures.ResponseMinimum)));
            Assert.Equal(FikiErrorKind.UnknownKey, caught.Kind);
        }

        private static string Refusal(Action verify)
        {
            // guide: the new error kinds
            try
            {
                verify();
            }
            catch (FikiException e)
            {
                return e.Kind switch
                {
                    FikiErrorKind.UnknownKey => "no key state for " + e.KeyId,
                    FikiErrorKind.UnsupportedSigner => "no single key of " + e.KeyId + " signs alone",
                    FikiErrorKind.InsufficientCoverage => "the signature does not cover " + e.Component,
                    FikiErrorKind.DuplicateComponent => "the covered list names " + e.Component + " twice",
                    FikiErrorKind.Unauthenticated => "an unsigned 401; its body is not to be trusted",
                    _ => e.Kind.ToString(),
                };
            }
            // end guide
            return "verified";
        }

        private static byte[]? Group(string keyid) =>
            // guide: a resolver that refuses
            throw new FikiException(FikiErrorKind.UnsupportedSigner,
                "This AID's key state has no single key that satisfies its threshold.", keyid);
        // end guide

        [Fact]
        public void TheGuidesErrorSampleNamesEachNewRefusal()
        {
            var keyState = KeyState();
            var headers = KeriRequest();
            Func<string, byte[]?> known = keyid => keyState.TryGetValue(keyid, out var current) ? current : null;
            Action Verify(IEnumerable<KeyValuePair<string, string>> h, Func<string, byte[]?> resolve) =>
                () => HttpSignatures.VerifyRequest("POST", KeriUrl, h,
                    VerifyOptions.MaxAge(300).WithBody(KeriBody).WithResolver(resolve).WithMinimum(HttpSignatures.RequestMinimum));

            Assert.Equal("verified", Refusal(Verify(headers, known)));
            Assert.Equal("no key state for " + ControllerAid, Refusal(Verify(headers, _ => null)));
            Assert.Equal("no single key of " + ControllerAid + " signs alone", Refusal(Verify(headers, Group)));

            var thin = HttpSignatures.SignRequest(Controller, "POST", KeriUrl, body: KeriBody, keyId: ControllerAid,
                covered: new[] { "@method", "@path", "content-digest" });
            Assert.Equal("the signature does not cover @query", Refusal(Verify(thin, known)));

            var twice = headers.ToDictionary(p => p.Key, p => p.Value);
            twice["Signature-Input"] = twice["Signature-Input"].Replace("(\"@method\"", "(\"@method\" \"@method\"");
            Assert.Equal("the covered list names @method twice", Refusal(Verify(twice, known)));

            Assert.Equal("an unsigned 401; its body is not to be trusted", Refusal(() =>
                HttpSignatures.VerifyResponse(401, new Dictionary<string, string>(), VerifyOptions.MaxAge(300))));
            Assert.Equal("MissingSignature", Refusal(Verify(new Dictionary<string, string>(), known)));

            // A mistake in the call is not a refusal of the message, so it is never a FikiException.
            Assert.Throws<ArgumentException>(() => HttpSignatures.VerifyRequest("POST", KeriUrl, headers,
                VerifyOptions.MaxAge(300).WithBody(KeriBody).WithResolver(known).WithMinimum(new[] { "@method" })));
            Assert.Throws<ArgumentException>(() => HttpSignatures.VerifyRequest("POST", KeriUrl, headers,
                VerifyOptions.MaxAge(300).WithBody(KeriBody).WithResolver(known).WithExpectedAid(Controller.Aid)));
        }

        private static List<string> Lines(string text) =>
            text.Replace("\r\n", "\n").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();

        /// <summary>The C# blocks in the guide, each as its trimmed, non-empty lines.</summary>
        private static List<List<string>> GuideBlocks()
        {
            var guide = File.ReadAllText(Repo.PathTo("docs", "user-guide.md"));
            return Regex.Matches(guide.Replace("\r\n", "\n"), "```csharp\n(.*?)```", RegexOptions.Singleline)
                .Cast<Match>().Select(m => Lines(m.Groups[1].Value)).ToList();
        }

        /// <summary>The samples above, between their "guide:" and "end guide" markers.</summary>
        private static List<List<string>> TestedSamples()
        {
            var source = Lines(File.ReadAllText(Repo.PathTo("csharp", "test", "Bakobo.Fiki.Tests", "GuideTests.cs")));
            var samples = new List<List<string>>();
            for (var i = 0; i < source.Count; i++)
            {
                if (source[i].StartsWith("// guide:", StringComparison.Ordinal))
                {
                    var end = source.IndexOf("// end guide", i);
                    samples.Add(source.GetRange(i + 1, end - i - 1));
                }
            }
            return samples;
        }

        [Fact]
        public void EveryCSharpBlockInTheGuideIsASampleRunHere()
        {
            var blocks = GuideBlocks();
            var samples = TestedSamples();
            Assert.Equal(8, samples.Count);
            Assert.NotEmpty(blocks);
            foreach (var block in blocks)
            {
                // A block may open with the using directive a reader needs, which a test file
                // carries at its top instead.
                var body = block.Where(l => !l.StartsWith("using ", StringComparison.Ordinal)).ToList();
                Assert.Contains(samples, sample => sample.SequenceEqual(body));
            }
            Assert.All(samples, sample => Assert.Contains(blocks, block =>
                block.Where(l => !l.StartsWith("using ", StringComparison.Ordinal)).SequenceEqual(sample)));
        }
    }
}
