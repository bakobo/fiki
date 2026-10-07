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
            Assert.Equal(2, samples.Count);
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
