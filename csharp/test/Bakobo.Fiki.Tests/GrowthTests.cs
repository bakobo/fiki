using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>Run after every other test and alone, so no test in the same process competes for the CPU being timed.</summary>
    [CollectionDefinition("Growth", DisableParallelization = true)]
    public class GrowthCollection
    {
    }

    /// <summary>
    /// The tests that time fiki, each as a ratio rather than a deadline (tick 7xbw; see
    /// <see cref="Growth"/>). From the hostile review of bakobo/fiki#7, finding 2 (a long covered
    /// list costs linear work), and the sweep's A6 (parsing is linear). Before 2026-10-09 each
    /// asserted a wall-clock bound, and two failed on a loaded machine that day.
    /// </summary>
    [Collection("Growth")]
    public class GrowthTests
    {
        private const string HostileUrl = "https://api.example.com/things?limit=1";

        [Fact]
        public void AnOverlongSignatureInputIsRefusedWithoutBeingReadToItsEnd()
        {
            // A received Signature-Input this long is over MaxFieldBytes and refused before it is
            // parsed (@5zrf8gjk), so refusing one four times as long costs no more (tick 7xbw).
            Func<int, Action> refuse = n =>
            {
                var input = "sig=(" + string.Join(" ", Enumerable.Range(0, n).Select(i => $"x-{i}").ToArray().Select(c => "\"" + c + "\"")) + ");created=1;keyid=\"k\"";
                var headers = new Dictionary<string, string> { { "Signature-Input", input }, { "Signature", "sig=:" + Convert.ToBase64String(new byte[64]) + ":" } };
                var options = Verifying.DecliningFreshness().WithExpectedAid(SignVerifyTests.TheKey.Aid);
                return () => Assert.Equal(FikiErrorKind.MalformedSignatureInput, Assert.Throws<FikiException>(() =>
                    HttpSignatures.VerifyRequest("GET", HostileUrl, headers, options)).Kind);
            };
            var ratio = Growth.Ratio(refuse, 50000, repeat: 50);
            Assert.True(ratio < Growth.BoundedCeiling, $"refusing an input {Growth.Factor} times as long took {ratio:F2} times as long");
        }

        [Fact]
        public void ALongCoveredListIsCheckedInLinearTime()
        {
            // A caller's own list is not bounded, and the work is linear, as py's set in
            // check_covered makes it.
            Func<int, Action> check = n =>
            {
                var covered = Enumerable.Range(0, n).Select(i => $"x-{i}").ToArray();
                return () => Assert.Equal(FikiErrorKind.MissingComponent, Assert.Throws<FikiException>(() =>
                    HttpSignatures.SignatureBase("GET", HostileUrl, new Dictionary<string, string>(), covered, 1, "k")).Kind);
            };
            var ratio = Growth.Ratio(check, 6250, repeat: 2);
            Assert.True(ratio < Growth.LinearCeiling, $"a list {Growth.Factor} times as long took {ratio:F2} times as long");
        }

        [Theory]
        [InlineData("parameters")]
        [InlineData("members")]
        public void ParametersAndMembersParseInLinearTime(string what)
        {
            Func<int, Action> parse = n =>
            {
                var text = what == "parameters"
                    ? "sig=(\"@method\")" + string.Concat(Enumerable.Range(0, n).Select(i => $";p{i}=1"))
                    : string.Join(", ", Enumerable.Range(0, n).Select(i => $"m{i}=:AAAA:"));
                return () => Sfv.ParseDictionary(text);
            };
            var ratio = Growth.Ratio(parse, 6250, repeat: 2);
            Assert.True(ratio < Growth.LinearCeiling, $"{Growth.Factor} times as many {what} took {ratio:F2} times as long");
        }

        [Fact]
        public void ALongCoveredListIsBuiltInLinearTime()
        {
            Func<int, Action> build = n =>
            {
                var headers = new List<KeyValuePair<string, string>>();
                var covered = new List<string>();
                for (var i = 0; i < n; i++)
                {
                    headers.Add(new KeyValuePair<string, string>("x-h" + i, "v"));
                    covered.Add("x-h" + i);
                }
                return () => HttpSignatures.SignatureBase("GET", HostileUrl, headers, covered, 1700000000, "k");
            };
            var ratio = Growth.Ratio(build, 6250, repeat: 2);
            Assert.True(ratio < Growth.LinearCeiling, $"{Growth.Factor} times as many components took {ratio:F2} times as long");
        }

        [Fact]
        public void ManyParametersAreParsedInLinearTime()
        {
            Assert.Equal(50000, Sfv.ParseDictionary("sig=" + Parameters(50000)).Single().Value.Params.Count);
            Func<int, Action> parse = n =>
            {
                var text = "sig=" + Parameters(n);
                return () => Sfv.ParseDictionary(text);
            };
            var ratio = Growth.Ratio(parse, 6250, repeat: 2);
            Assert.True(ratio < Growth.LinearCeiling, $"{Growth.Factor} times as many parameters took {ratio:F2} times as long");
        }

        private static string Parameters(int n)
        {
            var text = new StringBuilder("(\"@path\")");
            for (var i = 0; i < n; i++)
            {
                text.Append(";p").Append(i);
            }
            return text.ToString();
        }

    }
}
