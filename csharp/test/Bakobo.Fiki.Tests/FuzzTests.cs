using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// A deterministic, seeded mutation test (tick 7xbw). Inputs are the httpwg corpus's raw fields
    /// and the Signature-Input and Signature values of vectors/accepts.json and refusals.json,
    /// mutated at the level of .NET's string unit, the UTF-16 code unit, by flips, insertions,
    /// deletions, truncation and splicing, over an alphabet that includes non-ASCII, the C1
    /// controls, U+2028 and lone surrogates. From the parser the only allowed outcomes are a value
    /// or its FormatException (fiki's malformed error, once wrapped); from the bounded entry point a
    /// value or the header's malformed kind; from VerifyRequest, which is handed wire input and so
    /// never owes a caller error, a verdict or a FikiException. Anything else fails with the seed,
    /// the iteration and the input.
    /// </summary>
    public class FuzzTests
    {
        private const ulong Seed = 0x7B5D_F1C1_2026_1009;
        private const int Iterations = 20000;

        /// <summary>xorshift64*: no dependency, and the same sequence on every runtime.</summary>
        internal sealed class XorShift
        {
            private ulong _state;

            internal XorShift(ulong seed)
            {
                _state = seed == 0 ? 1 : seed;
            }

            internal ulong Next()
            {
                _state ^= _state >> 12;
                _state ^= _state << 25;
                _state ^= _state >> 27;
                return _state * 0x2545F4914F6CDD1DUL;
            }

            internal int Below(int bound) => bound <= 0 ? 0 : (int)(Next() % (ulong)bound);
        }

        // The structural characters RFC 8941 reads, the printable ASCII around them, and what a
        // UTF-16 string can hold that no honest header does.
        private static readonly char[] Alphabet =
            "\"\\=;,()?:*-._/ \t0123456789aAzZ+/!#%&'@^`|~"
            .Concat(new[] { '\0', '\r', '\n', '\x7f', '\u00e9', '\u4e2d', '\u2028', '\u2029', '\ufeff', '\ufffd', '\ud800', '\udbff', '\udc00', '\udfff' })
            .Concat(Enumerable.Range(0x80, 0x20).Select(c => (char)c))
            .ToArray();

        private sealed class Vector
        {
            internal string Method = "";
            internal string Url = "";
            internal List<KeyValuePair<string, string>> Headers = new List<KeyValuePair<string, string>>();
            internal byte[]? Body;
        }

        private static List<Vector> Vectors()
        {
            var vectors = new List<Vector>();
            foreach (var file in new[] { "accepts.json", "refusals.json" })
            {
                foreach (var c in Repo.Json("vectors", file).GetProperty("cases").EnumerateArray())
                {
                    vectors.Add(new Vector
                    {
                        Method = c.GetProperty("method").GetString()!,
                        Url = c.GetProperty("url").GetString()!,
                        Headers = VectorsTests.Headers(c.GetProperty("headers")),
                        Body = VectorsTests.Body(c),
                    });
                }
            }
            return vectors;
        }

        private static List<string> Seeds(List<Vector> vectors)
        {
            var seeds = new List<string>();
            var dir = Repo.PathTo("vectors", "third_party", "structured-field-tests");
            foreach (var file in Directory.GetFiles(dir, "*.json").OrderBy(f => f, StringComparer.Ordinal))
            {
                using var document = JsonDocument.Parse(File.ReadAllText(file));
                foreach (var test in document.RootElement.EnumerateArray())
                {
                    seeds.Add(string.Join(", ", test.GetProperty("raw").EnumerateArray().Select(r => r.GetString())));
                }
            }
            foreach (var vector in vectors)
            {
                foreach (var header in vector.Headers)
                {
                    if (header.Key == "Signature-Input" || header.Key == "Signature")
                    {
                        seeds.Add(header.Value);
                    }
                }
            }
            return seeds;
        }

        internal static string Mutate(XorShift random, string text, List<string> seeds)
        {
            var output = new StringBuilder(text);
            var steps = 1 + random.Below(4);
            for (var step = 0; step < steps; step++)
            {
                var at = random.Below(output.Length + 1);
                switch (random.Below(5))
                {
                    case 0: // flip one unit
                        if (output.Length > 0)
                        {
                            output[Math.Min(at, output.Length - 1)] = Alphabet[random.Below(Alphabet.Length)];
                        }
                        break;
                    case 1: // insert a run
                        output.Insert(at, new string(Alphabet[random.Below(Alphabet.Length)], 1 + random.Below(3)));
                        break;
                    case 2: // delete a run
                        output.Remove(Math.Min(at, output.Length), Math.Min(1 + random.Below(4), output.Length - Math.Min(at, output.Length)));
                        break;
                    case 3: // truncate
                        output.Length = Math.Min(at, output.Length);
                        break;
                    default: // splice in a piece of another input
                        var other = seeds[random.Below(seeds.Count)];
                        var from = random.Below(other.Length + 1);
                        output.Insert(at, other.Substring(from, Math.Min(other.Length - from, random.Below(24))));
                        break;
                }
            }
            return output.ToString();
        }

        internal static string Escaped(string text)
        {
            var output = new StringBuilder();
            foreach (var c in text)
            {
                output.Append(c >= ' ' && c <= '~' && c != '\\' ? c.ToString() : "\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture));
            }
            return output.ToString();
        }

        /// <summary>Null when every outcome is allowed, otherwise the first that was not.</summary>
        private static string? Feed(string input, Vector vector, bool replaceSignature, VerifyOptions options)
        {
            foreach (var (name, parse) in new (string, Action)[]
            {
                ("Sfv.ParseDictionary", () => Sfv.ParseDictionary(input)),
                ("Sfv.ParseList", () => Sfv.ParseList(input)),
                ("Sfv.ParseItem", () => Sfv.ParseItem(input)),
            })
            {
                try
                {
                    parse();
                }
                catch (FormatException)
                {
                }
                catch (Exception ex)
                {
                    return $"{name} threw {ex.GetType().Name}: {ex.Message}";
                }
            }
            foreach (var (name, parse) in new (string, Action)[]
            {
                ("Messages.Parse", () => Messages.Parse(input, "Signature-Input", FikiErrorKind.MalformedSignatureInput)),
                ("Messages.ParseList", () => Messages.ParseList(input, "Signature-Input", FikiErrorKind.MalformedSignatureInput)),
                ("Messages.ParseItem", () => Messages.ParseItem(input, "Signature-Input", FikiErrorKind.MalformedSignatureInput)),
            })
            {
                try
                {
                    parse();
                }
                catch (FikiException ex) when (ex.Kind == FikiErrorKind.MalformedSignatureInput)
                {
                }
                catch (Exception ex)
                {
                    return $"{name} threw {ex.GetType().Name}: {ex.Message}";
                }
            }
            var target = replaceSignature ? "Signature" : "Signature-Input";
            var headers = vector.Headers.Select(h => h.Key == target ? new KeyValuePair<string, string>(h.Key, input) : h).ToList();
            try
            {
                HttpSignatures.VerifyRequest(vector.Method, vector.Url, headers, options.WithBody(vector.Body));
            }
            catch (FikiException)
            {
            }
            catch (Exception ex)
            {
                return $"VerifyRequest with it as {target} threw {ex.GetType().Name}: {ex.Message}";
            }
            return null;
        }

        /// <summary>Every decision stated, a different combination per iteration.</summary>
        private static VerifyOptions Options(XorShift random)
        {
            var options = random.Below(2) == 0 ? VerifyOptions.DecliningFreshness() : VerifyOptions.MaxAge(300).WithNow(1700000000);
            options = random.Below(2) == 0 ? options.DecliningAuthorityCheck() : options.WithAuthorities(new[] { "api.example.com" });
            return random.Below(2) == 0 ? options.WithMinimum(HttpSignatures.DefaultMinimum) : options.WithoutMinimum();
        }

        [Fact]
        public void TwentyThousandMutantsGetOnlyAllowedOutcomes()
        {
            var vectors = Vectors();
            var seeds = Seeds(vectors);
            var random = new XorShift(Seed);
            var clock = Stopwatch.StartNew();
            for (var i = 0; i < Iterations; i++)
            {
                var input = Mutate(random, seeds[random.Below(seeds.Count)], seeds);
                var vector = vectors[random.Below(vectors.Count)];
                var problem = Feed(input, vector, random.Below(2) == 0, Options(random));
                Assert.True(problem == null, $"seed 0x{Seed:x}, iteration {i}: {problem}\ninput: \"{Escaped(input)}\"");
            }
            // Generous: the point is to keep the run near ten seconds on CI, not to time it.
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(60), $"{Iterations} mutants took {clock.Elapsed}");
        }

        [Fact]
        public void TheGeneratorIsDeterministicAndReachesEveryMutation()
        {
            var a = new XorShift(Seed);
            var b = new XorShift(Seed);
            Assert.Equal(Enumerable.Range(0, 8).Select(_ => a.Next()), Enumerable.Range(0, 8).Select(_ => b.Next()));
            Assert.NotEqual(0UL, new XorShift(0).Next());
            var seeds = new List<string> { "sig=(\"@method\");created=1" };
            var random = new XorShift(Seed);
            var seen = new HashSet<string>();
            for (var i = 0; i < 2000; i++)
            {
                seen.Add(Mutate(random, seeds[0], seeds));
            }
            Assert.True(seen.Count > 1000);
            Assert.Contains(seen, s => s.Any(char.IsSurrogate));
            Assert.Contains(seen, s => s.Any(c => c >= '\x80' && c <= '\x9f'));
            Assert.Contains(seen, s => s.Contains('\u2028'));
            Assert.Contains(seen, s => s.Length < seeds[0].Length);
            Assert.Contains(seen, s => s.Length > seeds[0].Length);
        }

        [Fact]
        public void AnOutcomeOutsideTheAllowedSetIsReportedWithTheInput()
        {
            Assert.Equal("a\\u0000\\ud800\\u005c", Escaped("a\0\ud800\\"));
            var vector = Vectors()[0];
            Assert.Null(Feed("sig=:AAAA:", vector, true, VerifyOptions.DecliningFreshness().DecliningAuthorityCheck().WithoutMinimum()));
            // A caller error from the verifier is not an allowed outcome for wire input.
            var problem = Feed("x", vector, false, VerifyOptions.DecliningFreshness());
            Assert.NotNull(problem);
            Assert.Contains("ArgumentException", problem!, StringComparison.Ordinal);
        }
    }
}
