using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The httpwg structured-field-tests corpus (this.i @7fexwu3s), vendored under
    /// vectors/third_party/structured-field-tests, run against this port's RFC 8941 parser.
    /// </summary>
    /// <remarks>
    /// Every case goes through a bounded entry point: a dictionary through
    /// <see cref="Messages.Parse"/>, the one the verifier reads Signature-Input with, and a list or
    /// an item through <see cref="Messages.ParseList"/> or <see cref="Messages.ParseItem"/>, which
    /// apply the same four bounds. The rules are the brief's, the same in all six ports: a case
    /// with a Date or a Display String fails (@7vdhfv3q); a case over any of fiki's bounds fails;
    /// a can_fail case asserts the one outcome fiki dictates, padding by @2g4xxev9 and any other by
    /// fiki-py's outcome; every other case matches the corpus exactly, parameters and their order
    /// included.
    /// </remarks>
    public class CorpusTests
    {
        private static readonly string Dir = Repo.PathTo("vectors", "third_party", "structured-field-tests");

        // Cases per file at hardening-a, read from the files once, so an emptied or truncated file
        // fails rather than passing on fewer cases. Every case runs; none is skipped.
        private static readonly Dictionary<string, int> Counts = new Dictionary<string, int>
        {
            { "binary.json", 17 }, { "boolean.json", 12 }, { "date.json", 17 }, { "dictionary.json", 26 },
            { "display-string.json", 22 }, { "examples.json", 21 }, { "item.json", 5 }, { "key-generated.json", 640 },
            { "large-generated.json", 11 }, { "list.json", 11 }, { "listlist.json", 12 }, { "number-generated.json", 193 },
            { "number.json", 37 }, { "param-dict.json", 14 }, { "param-list.json", 20 }, { "param-listlist.json", 3 },
            { "string-generated.json", 256 }, { "string.json", 14 }, { "token-generated.json", 256 }, { "token.json", 6 },
        };

        // The can_fail cases other than padding, and fiki-py's outcome for each: http_sfv parses the
        // combined field '"foo, bar"' as one string. The two Date cases and the Display String one
        // are refused by @7vdhfv3q before can_fail is consulted.
        private static readonly Dictionary<string, bool> PyCanFail = new Dictionary<string, bool>
        {
            { "two lines string", true },
        };

        // @2g4xxev9: missing, partial or extra padding is refused; non-zero pad bits are accepted.
        private static readonly Dictionary<string, bool> PaddingCanFail = new Dictionary<string, bool>
        {
            { "unpadded", false }, { "partially padded", false }, { "extra padding", false }, { "non-zero pad bits", true },
        };

        public static IEnumerable<object[]> Files() => Counts.Keys.Select(f => new object[] { f });

        [Fact]
        public void EveryFileInTheCorpusIsRun()
        {
            var present = Directory.GetFiles(Dir, "*.json").Select(Path.GetFileName).OrderBy(f => f, StringComparer.Ordinal);
            Assert.Equal(Counts.Keys.OrderBy(f => f, StringComparer.Ordinal), present);
        }

        [Theory]
        [MemberData(nameof(Files))]
        public void EveryCaseInTheFileGetsTheOutcomeFikiDictates(string file)
        {
            var failures = new List<string>();
            var run = 0;
            using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(Dir, file)));
            foreach (var test in document.RootElement.EnumerateArray())
            {
                run++;
                var problem = Run(file, test);
                if (problem != null)
                {
                    failures.Add(test.GetProperty("name").GetString() + ": " + problem);
                }
            }
            Assert.True(failures.Count == 0, $"{failures.Count} of {run} cases in {file} disagreed:\n" + string.Join("\n", failures));
            Assert.Equal(Counts[file], run);
        }

        /// <summary>Null when the case gets the outcome fiki dictates, otherwise what went wrong.</summary>
        private static string? Run(string file, JsonElement test)
        {
            var name = test.GetProperty("name").GetString()!;
            var raw = string.Join(", ", test.GetProperty("raw").EnumerateArray().Select(r => r.GetString()));
            var type = test.GetProperty("header_type").GetString()!;
            var hasExpected = test.TryGetProperty("expected", out var expected);
            var mustFail = test.TryGetProperty("must_fail", out var mf) && mf.GetBoolean();
            var canFail = test.TryGetProperty("can_fail", out var cf) && cf.GetBoolean();

            var why = "the corpus says must_fail";
            var fails = mustFail;
            if (!fails && (file == "date.json" || file == "display-string.json" || (hasExpected && UsesRfc9651(expected))))
            {
                fails = true;
                why = "it carries a Date or a Display String (@7vdhfv3q)";
            }
            if (!fails && hasExpected && OverBound(raw, type, expected) is string bound)
            {
                fails = true;
                why = "it is over " + bound;
            }
            if (!fails && canFail)
            {
                if (PaddingCanFail.TryGetValue(name, out var accepted))
                {
                    fails = !accepted;
                    why = "@2g4xxev9 refuses its padding";
                }
                else if (PyCanFail.TryGetValue(name, out var pyAccepts))
                {
                    fails = !pyAccepts;
                    why = "fiki-py refuses it";
                }
                else
                {
                    return "a can_fail case with no decided outcome; decide it from fiki-py and list it";
                }
            }

            object parsed;
            try
            {
                parsed = type switch
                {
                    "dictionary" => Messages.Parse(raw, "Signature-Input", FikiErrorKind.MalformedSignatureInput),
                    "list" => Messages.ParseList(raw, "Signature-Input", FikiErrorKind.MalformedSignatureInput),
                    "item" => (object)Messages.ParseItem(raw, "Signature-Input", FikiErrorKind.MalformedSignatureInput),
                    _ => throw new InvalidOperationException("no header_type " + type),
                };
            }
            catch (FikiException ex) when (ex.Kind == FikiErrorKind.MalformedSignatureInput)
            {
                if (!fails)
                {
                    return "refused, and the corpus expects it to parse: " + ex.Message;
                }
                if (why.StartsWith("it is over", StringComparison.Ordinal) && !ex.Message.Contains("fiki reads", StringComparison.Ordinal))
                {
                    return "refused for something other than the bound: " + ex.Message;
                }
                return null;
            }
            catch (Exception ex)
            {
                return "threw " + ex.GetType().Name + " rather than fiki's malformed error: " + ex.Message;
            }
            if (fails)
            {
                return "parsed, and must fail because " + why;
            }
            return type switch
            {
                "dictionary" => Dictionary(expected, (SfDictionary)parsed),
                "list" => List(expected, (List<SfMember>)parsed),
                _ => Item(expected, (SfItem)parsed),
            };
        }

        // --- the bounds, from the corpus's own expected structure ---

        private static string? OverBound(string raw, string type, JsonElement expected)
        {
            if (Encoding.UTF8.GetByteCount(raw) > HttpSignatures.MaxFieldBytes)
            {
                return "MaxFieldBytes";
            }
            var members = type == "item" ? new List<JsonElement> { expected } : expected.EnumerateArray().Select(m => type == "dictionary" ? m[1] : m).ToList();
            if (type != "item" && members.Count > HttpSignatures.MaxDictionaryMembers)
            {
                return "MaxDictionaryMembers";
            }
            foreach (var member in members)
            {
                if (member[1].GetArrayLength() > HttpSignatures.MaxParameters)
                {
                    return "MaxParameters";
                }
                if (member[0].ValueKind == JsonValueKind.Array)
                {
                    if (member[0].GetArrayLength() > HttpSignatures.MaxInnerListItems)
                    {
                        return "MaxInnerListItems";
                    }
                    if (member[0].EnumerateArray().Any(item => item[1].GetArrayLength() > HttpSignatures.MaxParameters))
                    {
                        return "MaxParameters";
                    }
                }
            }
            return null;
        }

        private static bool UsesRfc9651(JsonElement value)
        {
            switch (value.ValueKind)
            {
                case JsonValueKind.Array:
                    return value.EnumerateArray().Any(UsesRfc9651);
                case JsonValueKind.Object:
                    var type = value.GetProperty("__type").GetString();
                    return type == "date" || type == "displaystring";
                default:
                    return false;
            }
        }

        // --- comparing what parsed with what the corpus expects, exactly ---

        private static string? Dictionary(JsonElement expected, SfDictionary parsed)
        {
            var members = parsed.ToList();
            if (members.Count != expected.GetArrayLength())
            {
                return $"{members.Count} members, and the corpus expects {expected.GetArrayLength()}";
            }
            var i = 0;
            foreach (var pair in expected.EnumerateArray())
            {
                if (pair[0].GetString() != members[i].Key)
                {
                    return $"member {i} is {members[i].Key}, and the corpus expects {pair[0].GetString()}";
                }
                if (Member(pair[1], members[i].Value) is string problem)
                {
                    return $"member {members[i].Key}: {problem}";
                }
                i++;
            }
            return null;
        }

        private static string? List(JsonElement expected, List<SfMember> parsed)
        {
            if (parsed.Count != expected.GetArrayLength())
            {
                return $"{parsed.Count} members, and the corpus expects {expected.GetArrayLength()}";
            }
            var i = 0;
            foreach (var member in expected.EnumerateArray())
            {
                if (Member(member, parsed[i]) is string problem)
                {
                    return $"member {i}: {problem}";
                }
                i++;
            }
            return null;
        }

        private static string? Member(JsonElement expected, SfMember parsed)
        {
            if (expected[0].ValueKind != JsonValueKind.Array)
            {
                return parsed is SfItem item ? Item(expected, item) : "an inner list, and the corpus expects an item";
            }
            if (!(parsed is SfInnerList list))
            {
                return "an item, and the corpus expects an inner list";
            }
            if (list.Items.Count != expected[0].GetArrayLength())
            {
                return $"{list.Items.Count} inner-list items, and the corpus expects {expected[0].GetArrayLength()}";
            }
            var i = 0;
            foreach (var item in expected[0].EnumerateArray())
            {
                if (Item(item, list.Items[i]) is string problem)
                {
                    return $"inner-list item {i}: {problem}";
                }
                i++;
            }
            return Parameters(expected[1], list.Params);
        }

        private static string? Item(JsonElement expected, SfItem parsed) =>
            Bare(expected[0], parsed.Value) ?? Parameters(expected[1], parsed.Params);

        private static string? Parameters(JsonElement expected, SfParameters parsed)
        {
            var parameters = parsed.ToList();
            if (parameters.Count != expected.GetArrayLength())
            {
                return $"{parameters.Count} parameters, and the corpus expects {expected.GetArrayLength()}";
            }
            var i = 0;
            foreach (var pair in expected.EnumerateArray())
            {
                if (pair[0].GetString() != parameters[i].Key)
                {
                    return $"parameter {i} is {parameters[i].Key}, and the corpus expects {pair[0].GetString()}";
                }
                if (Bare(pair[1], parameters[i].Value) is string problem)
                {
                    return $"parameter {parameters[i].Key}: {problem}";
                }
                i++;
            }
            return null;
        }

        /// <summary>
        /// A JSON number is a decimal if and only if its literal has a "." or an exponent, since the
        /// loaded value cannot tell 1.0 from 1; a decimal compares at three fractional digits.
        /// </summary>
        private static string? Bare(JsonElement expected, SfValue parsed)
        {
            switch (expected.ValueKind)
            {
                case JsonValueKind.Number:
                    var literal = expected.GetRawText();
                    if (literal.IndexOfAny(new[] { '.', 'e', 'E' }) >= 0)
                    {
                        var want = Math.Round(decimal.Parse(literal, NumberStyles.Float, CultureInfo.InvariantCulture), 3);
                        return parsed.Type == SfType.Decimal && parsed.Decimal == want ? null : $"{Shown(parsed)}, and the corpus expects the decimal {want}";
                    }
                    var integer = long.Parse(literal, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
                    return parsed.Type == SfType.Integer && parsed.Integer == integer ? null : $"{Shown(parsed)}, and the corpus expects the integer {integer}";
                case JsonValueKind.String:
                    return parsed.Type == SfType.String && parsed.Text == expected.GetString() ? null : $"{Shown(parsed)}, and the corpus expects a string";
                case JsonValueKind.True:
                case JsonValueKind.False:
                    return parsed.Type == SfType.Boolean && parsed.Boolean == expected.GetBoolean() ? null : $"{Shown(parsed)}, and the corpus expects a boolean";
                default:
                    var value = expected.GetProperty("value");
                    switch (expected.GetProperty("__type").GetString())
                    {
                        case "token":
                            return parsed.Type == SfType.Token && parsed.Text == value.GetString() ? null : $"{Shown(parsed)}, and the corpus expects a token";
                        case "binary":
                            return parsed.Type == SfType.ByteSequence && parsed.Bytes.SequenceEqual(Base32(value.GetString()!))
                                ? null : $"{Shown(parsed)}, and the corpus expects a byte sequence";
                        default:
                            return $"{Shown(parsed)}, and the corpus expects an RFC 9651 type, which fiki refuses";
                    }
            }
        }

        private static string Shown(SfValue value) => value.Type + " " + value.Serialize();

        /// <summary>RFC 4648 base32, padded, as the corpus spells a byte sequence.</summary>
        internal static byte[] Base32(string text)
        {
            const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var output = new List<byte>();
            int buffer = 0, bits = 0;
            foreach (var c in text.TrimEnd('='))
            {
                buffer = (buffer << 5) | Alphabet.IndexOf(c);
                bits += 5;
                if (bits >= 8)
                {
                    bits -= 8;
                    output.Add((byte)(buffer >> bits));
                    buffer &= (1 << bits) - 1;
                }
            }
            return output.ToArray();
        }

        [Fact]
        public void Base32DecodesAsRfc4648Spells()
        {
            Assert.Equal(Encoding.ASCII.GetBytes("hello"), Base32("NBSWY3DP"));
            Assert.Equal(new byte[] { 0x89 }, Base32("RE======"));
            Assert.Empty(Base32(""));
        }

        // --- serialisation, through the public signing API ---

        private static readonly Key Signer = SignVerifyTests.TheKey;
        private const string Url = "https://api.example.com/x";
        private static readonly string SerialDir = Path.Combine(Dir, "serialisation-tests");

        private static JsonElement[] Serial(string file)
        {
            using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(SerialDir, file)));
            return document.RootElement.Clone().EnumerateArray().ToArray();
        }

        private static void CallerError(Action call, string fragment, string name, List<string> failures)
        {
            try
            {
                call();
                failures.Add(name + ": signed, and the corpus says must_fail");
            }
            catch (ArgumentException ex) when (ex.Message.Contains(fragment, StringComparison.Ordinal))
            {
            }
            catch (Exception ex)
            {
                failures.Add($"{name}: {ex.GetType().Name} rather than a caller error saying \"{fragment}\": {ex.Message}");
            }
        }

        [Fact]
        public void EveryGeneratedKeyIsRefusedAsALabelAndAsAComponentParameter()
        {
            // Every case is must_fail. As the label it is the caller's error, as py's ValueError is;
            // as a covered component's parameter key fiki-py refuses it as UnsupportedComponent, a
            // FikiError, since a component spelled in serialized form is read with the RFC 8941
            // parser and any parameter but req is unsupported. Both checked against fiki-py 0.9.0.
            var failures = new List<string>();
            var cases = Serial("key-generated.json");
            foreach (var test in cases)
            {
                var name = test.GetProperty("name").GetString()!;
                Assert.True(test.GetProperty("must_fail").GetBoolean());
                var first = test.GetProperty("expected")[0];
                var key = test.GetProperty("header_type").GetString() == "dictionary" ? first[0].GetString()! : first[1][0][0].GetString()!;
                CallerError(() => HttpSignatures.SignRequest(Signer, "GET", Url, created: 1, label: key), "is not an RFC 8941 dictionary key", name, failures);
                try
                {
                    HttpSignatures.SignRequest(Signer, "GET", Url, created: 1, covered: new[] { "@method", "@path", "@query", "\"x-a\";" + key });
                    failures.Add(name + ": signed with the key as a parameter");
                }
                catch (FikiException ex) when (ex.Kind == FikiErrorKind.UnsupportedComponent)
                {
                }
                catch (Exception ex)
                {
                    failures.Add($"{name}: {ex.GetType().Name} rather than UnsupportedComponent: {ex.Message}");
                }
            }
            Assert.True(failures.Count == 0, string.Join("\n", failures));
            Assert.Equal(378, cases.Length);
        }

        [Fact]
        public void EveryGeneratedStringIsRefusedAsAKeyidANonceAndATag()
        {
            var failures = new List<string>();
            var cases = Serial("string-generated.json");
            foreach (var test in cases)
            {
                var name = test.GetProperty("name").GetString()!;
                Assert.True(test.GetProperty("must_fail").GetBoolean());
                var text = test.GetProperty("expected")[0].GetString()!;
                const string Fragment = "holds a character outside printable ASCII";
                CallerError(() => HttpSignatures.SignRequest(Signer, "GET", Url, created: 1, keyId: text), Fragment, name + " (keyid)", failures);
                CallerError(() => HttpSignatures.SignRequest(Signer, "GET", Url, created: 1, nonce: text), Fragment, name + " (nonce)", failures);
                CallerError(() => HttpSignatures.SignRequest(Signer, "GET", Url, created: 1, tag: text), Fragment, name + " (tag)", failures);
            }
            Assert.True(failures.Count == 0, string.Join("\n", failures));
            Assert.Equal(33, cases.Length);
        }

        [Fact]
        public void EveryTooBigIntegerIsRefusedAsCreated()
        {
            // The subset is number.json's "too big" cases. created is a long here, so the two
            // decimal ones cannot be passed at all; fiki-py refuses them as a TypeError, the
            // compile-time refusal's runtime twin. The five rounding cases are outside the subset.
            var failures = new List<string>();
            var cases = Serial("number.json");
            var run = 0;
            var decimals = 0;
            foreach (var test in cases)
            {
                var name = test.GetProperty("name").GetString()!;
                if (!name.StartsWith("too big", StringComparison.Ordinal))
                {
                    continue;
                }
                Assert.True(test.GetProperty("must_fail").GetBoolean());
                var literal = test.GetProperty("expected")[0].GetRawText();
                if (literal.Contains('.'))
                {
                    decimals++;
                    continue;
                }
                run++;
                var created = long.Parse(literal, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
                CallerError(() => HttpSignatures.SignRequest(Signer, "GET", Url, created: created),
                    "RFC 8941 carries an integer of at most fifteen digits", name, failures);
            }
            Assert.True(failures.Count == 0, string.Join("\n", failures));
            Assert.Equal(9, cases.Length);
            Assert.Equal(2, run);
            Assert.Equal(2, decimals);
        }

        [Fact]
        public void TheSerialisationFilesAreTheOnesThisSubsetReads()
        {
            var present = Directory.GetFiles(SerialDir, "*.json").Select(Path.GetFileName).OrderBy(f => f, StringComparer.Ordinal);
            // token-generated.json is not in the subset: fiki serializes no token a caller chose.
            Assert.Equal(new[] { "key-generated.json", "number.json", "string-generated.json", "token-generated.json" }, present);
        }
    }
}
