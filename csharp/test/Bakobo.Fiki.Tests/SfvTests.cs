using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The hand-rolled RFC 8941 parser agrees with http_sfv, fiki-py's parser, input for input,
    /// except where http_sfv accepts what RFC 8941 refuses.
    /// </summary>
    /// <remarks>
    /// Which header parses decides between a Malformed* refusal and a later one, so this port's
    /// parser follows py's wherever py follows RFC 8941. Where py is more lenient than the RFC, the
    /// ports are strict (conductor ruling D-SJ55; fiki-py's fix is tick 6ixo), and each such input is
    /// named in <see cref="Leniencies"/> with the section that refuses it. The oracle file stays
    /// http_sfv's own verdict, written by oracle/sfv_oracle.py, so it says what py does today.
    /// </remarks>
    public class SfvTests
    {
        private static readonly JsonElement Oracle = Repo.Json("csharp", "test", "Bakobo.Fiki.Tests", "oracle", "sfv-oracle.json");

        private const string Number = "RFC 8941 section 4.2.4";
        private const string Integer16 = Number + " step 7.5: an integer of more than 15 digits fails, end of field or not";
        private const string TrailingPoint = Number + " step 9.1: a decimal ending in \".\" fails";
        private const string Base64 = "RFC 8941 section 4.2.7, by RFC 4648 section 3.3: \"=\" is padding only at the end of the content";
        private const string NoDate = "RFC 8941 section 4.2.3.1: no bare item begins with \"@\"; Dates are RFC 9651's, not RFC 8941's";
        private const string NoDisplay = "RFC 8941 section 4.2.3.1: no bare item begins with \"%\"; Display Strings are RFC 9651's, not RFC 8941's";

        /// <summary>The inputs http_sfv accepts and RFC 8941 refuses, which this port refuses, and why.</summary>
        internal static readonly Dictionary<string, string> Leniencies = new Dictionary<string, string>
        {
            { "a=0000000000000001", Integer16 },
            { "a=-0000000000000001", Integer16 },
            { "a=1;p=0000000000000001", Integer16 },
            { "a=@0000000000000001", Integer16 + "; and " + NoDate },
            { "a=1.", TrailingPoint },
            { "a=-1.", TrailingPoint },
            { "a=:QUJD=QQ==:", Base64 },
            { "a=:QQ=x=:", Base64 },
            { "a=:=QQ==:", Base64 },
            { "a=:QQ==QQ==:", Base64 },
            { "a=:==:", Base64 },
            { "a=:=:", Base64 },
            { "a=@0", NoDate },
            { "a=@1700000000", NoDate },
            { "a=@-1", NoDate },
            { "a=@253402300799", NoDate },
            { "a=@-62135510400", NoDate },
            { "\"x\";p=@5", NoDate },
            { "a=%\"x\"", NoDisplay },
            { "a=%\"\"", NoDisplay },
            { "a=%\"%c3%a9\"", NoDisplay },
            { "a=%\"%25\"", NoDisplay },
            { "a=%\"%22\"", NoDisplay },
            { "a=%\"%7f\"", NoDisplay },
            { "a=%\"%1f\"", NoDisplay },
            { "a=%\"% a\"", NoDisplay },
            { "a=%\"%a \"", NoDisplay },
            { "a=%\"%+a\"", NoDisplay },
            { "a=%\"%-0\"", NoDisplay },
            { "a=%\"%\ta\"", NoDisplay },
            { "a=%\"%a\u000b\"", NoDisplay },
            { "a=%\"\\\"", NoDisplay },
            { "\"x\";p=%\"d\"", NoDisplay },
            { "a=(1 2.5 tok ?0 :QQ==: @1 %\"d\")", NoDate + "; and " + NoDisplay },
        };

        /// <summary>
        /// The inputs http_sfv refuses and RFC 8941 accepts, which this port accepts: section 4.2.2
        /// parses a field of nothing but spaces as an empty dictionary, and so does the httpwg
        /// corpus's "empty dictionary" (this.i @7fexwu3s), where http_sfv raises.
        /// </summary>
        internal static readonly Dictionary<string, string> Strictnesses = new Dictionary<string, string>
        {
            { "", "RFC 8941 section 4.2.2: an empty field is an empty dictionary" },
            { " ", "RFC 8941 section 4.2.2: leading spaces are discarded, leaving an empty dictionary" },
        };

        public static IEnumerable<object?[]> Dictionaries() =>
            Oracle.GetProperty("dictionaries").EnumerateArray()
                .Select(c => new object?[] { c.GetProperty("input").GetString(), c.GetProperty("parsed").GetString() });

        public static IEnumerable<object?[]> Items() =>
            Oracle.GetProperty("items").EnumerateArray()
                .Select(c => new object?[] { c.GetProperty("input").GetString(), c.GetProperty("parsed").GetString() });

        /// <summary>http_sfv's str(Dictionary): a bare key for an item whose value is true.</summary>
        private static string Dump(SfDictionary parsed) =>
            string.Join(", ", parsed.Select(member =>
                member.Value is SfItem item && item.Value.Type == SfType.Boolean && item.Value.Boolean
                    ? member.Key + item.Params.Serialize()
                    : member.Key + "=" + member.Value.Serialize()));

        [Theory]
        [MemberData(nameof(Dictionaries))]
        public void ADictionaryParsesExactlyWhenHttpSfvParsesItUnlessRfc8941RefusesIt(string input, string? expected)
        {
            if (Strictnesses.ContainsKey(input))
            {
                Assert.Null(expected);
                Assert.Empty(Sfv.ParseDictionary(input));
            }
            else if (expected == null || Leniencies.ContainsKey(input))
            {
                Assert.Throws<FormatException>(() => Sfv.ParseDictionary(input));
            }
            else
            {
                Assert.Equal(expected, Dump(Sfv.ParseDictionary(input)));
            }
        }

        [Theory]
        [MemberData(nameof(Items))]
        public void AnItemParsesExactlyWhenHttpSfvParsesItUnlessRfc8941RefusesIt(string input, string? expected)
        {
            if (expected == null || Leniencies.ContainsKey(input))
            {
                Assert.Throws<FormatException>(() => Sfv.ParseItem(input));
            }
            else
            {
                Assert.Equal(expected, Sfv.ParseItem(input).Serialize());
            }
        }

        [Fact]
        public void EveryNamedLeniencyIsOneHttpSfvReallyAccepts()
        {
            // The list says what py does, so it must agree with the oracle py wrote: each input is in
            // the corpus, and http_sfv parsed it.
            var corpus = Dictionaries().Concat(Items()).ToList();
            Assert.All(Leniencies.Keys, input => Assert.Contains(corpus, c => (string)c[0]! == input && c[1] != null));
        }

        [Theory]
        [InlineData("-1.25", "-1.25")]
        [InlineData("-1.50", "-1.5")]
        [InlineData("-0.0", "0.0")]
        [InlineData("100.0", "100.0")]
        public void ADecimalSerializesAsHttpSfvSerializesIt(string input, string expected) =>
            Assert.Equal(expected, Sfv.ParseItem(input).Serialize());

        [Fact]
        public void ATrailingTabAfterAMemberIsNotALeniency()
        {
            // RFC 8941 section 4.2.2 steps 6 and 7 discard OWS, SP or HTAB, after a member and then
            // return the dictionary if nothing is left, so "a=1\t" parses under the RFC as under
            // http_sfv; only the whole field's leading and trailing SP are trimmed first (4.2).
            Assert.Equal("a=1", Dump(Sfv.ParseDictionary("a=1\t")));
            Assert.Throws<FormatException>(() => Sfv.ParseDictionary("\ta=1"));
        }

        [Fact]
        public void TheOracleCoversBothVerdicts()
        {
            var verdicts = Dictionaries().Select(c => c[1] == null).Distinct().ToList();
            Assert.Equal(2, verdicts.Count);
        }

        [Fact]
        public void ADictionaryKeepsItsMembersInOrderAndAnswersLookups()
        {
            var parsed = Sfv.ParseDictionary("b=1, a=(\"x\");p, b=2");
            Assert.Equal(new[] { "b", "a" }, parsed.Select(m => m.Key).ToArray());
            Assert.Equal(2, parsed.Count);
            Assert.True(parsed.TryGet("a", out var member));
            Assert.IsType<SfInnerList>(member);
            Assert.False(parsed.TryGet("c", out _));
            Assert.Equal("b", parsed.First().Key);
            var inner = (SfInnerList)member!;
            Assert.Single(inner.Items);
            Assert.True(inner.Params.Contains("p"));
        }

        [Fact]
        public void ParametersAnswerLookups()
        {
            var item = Sfv.ParseItem("\"x\";a=1;b");
            Assert.Equal(2, item.Params.Count);
            Assert.True(item.Params.TryGet("a", out var a));
            Assert.Equal(1, a!.Integer);
            Assert.False(item.Params.TryGet("c", out _));
            Assert.Equal(new[] { "a", "b" }, item.Params.Select(p => p.Key).ToArray());
        }

        [Fact]
        public void DictionariesAndParametersEnumerateAsPlainSequencesToo()
        {
            var parsed = Sfv.ParseDictionary("a=1;p");
            var members = ((System.Collections.IEnumerable)parsed).GetEnumerator();
            Assert.True(members.MoveNext());
            var parameters = ((System.Collections.IEnumerable)((SfItem)parsed.First().Value).Params).GetEnumerator();
            Assert.True(parameters.MoveNext());
        }

        // --- serialization of values fiki builds itself ---

        [Fact]
        public void AStringOutsideVisibleAsciiCannotBeSerialized()
        {
            Assert.Throws<ArgumentException>(() => SfValue.OfString("café").Serialize());
            Assert.Throws<ArgumentException>(() => SfValue.OfString("a\nb").Serialize());
            Assert.Equal("\"a\\\"b\\\\c\"", SfValue.OfString("a\"b\\c").Serialize());
        }

        [Fact]
        public void AnIntegerOutsideRfc8941RangeCannotBeSerialized()
        {
            Assert.Throws<ArgumentException>(() => SfValue.OfInteger(1000000000000000).Serialize());
            Assert.Throws<ArgumentException>(() => SfValue.OfInteger(-1000000000000000).Serialize());
            Assert.Equal("-999999999999999", SfValue.OfInteger(-999999999999999).Serialize());
        }

        // --- Python's value equality, which identity() relies on ---

        [Theory]
        [InlineData("?1", "1", true)]
        [InlineData("?1", "1.0", true)]
        [InlineData("?0", "0", true)]
        [InlineData("2", "2.0", true)]
        [InlineData("2", "2.5", false)]
        [InlineData("tok", "\"tok\"", true)]
        [InlineData("\"a\"", "\"b\"", false)]
        [InlineData(":QQ==:", ":QQ==:", true)]
        [InlineData(":QQ==:", ":QUI=:", false)]
        [InlineData(":QQ==:", "\"A\"", false)]
        [InlineData("\"5\"", "5", false)]
        [InlineData("1.50", "1.5", true)]
        [InlineData("-1.50", "-1.5", true)]
        [InlineData("-0.0", "0", true)]
        [InlineData("?0", "0.0", true)]
        [InlineData("10", "1.0", false)]
        public void ValuesCompareAsPythonComparesThem(string left, string right, bool equal)
        {
            var a = Sfv.ParseItem(left).Value;
            var b = Sfv.ParseItem(right).Value;
            Assert.Equal(equal, a.PyEquals(b));
            Assert.Equal(equal, b.PyEquals(a));
            // The set-friendly identity agrees with Python's == on every pair (bakobo/fiki#7).
            var x = Components.Identity(Sfv.ParseItem("\"c\";p=" + left));
            var y = Components.Identity(Sfv.ParseItem("\"c\";p=" + right));
            Assert.Equal(equal, x == y);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void AnEmptyFieldIsAnEmptyDictionaryAndAnEmptyList(string field)
        {
            Assert.Empty(Sfv.ParseDictionary(field));
            Assert.Empty(Sfv.ParseList(field));
            Assert.Empty(Messages.Parse(field, "Content-Digest", FikiErrorKind.MalformedDigest));
        }

        [Theory]
        [InlineData("Signature", FikiErrorKind.MalformedSignature)]
        [InlineData("Signature-Input", FikiErrorKind.MalformedSignatureInput)]
        public void AHeaderOfSpacesKeepsItsMalformedKindThoughItParsesAsEmpty(string name, FikiErrorKind kind)
        {
            // Parsing it empty must not move its refusal: before, the parser refused it as the
            // header's malformed kind, and so does fiki-py, whose http_sfv refuses it outright.
            var key = SignVerifyTests.TheKey;
            var url = "https://api.example.com/x";
            var headers = HttpSignatures.SignRequest(key, "POST", url, body: new byte[] { 1 }).ToDictionary(p => p.Key, p => p.Value);
            headers[name] = "   ";
            var caught = Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("POST", url, headers,
                Verifying.DecliningFreshness().WithBody(new byte[] { 1 })));
            Assert.Equal(kind, caught.Kind);
        }
    }
}
