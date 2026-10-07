using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The hand-rolled RFC 8941 parser agrees with http_sfv, fiki-py's parser, input for input.
    /// </summary>
    /// <remarks>
    /// Which header parses decides between a Malformed* refusal and a later one, so this port's
    /// parser has to agree with py's on every input, quirks included. The oracle file is
    /// http_sfv's own verdict on a corpus, written by oracle/sfv_oracle.py.
    /// </remarks>
    public class SfvTests
    {
        private static readonly JsonElement Oracle = Repo.Json("csharp", "test", "Bakobo.Fiki.Tests", "oracle", "sfv-oracle.json");

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
        public void ADictionaryParsesExactlyWhenHttpSfvParsesIt(string input, string? expected)
        {
            if (expected == null)
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
        public void AnItemParsesExactlyWhenHttpSfvParsesIt(string input, string? expected)
        {
            if (expected == null)
            {
                Assert.Throws<FormatException>(() => Sfv.ParseItem(input));
            }
            else
            {
                Assert.Equal(expected, Sfv.ParseItem(input).Serialize());
            }
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

        [Fact]
        public void ADisplayStringEscapesAsHttpSfvDoes()
        {
            // Lowercase hex without zero padding, and 0x1F and 0x7F left literal: http_sfv's own
            // serializer, quirks included.
            var parsed = Sfv.ParseItem("%\"%05%7f%1f%e2%82%ac%25\"");
            Assert.Equal("%\"%5\u007f\u001f%e2%82%ac%25\"", parsed.Serialize());
        }

        // --- Python's value equality, which identity() relies on ---

        [Theory]
        [InlineData("?1", "1", true)]
        [InlineData("?1", "1.0", true)]
        [InlineData("?0", "0", true)]
        [InlineData("2", "2.0", true)]
        [InlineData("2", "2.5", false)]
        [InlineData("tok", "\"tok\"", true)]
        [InlineData("%\"tok\"", "tok", true)]
        [InlineData("\"a\"", "\"b\"", false)]
        [InlineData(":QQ==:", ":QQ==:", true)]
        [InlineData(":QQ==:", ":QUI=:", false)]
        [InlineData(":QQ==:", "\"A\"", false)]
        [InlineData("@5", "@5", true)]
        [InlineData("@5", "@6", false)]
        [InlineData("@5", "5", false)]
        [InlineData("5", "@5", false)]
        [InlineData("\"5\"", "5", false)]
        public void ValuesCompareAsPythonComparesThem(string left, string right, bool equal)
        {
            var a = Sfv.ParseItem(left).Value;
            var b = Sfv.ParseItem(right).Value;
            Assert.Equal(equal, a.PyEquals(b));
            Assert.Equal(equal, b.PyEquals(a));
        }
    }
}
