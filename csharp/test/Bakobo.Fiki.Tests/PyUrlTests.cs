using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The urlsplit port agrees with Python's, URL for URL. fiki-py derives @authority, @path and
    /// @query from urllib.parse.urlsplit, and System.Uri normalizes paths and percent-encoding, so it
    /// would build a different base from the same URL.
    /// </summary>
    public class PyUrlTests
    {
        private static readonly JsonElement Oracle = Repo.Json("csharp", "test", "Bakobo.Fiki.Tests", "oracle", "url-oracle.json");

        public static IEnumerable<object[]> Cases() =>
            Oracle.GetProperty("cases").EnumerateArray().Select(c => new object[] { c.GetProperty("input").GetString()! });

        private static JsonElement Expected(string input) =>
            Oracle.GetProperty("cases").EnumerateArray().First(c => c.GetProperty("input").GetString() == input);

        [Theory]
        [MemberData(nameof(Cases))]
        public void ASplitAgreesWithPython(string input)
        {
            var expected = Expected(input);
            if (expected.GetProperty("error").GetBoolean())
            {
                Assert.Throws<ArgumentException>(() => PyUrl.Split(input));
                return;
            }
            var parts = PyUrl.Split(input);
            Assert.Equal(expected.GetProperty("scheme").GetString(), parts.Scheme);
            Assert.Equal(expected.GetProperty("netloc").GetString(), parts.Netloc);
            Assert.Equal(expected.GetProperty("path").GetString(), parts.Path);
            Assert.Equal(expected.GetProperty("query").GetString(), parts.Query);
            Assert.Equal(expected.GetProperty("hostname").ValueKind == JsonValueKind.Null ? null : expected.GetProperty("hostname").GetString(), parts.Hostname);
            var port = expected.GetProperty("port");
            if (port.ValueKind == JsonValueKind.String)
            {
                Assert.Throws<ArgumentException>(() => parts.Port);
            }
            else
            {
                Assert.Equal(port.ValueKind == JsonValueKind.Null ? null : port.GetInt32(), parts.Port);
            }
        }

        [Fact]
        public void TheOracleCoversErrorsAndPorts()
        {
            var cases = Oracle.GetProperty("cases").EnumerateArray().ToList();
            Assert.Contains(cases, c => c.GetProperty("error").GetBoolean());
            Assert.Contains(cases, c => !c.GetProperty("error").GetBoolean() && c.GetProperty("port").ValueKind == JsonValueKind.String);
        }

        [Theory]
        [InlineData("Content-Digest", "content-digest")]
        [InlineData("\u0130x", "i\u0307x")]
        [InlineData("\u00c9", "\u00e9")]
        public void LowerFollowsPythonsFullCaseMapping(string input, string expected) =>
            Assert.Equal(expected, PyText.Lower(input));
    }
}
