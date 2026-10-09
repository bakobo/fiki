using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// <see cref="PyText.Shown"/> escapes exactly what Python's <c>repr()</c> escapes, which is every
    /// character for which <c>str.isprintable()</c> is false (tick 7us4, from #18): the Unicode
    /// categories Cc, Cf, Cs, Co, Cn, Zl and Zp, and every Zs but the space. The spelling stays this
    /// port's own, double quotes and \x, \u or \U by the code point's width, since matching repr's
    /// choice of quote is out of scope. One test per class; each expected answer is Python 3.14's
    /// isprintable on the same character.
    /// </summary>
    public class ShownTests
    {
        private static string Escaped(string text) => "\"" + text + "\"";

        [Theory]
        [InlineData("\u0000", "\\x00")]
        [InlineData("\u001f", "\\x1f")]
        [InlineData("\u007f", "\\x7f")]
        public void AnAsciiControlIsEscaped(string c, string spelled) => Assert.Equal(Escaped(spelled), PyText.Shown(c));

        [Theory]
        [InlineData("\u0080", "\\x80")]
        [InlineData("\u0085", "\\x85")]
        [InlineData("\u009f", "\\x9f")]
        public void AC1ControlIsEscaped(string c, string spelled) => Assert.Equal(Escaped(spelled), PyText.Shown(c));

        [Theory]
        [InlineData("\u2028", "\\u2028")]
        public void TheLineSeparatorIsEscaped(string c, string spelled) => Assert.Equal(Escaped(spelled), PyText.Shown(c));

        [Theory]
        [InlineData("\u2029", "\\u2029")]
        public void TheParagraphSeparatorIsEscaped(string c, string spelled) => Assert.Equal(Escaped(spelled), PyText.Shown(c));

        [Theory]
        [InlineData("\u00a0", "\\xa0")]
        [InlineData("\u1680", "\\u1680")]
        [InlineData("\u3000", "\\u3000")]
        public void ASpaceSeparatorOtherThanTheSpaceIsEscaped(string c, string spelled) => Assert.Equal(Escaped(spelled), PyText.Shown(c));

        [Theory]
        [InlineData("\u00ad", "\\xad")]
        [InlineData("\u200b", "\\u200b")]
        [InlineData("\u200e", "\\u200e")]
        [InlineData("\ufeff", "\\ufeff")]
        [InlineData("\U000E0001", "\\U000e0001")]
        public void AFormatCharacterIsEscaped(string c, string spelled) => Assert.Equal(Escaped(spelled), PyText.Shown(c));

        [Theory]
        [InlineData("\ue000", "\\ue000")]
        [InlineData("\U000F0000", "\\U000f0000")]
        public void APrivateUseCharacterIsEscaped(string c, string spelled) => Assert.Equal(Escaped(spelled), PyText.Shown(c));

        [Theory]
        [InlineData("\u0378", "\\u0378")]
        [InlineData("\ufffe", "\\ufffe")]
        [InlineData("\U0010FFFF", "\\U0010ffff")]
        public void AnUnassignedCodePointIsEscaped(string c, string spelled) => Assert.Equal(Escaped(spelled), PyText.Shown(c));

        [Fact]
        public void ALoneSurrogateIsEscaped()
        {
            Assert.Equal(Escaped("\\ud800"), PyText.Shown("\ud800"));
            Assert.Equal(Escaped("\\udc00"), PyText.Shown("\udc00"));
            // Reversed, a pair is two lone surrogates.
            Assert.Equal(Escaped("a\\udc00\\ud800b"), PyText.Shown("a\udc00\ud800b"));
        }

        [Theory]
        [InlineData(" ")]
        [InlineData("~")]
        [InlineData("\u00a1")]
        [InlineData("\u00e9")]
        [InlineData("\u4e2d")]
        [InlineData("\U0001F600")]
        public void APrintableCharacterIsLeftAsItIs(string c) => Assert.Equal(Escaped(c), PyText.Shown(c));

        [Fact]
        public void QuotesAndBackslashesKeepThisPortsSpelling() =>
            Assert.Equal("\"a\\\"b\\\\c\"", PyText.Shown("a\"b\\c"));
    }
}
