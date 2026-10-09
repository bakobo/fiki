using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// Conductor ruling this.i @56qu7gyw: a field value is checked as received, and only SP and HTAB
    /// are trimmed from it. fiki-py's str.strip also removes CR, LF and Unicode whitespace, so a
    /// covered "admin" followed by CR LF verifies there as "admin"; the ports do not copy that.
    /// </summary>
    public class RawValueTests
    {
        private static readonly Key Signer = Key.FromSeed(Bytes.Range(0, 32));
        private const string Url = "https://api.example.com/things?limit=1";
        private static readonly string[] Covered = { "@method", "@path", "@query", "x-role" };

        private static KeyValuePair<string, string> H(string name, string value) => new KeyValuePair<string, string>(name, value);

        private static Verdict Verify(string role)
        {
            var signed = HttpSignatures.SignRequest(Signer, "GET", Url, new[] { H("X-Role", "admin") }, covered: Covered);
            return HttpSignatures.VerifyRequest("GET", Url, new[] { H("X-Role", role) }.Concat(signed), Verifying.DecliningFreshness());
        }

        [Theory]
        [InlineData("admin\r\n")]
        [InlineData("admin\n")]
        [InlineData("admin\r")]
        [InlineData("\r\nadmin")]
        [InlineData("admin\0")]
        [InlineData("admin\u00a0")]
        [InlineData("\u3000admin")]
        [InlineData("admin\v")]
        [InlineData("admin\u001f")]
        public void ACoveredValueWithAnyOtherByteAroundItIsASignatureMismatch(string role) =>
            Assert.Equal(FikiErrorKind.SignatureMismatch, Assert.Throws<FikiException>(() => Verify(role)).Kind);

        [Theory]
        [InlineData("admin")]
        [InlineData("  admin")]
        [InlineData("admin\t")]
        [InlineData(" \t admin \t ")]
        public void SpacesAndTabsAroundACoveredValueAreTrimmed(string role) =>
            Assert.Equal(Signer.Aid, Verify(role).Aid);

        [Fact]
        public void ASignerBuildsNoBaseFromAValueCarryingALineBreak()
        {
            Assert.Equal(FikiErrorKind.SignatureMismatch, Assert.Throws<FikiException>(() =>
                HttpSignatures.SignatureBase("GET", Url, new[] { H("X-Role", "admin\r\n") }, new[] { "x-role" }, 1, "k")).Kind);
            Assert.Equal("\"x-role\": admin", Bytes.Text(HttpSignatures.SignatureBase("GET", Url,
                new[] { H("X-Role", "\tadmin ") }, new[] { "x-role" }, 1, "k")).Split('\n')[0]);
        }

        [Fact]
        public void AHostHeaderCarryingALineBreakBuildsNoAuthority() =>
            Assert.Equal(FikiErrorKind.SignatureMismatch, Assert.Throws<FikiException>(() =>
                HttpSignatures.SignatureBase("GET", "/x", new[] { H("Host", "example.com\r\n") }, new[] { "@authority" }, 1, "k")).Kind);

        [Fact]
        public void AContentLengthIsTrimmedOfSpacesAndTabsOnly()
        {
            // A length that is not a plain decimal once SP and HTAB are gone counts as a body (fail
            // closed), so "0" with a CR beside it obliges a covered digest, and " 0\t" does not.
            var zero = HttpSignatures.SignRequest(Signer, "POST", Url);
            var options = Verifying.DecliningFreshness().WithMinimum(HttpSignatures.RequestMinimum);
            Assert.Equal(Signer.Aid, HttpSignatures.VerifyRequest("POST", Url, new[] { H("Content-Length", " 0\t") }.Concat(zero), options).Aid);
            var caught = Assert.Throws<FikiException>(() =>
                HttpSignatures.VerifyRequest("POST", Url, new[] { H("Content-Length", "0\r\n") }.Concat(zero), options));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
            Assert.Equal("content-digest", caught.Component);
        }

        // --- an empty method is a caller who lost it (this.i @56qu7gyw) ---

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AnEmptyMethodIsACallerErrorWhenMethodIsBuilt(string? method)
        {
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignatureBase(method!, Url, new KeyValuePair<string, string>[0], new[] { "@method" }, 1, "k"));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignRequest(Signer, method!, Url));
            var signed = HttpSignatures.SignRequest(Signer, "GET", Url);
            Assert.Throws<ArgumentException>(() => HttpSignatures.VerifyRequest(method!, Url, signed, Verifying.DecliningFreshness()));
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignResponse(Signer, 200, new Request(method!, Url)));
        }

        [Fact]
        public void AnEmptyMethodIsACallerErrorEvenWhenMethodIsNotCovered() =>
            // A method is a token wherever a request message is built, covered or not (@5zrf8gjk).
            Assert.Throws<ArgumentException>(() => HttpSignatures.SignatureBase("", Url,
                new KeyValuePair<string, string>[0], new[] { "@path" }, 1, "k"));
    }
}
