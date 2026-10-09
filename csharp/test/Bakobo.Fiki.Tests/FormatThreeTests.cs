using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// What vectors format 3 changed (this.i @524c8qgv) that the shared vectors cannot reach: this
    /// port's own API for the stated policy, the signing side of a target that cannot be read, and
    /// .NET's own lowercasing (review B5).
    /// </summary>
    public class FormatThreeTests
    {
        private static readonly Key TheKey = SignVerifyTests.TheKey;

        private static Dictionary<string, string> Host(string host) => new Dictionary<string, string> { { "Host", host } };

        private static Dictionary<string, string> Signed(string url, Dictionary<string, string>? headers = null)
        {
            var all = new Dictionary<string, string>(headers ?? new Dictionary<string, string>());
            foreach (var header in HttpSignatures.SignRequest(TheKey, "GET", url, all))
            {
                all[header.Key] = header.Value;
            }
            return all;
        }

        private static FikiException Refused(string url, Dictionary<string, string> headers, VerifyOptions? options = null) =>
            Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("GET", url, headers, options ?? Verifying.DecliningFreshness()));

        [Fact]
        public void TheDefaultMinimumIsExportedAndIsTheSigningDefault()
        {
            Assert.Equal(new[] { "@method", "@authority", "@path", "@query" }, HttpSignatures.DefaultMinimum);
            Assert.Equal(HttpSignatures.DefaultCovered, HttpSignatures.DefaultMinimum);
        }

        [Fact]
        public void AnUnstatedMinimumIsTheDefaultAndWithoutMinimumOptsOut()
        {
            var url = "https://api.example.com/x";
            var thin = HttpSignatures.SignRequest(TheKey, "GET", url, covered: new[] { "@method", "@path", "@query" }).ToDictionary(p => p.Key, p => p.Value);
            var options = VerifyOptions.DecliningFreshness().DecliningAuthorityCheck();

            var caught = Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("GET", url, thin, options));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
            Assert.Equal("@authority", caught.Component);

            Assert.Equal(TheKey.Aid, HttpSignatures.VerifyRequest("GET", url, thin, options.WithoutMinimum()).Aid);
            // The later statement wins, either way round.
            Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("GET", url, thin,
                options.WithoutMinimum().WithMinimum(HttpSignatures.DefaultMinimum)));
            Assert.Equal(TheKey.Aid, HttpSignatures.VerifyRequest("GET", url, thin,
                options.WithMinimum(HttpSignatures.DefaultMinimum).WithoutMinimum()).Aid);
        }

        [Fact]
        public void AResponseIsStillHeldToNoMinimumUnlessOneIsStated()
        {
            // The default minimum is a request's (@524c8qgv); a response states its own or has none.
            var headers = HttpSignatures.SignResponse(TheKey, 200, covered: new[] { "@status" });
            Assert.Equal(new[] { "@status" }, HttpSignatures.VerifyResponse(200, headers, VerifyOptions.DecliningFreshness()).Covered);
            Assert.Equal(new[] { "@status" },
                HttpSignatures.VerifyResponse(200, headers, VerifyOptions.DecliningFreshness().DecliningAuthorityCheck()).Covered);
        }

        [Fact]
        public void TheAuthoritiesDecisionIsRequiredAndChecked()
        {
            var url = "https://api.example.com/x";
            var headers = Signed(url);
            var unstated = Assert.Throws<ArgumentException>(() =>
                HttpSignatures.VerifyRequest("GET", url, headers, VerifyOptions.DecliningFreshness()));
            Assert.Contains("DecliningAuthorityCheck", unstated.Message, StringComparison.Ordinal);

            Assert.Throws<ArgumentNullException>(() => VerifyOptions.DecliningFreshness().WithAuthorities((IEnumerable<string>)null!));
            Assert.Throws<ArgumentException>(() => VerifyOptions.DecliningFreshness().WithAuthorities(new string[0]));
            Assert.Throws<ArgumentException>(() => VerifyOptions.DecliningFreshness().WithAuthorities(new[] { "api.example.com", null! }));

            var served = VerifyOptions.DecliningFreshness().WithAuthorities(new[] { "api.example.com" });
            Assert.Equal(TheKey.Aid, HttpSignatures.VerifyRequest("GET", url, headers, served).Aid);
            // Compared exactly: no case folding and no default port is added or removed.
            Assert.Equal(FikiErrorKind.SignatureMismatch, Refused(url, headers,
                VerifyOptions.DecliningFreshness().WithAuthorities(new[] { "API.example.com", "api.example.com:443" })).Kind);
        }

        [Fact]
        public void ASingleStringIsACompileErrorAndAnArgumentExceptionWhenReachedAnyway()
        {
            var single = typeof(VerifyOptions).GetMethod(nameof(VerifyOptions.WithAuthorities), new[] { typeof(string) })!;
            var obsolete = (ObsoleteAttribute)Attribute.GetCustomAttribute(single, typeof(ObsoleteAttribute))!;
            Assert.True(obsolete.IsError);
            var caught = Assert.Throws<System.Reflection.TargetInvocationException>(() =>
                single.Invoke(VerifyOptions.DecliningFreshness(), new object[] { "api.example.com" }));
            Assert.IsType<ArgumentException>(caught.InnerException);
        }

        [Fact]
        public void ADoubleSlashTargetIsOriginFormAndItsAuthorityIsTheHost()
        {
            var url = "//evil.example/p";
            Assert.Equal("\"@path\": //evil.example/p\n\"@authority\": api.example.com\n", string.Concat(Bytes.Text(
                HttpSignatures.SignatureBase("GET", url, Host("api.example.com"), new[] { "@path", "@authority" }, 1, "k"))
                .Split('\n').Take(2).Select(l => l + "\n")));
            Assert.Equal(TheKey.Aid, HttpSignatures.VerifyRequest("GET", url, Signed(url, Host("api.example.com")),
                VerifyOptions.DecliningFreshness().WithAuthorities(new[] { "api.example.com" })).Aid);
        }

        [Theory]
        [InlineData("http:/x")]
        [InlineData("https:///x")]
        [InlineData("/x#frag")]
        [InlineData("https://api.example.com/x#frag")]
        [InlineData("/a b")]
        [InlineData("/x\t")]
        [InlineData("/x\u007f")]
        [InlineData("x")]
        public void ATargetThatCannotBeReadIsTheSignersMistake(string url) =>
            Assert.Throws<ArgumentException>(() => Signed(url, Host("api.example.com")));

        [Theory]
        [InlineData("[::1")]
        [InlineData("a]b")]
        [InlineData("a[b")]
        [InlineData("example.com:1000000")]
        [InlineData("example.com:0000080x")]
        public void AHostThatIsNoAuthorityIsAMismatchAndTheSignersMistake(string host)
        {
            Assert.Throws<ArgumentException>(() => Signed("/x", Host(host)));
            var headers = Signed("/x", Host("example.com"));
            headers["Host"] = host;
            Assert.Equal(FikiErrorKind.SignatureMismatch, Refused("/x", headers).Kind);
        }

        [Fact]
        public void AHostKeepsItsPortAndALeadingZeroPortIsANumber()
        {
            Assert.Contains("\"@authority\": example.com:80\n", Bytes.Text(HttpSignatures.SignatureBase("GET", "/x", Host("example.com:00080"),
                new[] { "@authority" }, 1, "k")), StringComparison.Ordinal);
            Assert.Contains("\"@authority\": example.com:443\n", Bytes.Text(HttpSignatures.SignatureBase("GET", "/x", Host("EXAMPLE.com:443"),
                new[] { "@authority" }, 1, "k")), StringComparison.Ordinal);
        }

        [Fact]
        public void AnEmptyHostIsAnEmptyAuthority()
        {
            // The behaviour fiki-py has and this port keeps (brief: report, do not change).
            Assert.Contains("\"@authority\": \n", Bytes.Text(HttpSignatures.SignatureBase("GET", "/x", Host(""),
                new[] { "@authority" }, 1, "k")), StringComparison.Ordinal);
        }

        [Fact]
        public void AKelvinSignIsNeverLoweredIntoAServedHost()
        {
            // .NET lowercases U+212A to "k" (review B5); the host is checked for ASCII first.
            var kelvin = "Key.example";
            Assert.Equal("key.example", kelvin.ToLowerInvariant());

            Assert.Throws<ArgumentException>(() => Signed("https://" + kelvin + "/x"));
            var headers = Signed("https://key.example/x");
            var served = VerifyOptions.DecliningFreshness().WithAuthorities(new[] { "key.example" });
            Assert.Equal(FikiErrorKind.SignatureMismatch, Refused("https://" + kelvin + "/x", headers, served).Kind);

            // A Host header is a covered value like any other, refused as raw bytes on either side.
            Assert.Equal(FikiErrorKind.SignatureMismatch, Assert.Throws<FikiException>(() => Signed("/x", Host(kelvin))).Kind);
            var origin = Signed("/x", Host("key.example"));
            origin["Host"] = kelvin;
            Assert.Equal(FikiErrorKind.SignatureMismatch, Refused("/x", origin, served).Kind);
        }
    }
}
