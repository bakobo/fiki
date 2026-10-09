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
        public void AResponseIsHeldToTheResponseMinimumUnlessItOptsOut()
        {
            // Part two of format 3 (this.i @524c8qgv): a response's unstated minimum is
            // ResponseMinimum, as a request's is DefaultMinimum, and WithoutMinimum opts out. Before
            // it, a response was held to none; this test's subject is that default, so its
            // expectation changed.
            var headers = HttpSignatures.SignResponse(TheKey, 200, covered: new[] { "@status" });
            var options = VerifyOptions.DecliningFreshness().DecliningKeyidCheck();
            var caught = Assert.Throws<FikiException>(() => HttpSignatures.VerifyResponse(200, headers, options));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
            Assert.Equal(new[] { "@status" }, HttpSignatures.VerifyResponse(200, headers, options.WithoutMinimum()).Covered);
            Assert.Equal(new[] { "@status" },
                HttpSignatures.VerifyResponse(200, headers, options.WithoutMinimum().DecliningAuthorityCheck()).Covered);
        }

        [Fact]
        public void AResponseNeedsADecisionAboutItsSigner()
        {
            var request = new Request("GET", "https://api.example.com/x");
            var headers = HttpSignatures.SignResponse(TheKey, 200, request, created: 1_700_000_000);
            var unstated = Assert.Throws<ArgumentException>(() =>
                HttpSignatures.VerifyResponse(200, headers, VerifyOptions.DecliningFreshness().WithRequest(request)));
            Assert.Contains("DecliningKeyidCheck", unstated.Message, StringComparison.Ordinal);
            // Checked before anything about the message, an unsigned 401 included.
            Assert.Throws<ArgumentException>(() =>
                HttpSignatures.VerifyResponse(401, new Dictionary<string, string>(), VerifyOptions.DecliningFreshness()));

            Assert.Throws<ArgumentNullException>(() => VerifyOptions.DecliningFreshness().WithExpectedKeyId(null!));
            Assert.Throws<ArgumentException>(() => VerifyOptions.DecliningFreshness().WithExpectedKeyId(""));

            var declined = VerifyOptions.DecliningFreshness().WithRequest(request).DecliningKeyidCheck();
            var keyId = HttpSignatures.VerifyResponse(200, headers, declined).KeyId!;
            Assert.Equal(TheKey.Aid, HttpSignatures.VerifyResponse(200, headers, declined.WithExpectedKeyId(keyId)).Aid);
            // The later statement wins: a decline after an expected keyid drops it.
            var other = Key.FromSeed(new byte[32]).Aid;
            Assert.Equal(FikiErrorKind.UnknownKey, Assert.Throws<FikiException>(() =>
                HttpSignatures.VerifyResponse(200, headers, declined.WithExpectedKeyId(other))).Kind);
            Assert.Equal(TheKey.Aid, HttpSignatures.VerifyResponse(200, headers, declined.WithExpectedKeyId(other).DecliningKeyidCheck()).Aid);
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
            // Whether ToLowerInvariant does so depends on the runtime's Unicode tables: .NET does,
            // .NET Framework 4.8.1 does not (#17 CI). The refusal below holds either way.
            var kelvin = "Key.example";

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

        // --- format 3 part two (this.i @524c8qgv) ---

        [Theory]
        [InlineData("https://user@api.example.com/x")]
        [InlineData("https://@api.example.com/x")]
        [InlineData("https://user:pw@api.example.com/x")]
        public void UserinfoIsABaseThatCannotBeBuilt(string url)
        {
            Assert.Throws<ArgumentException>(() => Signed(url));
            Assert.Equal(FikiErrorKind.SignatureMismatch, Refused(url, Signed("https://api.example.com/x")).Kind);
        }

        [Fact]
        public void AnErrorQuotesAtMost64CharactersOfAnUntrustedUrlAndEscapesControls()
        {
            // Review A9, B9: a 5 MB URL made a 10 MB error message, and js echoed controls raw.
            var headers = Signed("https://api.example.com/x");
            var url = "https://api.example.com/" + new string('p', 9000);
            var caught = Refused(url, headers);
            Assert.True(caught.Message.Length < 400, caught.Message);
            Assert.Contains("cut from 9024 characters", caught.Message, StringComparison.Ordinal);
            var mistake = Assert.Throws<ArgumentException>(() => Signed(url));
            Assert.Contains("cut from 9024 characters", mistake.Message, StringComparison.Ordinal);

            caught = Refused("https://api.example.com/a\u001bb", headers);
            Assert.DoesNotContain("\u001b", caught.Message, StringComparison.Ordinal);
            Assert.Contains("\\x1b", caught.Message, StringComparison.Ordinal);

            var port = Refused("https://api.example.com:" + new string('9', 100) + "/x", headers);
            Assert.Contains("cut from 100 characters", port.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void ShownEscapesAndCutsWithoutSplittingACharacter()
        {
            Assert.Equal("\"a\\\"b\\\\c\\x7f\"", PyText.Shown("a\"b\\c\u007f"));
            // A pair straddling the cut is left out whole rather than halved.
            var straddling = new string('a', 63) + "\U0001F600" + "tail";
            Assert.Equal("\"" + new string('a', 63) + "\" (cut from 69 characters)", PyText.Shown(straddling));
            Assert.Equal("\"" + new string('a', 64) + "\" (cut from 65 characters)", PyText.Shown(new string('a', 65)));
        }

        [Fact]
        public void FieldNamesFoldAsciiOnly()
        {
            // Never ToLowerInvariant, which folds U+212A to "k" on .NET 10 and not on .NET Framework.
            Assert.Equal("x-note", PyText.AsciiLower("X-Note"));
            Assert.Equal("\u212Aey", PyText.AsciiLower("\u212Aey"));
            Assert.Equal("\u00C9", PyText.AsciiLower("\u00C9"));
            // Two names that differ only by a Kelvin sign are two fields, never one twice.
            var signed = HttpSignatures.SignRequest(TheKey, "GET", "https://api.example.com/x",
                new Dictionary<string, string> { { "Key-Id", "real" }, { "\u212Aey-Id", "decoy" } }, covered: new[] { "@method", "Key-Id" });
            Assert.Contains("\"key-id\"", signed["Signature-Input"], StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(0, true)]
        [InlineData(-1, false)]
        public void CreatedAndExpiresAreNotNegativeAndZeroIsATime(long value, bool accepted)
        {
            var url = "https://api.example.com/x";
            var signed = HttpSignatures.SignRequest(TheKey, "GET", url, created: 1_700_000_000);
            foreach (var name in new[] { "created", "expires" })
            {
                var headers = signed.ToDictionary(p => p.Key, p => p.Value);
                headers["Signature-Input"] = headers["Signature-Input"].Replace(";created=1700000000",
                    name == "created" ? ";created=" + value : ";created=1700000000;expires=" + value);
                var options = VerifyOptions.DecliningFreshness().WithoutMinimum().DecliningAuthorityCheck().WithNow(0);
                var kind = Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("GET", url, headers, options)).Kind;
                // Zero passes the parameter check and reaches the signature, which it no longer
                // matches; a negative value is refused before the signature is examined.
                Assert.Equal(accepted ? FikiErrorKind.SignatureMismatch : FikiErrorKind.MalformedSignatureInput, kind);
            }
        }

        [Fact]
        public void AFieldValueIsBoundedAsReceivedAndContentDigestKeepsItsOwnBound()
        {
            var url = "https://api.example.com/x";
            var exact = new string('v', HttpSignatures.MaxFieldBytes);
            var note = new Dictionary<string, string> { { "X-Note", exact } };
            var signed = HttpSignatures.SignRequest(TheKey, "GET", url, note, covered: new[] { "@method", "x-note" });
            foreach (var header in signed)
            {
                note[header.Key] = header.Value;
            }
            // Exactly the bound is accepted; one byte over, even of trailing whitespace, is not.
            Assert.Equal(TheKey.Aid, HttpSignatures.VerifyRequest("GET", url, note, Verifying.DecliningFreshness()).Aid);
            note["X-Note"] = exact + " ";
            Assert.Equal(FikiErrorKind.SignatureMismatch, Refused(url, note).Kind);
            Assert.Equal(FikiErrorKind.SignatureMismatch, Assert.Throws<FikiException>(() =>
                HttpSignatures.SignRequest(TheKey, "GET", url, new Dictionary<string, string> { { "X-Note", exact + "v" } },
                    covered: new[] { "@method", "x-note" })).Kind);

            // A Content-Digest over the bound is MalformedDigest, from its own parse.
            var body = Bytes.Utf8("{}");
            var digest = HttpSignatures.ContentDigest(body) + ", " + new string('x', HttpSignatures.MaxFieldBytes);
            var bodySigned = HttpSignatures.SignRequest(TheKey, "POST", url, new Dictionary<string, string> { { "Content-Digest", digest } },
                covered: new[] { "@method", "content-digest" });
            var all = bodySigned.ToDictionary(p => p.Key, p => p.Value);
            all["Content-Digest"] = digest;
            Assert.Equal(FikiErrorKind.MalformedDigest, Assert.Throws<FikiException>(() =>
                HttpSignatures.VerifyRequest("POST", url, all, Verifying.DecliningFreshness().WithBody(body))).Kind);
        }
    }
}
