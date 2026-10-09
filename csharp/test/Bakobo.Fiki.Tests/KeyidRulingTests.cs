using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// A cross-port ruling from the hostile review of bakobo/fiki#8: the KERI profile makes keyid
    /// REQUIRED, and a minimum is how a caller applies the profile, so under a minimum a signature
    /// with no keyid is refused even when an expected AID names the key.
    /// </summary>
    public class KeyidRulingTests
    {
        private static readonly Key Signer = Key.FromSeed(Bytes.Range(0, 32));
        private const string Url = "https://api.example.com/things?limit=1";
        private static readonly byte[] Body = Bytes.Utf8("{\"hello\": \"world\"}");

        [Fact]
        public void AMinimumRequiresAKeyidEvenWhenTheKeyIsNamed()
        {
            var signed = HttpSignatures.SignRequest(Signer, "POST", Url, body: Body, created: 1700000000)
                .ToDictionary(h => h.Key, h => h.Value);
            var keyId = signed["Signature-Input"].Split(new[] { ";keyid=\"" }, StringSplitOptions.None)[1].Split('"')[0];
            signed["Signature-Input"] = signed["Signature-Input"].Replace($";keyid=\"{keyId}\"", "");
            var options = Verifying.DecliningFreshness().WithBody(Body).WithExpectedAid(Signer.Aid);

            // Without a minimum RFC 9421 lets the key be named instead: the keyid-less base was not
            // what was signed, so this reaches the signature and fails there.
            Assert.Equal(FikiErrorKind.SignatureMismatch,
                Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("POST", Url, signed, options)).Kind);
            // Under the profile it is MissingKey, py's kind for an absent keyid, and it comes before
            // the missing created, the covered list and the labels.
            var caught = Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("POST", Url, signed,
                options.WithMinimum(HttpSignatures.RequestMinimum)));
            Assert.Equal(FikiErrorKind.MissingKey, caught.Kind);
            signed["Signature-Input"] = signed["Signature-Input"].Replace(";created=1700000000", "").Replace("\"@path\"", "\"@path\" \"@path\"");
            Assert.Equal(FikiErrorKind.MissingKey, Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("POST", Url, signed,
                options.WithMinimum(HttpSignatures.RequestMinimum))).Kind);
        }

        [Fact]
        public void AResponseUnderAMinimumRequiresAKeyidToo()
        {
            var signed = HttpSignatures.SignResponse(Signer, 204, created: 1700000000, keyId: "k").ToDictionary(h => h.Key, h => h.Value);
            signed["Signature-Input"] = signed["Signature-Input"].Replace(";keyid=\"k\"", "");
            var request = new Request("GET", Url);
            Assert.Equal(FikiErrorKind.MissingKey, Assert.Throws<FikiException>(() => HttpSignatures.VerifyResponse(204, signed,
                Verifying.DecliningFreshness().WithExpectedAid(Signer.Aid).WithMinimum(new[] { "@status" }.Concat(HttpSignatures.ResponseMinimum.Skip(1))).WithRequest(request))).Kind);
        }
    }
}
