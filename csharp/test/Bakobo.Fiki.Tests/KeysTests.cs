using System;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>Keys and the AID lens (this.i @07wstqk7), mirroring py/tests/test_keys.py.</summary>
    public class KeysTests
    {
        // heti derives this same AID from this same seed through keripy's Signer, which is what
        // keeps the two libraries' key types interchangeable over one seed.
        private static readonly byte[] Seed = Bytes.Range(0, 32);
        private const string AidOfSeed = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";

        private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        /// <summary>
        /// The same 32 key bytes, spelled with a non-zero bit in the pad byte the code replaces.
        /// The second character's top two bits land in that pad byte, so the alias decodes to the
        /// same key under a lenient decoder.
        /// </summary>
        internal static string PaddingBitAlias(string aid)
        {
            var value = Alphabet.IndexOf(aid[1]);
            return aid.Substring(0, 1) + Alphabet[value ^ 0b010000] + aid.Substring(2);
        }

        [Fact]
        public void FromSeedRendersTheExpectedAid() => Assert.Equal(AidOfSeed, Key.FromSeed(Seed).Aid);

        [Fact]
        public void AnAidIs44CharactersAndBPrefixed()
        {
            var aid = Key.Generate().Aid;
            Assert.Equal(44, aid.Length);
            Assert.StartsWith("B", aid, StringComparison.Ordinal);
        }

        [Fact]
        public void GenerateProducesADistinctKeyEachTime() => Assert.NotEqual(Key.Generate().Aid, Key.Generate().Aid);

        [Fact]
        public void TheSeedRoundTripsSoACallerCanPersistIt()
        {
            var key = Key.Generate();
            Assert.Equal(32, key.Seed.Length);
            Assert.Equal(key.Aid, Key.FromSeed(key.Seed).Aid);
        }

        [Fact]
        public void TheSeedIsACopyACallerCannotUseToChangeTheKey()
        {
            var seed = Bytes.Range(0, 32);
            var key = Key.FromSeed(seed);
            seed[0] ^= 0xff;
            key.Seed[1] ^= 0xff;
            Assert.Equal(AidOfSeed, key.Aid);
            Assert.Equal(Bytes.Range(0, 32), key.Seed);
        }

        [Fact]
        public void FromSeedRefusesASeedOfTheWrongLength()
        {
            var caught = Assert.Throws<FikiException>(() => Key.FromSeed(new byte[31]));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
            Assert.Equal("", caught.KeyId);
            Assert.Equal("An Ed25519 seed is 32 bytes; this one is 31.", caught.Message);
        }

        [Fact]
        public void VerifyingKeyRecoversTheKeyThatSigned()
        {
            var key = Key.FromSeed(Seed);
            var data = Bytes.Utf8("whatever");
            var signature = key.Sign(data);
            var publicKey = Key.VerifyingKey(key.Aid);
            Assert.True(publicKey.Verify(signature, data));
            Assert.False(publicKey.Verify(signature, Bytes.Utf8("whatever else")));
            Assert.Equal(key.Aid, publicKey.Aid);
            Assert.Equal(key.Aid, Key.ToAid(publicKey.ToBytes()));
        }

        [Fact]
        public void APublicKeyRefusesASignatureOfTheWrongLengthRatherThanThrowing()
        {
            var publicKey = Key.VerifyingKey(Key.FromSeed(Seed).Aid);
            Assert.False(publicKey.Verify(new byte[63], Bytes.Utf8("whatever")));
        }

        [Theory]
        [InlineData("B" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // too short
        [InlineData("B" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // too long
        [InlineData("D" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // transferable prefix
        [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // no code
        [InlineData("")] // empty
        public void VerifyingKeyRefusesAnythingThatIsNotANonTransferableAid(string aid)
        {
            var caught = Assert.Throws<FikiException>(() => Key.VerifyingKey(aid));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
        }

        [Theory]
        [InlineData("B!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")] // no valid characters
        [InlineData("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!!!!")] // short after discarding invalid
        [InlineData("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")] // padded to 31 bytes
        [InlineData("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")] // padded to 32 bytes
        [InlineData("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+")] // standard alphabet, not url-safe
        [InlineData("BAAAAAAAAAAAAAAAAAAAA=AAAAAAAAAAAAAAAAAAAAAA")] // padding in the middle
        [InlineData("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA===")] // excess padding
        public void VerifyingKeyRefusesAWellShapedAidThatIsNotBase64Url(string aid)
        {
            Assert.Equal(44, aid.Length);
            var caught = Assert.Throws<FikiException>(() => Key.VerifyingKey(aid));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
        }

        [Fact]
        public void ANonAsciiAidIsACallerErrorAsInFikiPy()
        {
            // py's base64 raises ValueError on a non-ASCII str before binascii sees it, and
            // verifying_key catches only binascii.Error, so the ValueError escapes. C# mirrors it
            // with ArgumentException rather than inventing a different refusal.
            Assert.Throws<ArgumentException>(() => Key.VerifyingKey("B" + new string('é', 43)));
        }

        [Fact]
        public void ARefusalCarriesTheOffendingValueAsAProperty()
        {
            // heti reads these fields to fill its own message templates (heti @4n9m4xfz).
            var aid = "D" + new string('A', 43);
            var caught = Assert.Throws<FikiException>(() => Key.VerifyingKey(aid));
            Assert.Equal(aid, caught.KeyId);
        }

        [Fact]
        public void VerifyingKeyRefusesAPaddingBitAliasOfARealAid()
        {
            // bakobo/fiki#4: an AID has exactly one spelling, or two identifiers name one key.
            var aid = Key.FromSeed(Seed).Aid;
            var alias = PaddingBitAlias(aid);
            Assert.NotEqual(aid, alias);
            var caught = Assert.Throws<FikiException>(() => Key.VerifyingKey(alias));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
        }

        [Fact]
        public void ToAidRefusesAKeyOfTheWrongLength()
        {
            Assert.Throws<ArgumentException>(() => Key.ToAid(new byte[31]));
        }

        [Fact]
        public void MisspelledAidNamesOnlyAidShapedKeyidsThatAreNotCanonical()
        {
            var aid = Key.FromSeed(Seed).Aid;
            Assert.False(Aids.Misspelled(aid));
            Assert.True(Aids.Misspelled(PaddingBitAlias(aid)));
            Assert.True(Aids.Misspelled("E" + new string('!', 43)));
            Assert.True(Aids.Misspelled("D" + aid.Substring(1, 42) + "+"));
            Assert.False(Aids.Misspelled("not-an-aid"));
            Assert.False(Aids.Misspelled("A" + aid.Substring(1)));
            Assert.False(Aids.Misspelled(""));
        }
    }
}
