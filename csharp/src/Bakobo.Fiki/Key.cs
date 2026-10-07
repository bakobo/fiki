using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Bakobo.Fiki
{
    /// <summary>
    /// An Ed25519 key pair whose public half is rendered as a non-transferable AID (this.i @07wstqk7).
    /// </summary>
    /// <remarks>
    /// The AID is the verifying key in CESR's <c>Ed25519N</c> encoding, a 44-character <c>B…</c>
    /// string. Non-transferable is the point: the key is recoverable from the identifier alone, so a
    /// verifier resolves nothing and fetches nothing.
    /// </remarks>
    public sealed class Key
    {
        private readonly Ed25519PrivateKeyParameters _privateKey;
        private readonly byte[] _seed;

        private Key(byte[] seed)
        {
            _seed = (byte[])seed.Clone();
            _privateKey = new Ed25519PrivateKeyParameters(_seed, 0);
            Aid = Aids.ToAid(_privateKey.GeneratePublicKey().GetEncoded());
        }

        /// <summary>Create a key from a fresh random seed.</summary>
        public static Key Generate()
        {
            var seed = new byte[Aids.RawLength];
            new SecureRandom().NextBytes(seed);
            return new Key(seed);
        }

        /// <summary>Recreate a key from its 32-byte Ed25519 seed.</summary>
        /// <exception cref="FikiException">MalformedKey, when the seed is not 32 bytes.</exception>
        public static Key FromSeed(byte[] seed)
        {
            if (seed.Length != Aids.RawLength)
            {
                throw new FikiException(
                    FikiErrorKind.MalformedKey,
                    $"An Ed25519 seed is {Aids.RawLength} bytes; this one is {seed.Length}.",
                    keyId: "");
            }
            return new Key(seed);
        }

        /// <summary>The non-transferable AID: 44 characters, <c>B</c> prefixed, and also the verifying key.</summary>
        public string Aid { get; }

        /// <summary>A copy of the 32-byte seed, for a caller that has to persist the key somewhere.</summary>
        public byte[] Seed => (byte[])_seed.Clone();

        /// <summary>
        /// Sign bytes, returning the raw 64-byte Ed25519 signature. Raw rather than CESR-qualified,
        /// because RFC 9421 carries a signature as an RFC 8941 byte sequence.
        /// </summary>
        public byte[] Sign(byte[] data)
        {
            var signer = new Ed25519Signer();
            signer.Init(true, _privateKey);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        /// <summary>Render a raw 32-byte Ed25519 public key as a non-transferable AID.</summary>
        /// <exception cref="ArgumentException">The key is not 32 bytes.</exception>
        public static string ToAid(byte[] raw)
        {
            if (raw.Length != Aids.RawLength)
            {
                throw new ArgumentException($"An Ed25519 public key is {Aids.RawLength} bytes; this one is {raw.Length}.", nameof(raw));
            }
            return Aids.ToAid(raw);
        }

        /// <summary>Recover the Ed25519 public key from a non-transferable AID.</summary>
        /// <exception cref="FikiException">
        /// MalformedKey, for anything that is not the canonical 44-character <c>B…</c> spelling of a key.
        /// </exception>
        public static PublicKey VerifyingKey(string aid) => new PublicKey(Aids.VerifyingKey(aid));
    }
}
