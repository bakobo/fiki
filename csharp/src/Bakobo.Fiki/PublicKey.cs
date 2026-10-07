using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Bakobo.Fiki
{
    /// <summary>A 32-byte Ed25519 public key.</summary>
    public sealed class PublicKey
    {
        private readonly byte[] _raw;

        internal PublicKey(byte[] raw)
        {
            _raw = (byte[])raw.Clone();
        }

        /// <summary>A copy of the raw 32 bytes.</summary>
        public byte[] ToBytes() => (byte[])_raw.Clone();

        /// <summary>The key's non-transferable AID.</summary>
        public string Aid => Aids.ToAid(_raw);

        /// <summary>
        /// True when <paramref name="signature"/> is this key's Ed25519 signature over
        /// <paramref name="data"/>; false for anything else, a malformed signature or key included.
        /// </summary>
        public bool Verify(byte[] signature, byte[] data) =>
            signature.Length == Ed25519.SignatureSize
            && Ed25519.Verify(signature, 0, _raw, 0, data, 0, data.Length);
    }
}
