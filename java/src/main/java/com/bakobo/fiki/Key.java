package com.bakobo.fiki;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;

/**
 * An Ed25519 key pair whose public half is rendered as a non-transferable AID (this.i @07wstqk7).
 *
 * <p>The AID is the verifying key in CESR's {@code Ed25519N} encoding — a 44-character {@code B…}
 * string. The encoding is base64url over the raw 32 bytes with one leading pad byte, the first
 * character then replaced by the code: a few lines of arithmetic rather than a dependency.
 *
 * <p><b>How a seed becomes a key pair, and why it is done this way.</b> Java has had Ed25519 since
 * JDK 15, but the JCA offers no way to derive a public key from a private one:
 * {@code EdECPrivateKey} exposes the seed bytes and the parameter spec and nothing else, and no
 * {@code KeyFactory} spec yields the public half. The alternatives were a cryptography dependency
 * — which would have put this port in the same column as Rust — or hand-written curve arithmetic,
 * which is not a thing to write. What works instead is seeding the provider's key-pair generator:
 * SunEC's Ed25519 generator draws exactly 32 bytes and uses them as the seed, so a
 * {@link SecureRandom} that hands back the caller's seed produces the caller's key pair.
 *
 * <p>That is provider behaviour rather than a specified contract, so {@link #fromSeed} does not
 * trust it: it reads the seed back out of the generated private key and refuses if the generator
 * used something else. A JDK that changes this fails loudly at the call rather than quietly
 * producing the wrong AID, and the shared {@code aid-lens} vector is the standing tripwire.
 */
public final class Key {

    // CESR's Ed25519N. fiki decodes this code and no other: a decoder that handles one
    // fixed-length code can only ever be narrower than a full CESR implementation, which is the
    // safe direction for a differential.
    static final char CODE = 'B';
    static final int RAW_LEN = 32;
    static final int QB64_LEN = 44;

    // An X.509 SubjectPublicKeyInfo for Ed25519 is a fixed DER prefix followed by the 32 bytes, so
    // wrapping a raw key is a concatenation rather than an ASN.1 encoder.
    private static final byte[] X509_PREFIX = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();
    static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
    static final Base64.Encoder STD = Base64.getEncoder();
    static final Base64.Decoder STD_DECODER = Base64.getDecoder();

    private final PrivateKey privateKey;
    private final byte[] publicRaw;
    private final byte[] seed;

    private Key(PrivateKey privateKey, byte[] publicRaw, byte[] seed) {
        this.privateKey = privateKey;
        this.publicRaw = publicRaw;
        this.seed = seed;
    }

    /** Create a key from fresh randomness. */
    public static Key generate() {
        byte[] seed = new byte[RAW_LEN];
        new SecureRandom().nextBytes(seed);
        return fromSeed(seed);
    }

    /** Recreate a key from its 32-byte Ed25519 seed. */
    public static Key fromSeed(byte[] seed) {
        if (seed == null || seed.length != RAW_LEN) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                "An Ed25519 seed is 32 bytes; this one is " + (seed == null ? 0 : seed.length) + ".");
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            generator.initialize(NamedParameterSpec.ED25519, new SeedSource(seed));
            KeyPair pair = generator.generateKeyPair();

            byte[] encodedPrivate = pair.getPrivate().getEncoded();
            byte[] used = Arrays.copyOfRange(encodedPrivate, encodedPrivate.length - RAW_LEN, encodedPrivate.length);
            if (!Arrays.equals(seed, used)) {
                // The provider did not take our bytes as the seed. Fail here rather than return a
                // key pair for some other identity.
                throw new IllegalStateException(
                    "this JDK's Ed25519 generator does not seed from SecureRandom as fiki expects");
            }

            byte[] encodedPublic = pair.getPublic().getEncoded();
            byte[] raw = Arrays.copyOfRange(encodedPublic, encodedPublic.length - RAW_LEN, encodedPublic.length);
            return new Key(pair.getPrivate(), raw, seed.clone());
        } catch (java.security.GeneralSecurityException e) {
            // Ed25519 has been in the JDK since 15 and the build requires 17.
            throw new IllegalStateException("this JDK has no Ed25519", e);
        }
    }

    /** Hands the generator exactly the seed it asks for, once. */
    private static final class SeedSource extends SecureRandom {
        private final byte[] seed;

        SeedSource(byte[] seed) {
            this.seed = seed;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            if (bytes.length != seed.length) {
                throw new IllegalStateException(
                    "the Ed25519 generator asked for " + bytes.length + " bytes, not " + seed.length);
            }
            System.arraycopy(seed, 0, bytes, 0, seed.length);
        }
    }

    /** The non-transferable AID: 44 characters, {@code B} prefixed, and also the verifying key. */
    public String aid() {
        return toAid(publicRaw);
    }

    /** The raw verifying key, base64url and unpadded — the RFC 8037 JWK "x" form (@7xrx5evg). */
    public String keyid() {
        return URL.encodeToString(publicRaw);
    }

    /** The 32-byte seed, for a caller that has to persist the key somewhere. */
    public byte[] seed() {
        return seed.clone();
    }

    /** Sign bytes, returning the raw 64-byte Ed25519 signature. */
    public byte[] sign(byte[] data) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(data);
            return signer.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    /** Render a raw 32-byte Ed25519 public key as a non-transferable AID. */
    public static String toAid(byte[] raw) {
        byte[] padded = new byte[RAW_LEN + 1];
        System.arraycopy(raw, 0, padded, 1, RAW_LEN);
        return CODE + URL.encodeToString(padded).substring(1);
    }

    /** Recover the Ed25519 public key from a non-transferable AID. */
    public static PublicKey verifyingKey(String aid) {
        return decodePublic(verifyingKeyBytes(aid));
    }

    /** Recover the raw 32 bytes from a non-transferable AID. */
    public static byte[] verifyingKeyBytes(String aid) {
        if (aid == null || aid.length() != QB64_LEN || aid.charAt(0) != CODE) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                "A non-transferable AID is 44 characters beginning with \"B\"; this one is not.", aid);
        }
        // Strict rather than lenient: "=" is inside base64's alphabet, so a lenient decoder would
        // accept a padded AID that decodes short, and a decoder is exactly the place a quiet
        // shortfall turns into somebody else's exception.
        if (!aid.matches("^[A-Za-z0-9\\-_]{44}$")) {
            throw new FikiException(
                FikiException.Kind.MalformedKey, "The AID " + aid + " is not valid base64url.", aid);
        }
        byte[] decoded = URL_DECODER.decode("A" + aid.substring(1));
        byte[] raw = Arrays.copyOfRange(decoded, 1, decoded.length);
        // The second character's top two bits land in the pad byte the code replaced, so a
        // non-zero pad would give one key two spellings. Only the one toAid produces is the AID
        // (bakobo/fiki#4).
        if (!toAid(raw).equals(aid)) {
            throw new FikiException(
                FikiException.Kind.MalformedKey, "The AID " + aid + " is not the canonical spelling of its key.", aid);
        }
        return raw;
    }

    // The one-character codes whose 44-character qb64 carries 32 raw bytes behind one pad byte:
    // Ed25519N (B), Ed25519 transferable (D), and Blake3-256 (E, the usual AID digest).
    private static final String SPELLED_CODES = "BDE";

    /**
     * True when {@code keyid} is shaped like a B, D or E AID and is not its canonical spelling:
     * 44 characters under one of those codes whose other 43 are not base64url, or which decode
     * with a non-zero pad byte and so name the same 32 bytes as another spelling. fiki checks this
     * before any resolver sees the keyid, so a resolver never has to (bakobo/fiki#4).
     */
    static boolean misspelledAid(String keyid) {
        if (keyid.length() != QB64_LEN || SPELLED_CODES.indexOf(keyid.charAt(0)) < 0) {
            return false;
        }
        if (!keyid.matches("^[A-Za-z0-9\\-_]{44}$")) {
            return true;
        }
        byte[] decoded = URL_DECODER.decode("A" + keyid.substring(1));
        byte[] padded = new byte[RAW_LEN + 1];
        System.arraycopy(decoded, 1, padded, 1, RAW_LEN);
        return !(keyid.charAt(0) + URL.encodeToString(padded).substring(1)).equals(keyid);
    }

    /* ------------------------------------------- keys a verifier must never trust (@2kc2c4h5) */

    // The y-coordinates of Ed25519's eight small-order points, little-endian, plus the two
    // non-canonical spellings p and p + 1 -- libsodium's has_small_order table. Compared with
    // the sign bit of the last byte cleared, which covers both signs of each: fourteen
    // encodings. Derived for @2kc2c4h5 from curve arithmetic, not copied.
    private static final byte[][] SMALL_ORDER = {
        hex("0000000000000000000000000000000000000000000000000000000000000000"),
        hex("0100000000000000000000000000000000000000000000000000000000000000"),
        hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    };

    private static byte[] hex(String text) {
        return java.util.HexFormat.of().parseHex(text);
    }

    /** True when {@code raw} encodes one of the eight small-order points, under either sign. */
    static boolean smallOrder(byte[] raw) {
        byte[] cleared = raw.clone();
        cleared[RAW_LEN - 1] &= 0x7f;
        for (byte[] blocked : SMALL_ORDER) {
            if (Arrays.equals(cleared, blocked)) {
                return true;
            }
        }
        return false;
    }

    private static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger D = BigInteger.valueOf(-121665)
        .multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
    private static final BigInteger SQRT_M1 = BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);

    /**
     * True when {@code raw} is the canonical encoding of a point on the curve: RFC 8032 section
     * 5.1.3's decoding, refusing a y of p or more, a y with no x, and x = 0 with the sign bit set
     * (@3kdzr0zn).
     */
    static boolean canonicalPoint(byte[] raw) {
        byte[] bigEndian = new byte[RAW_LEN];
        for (int i = 0; i < RAW_LEN; i++) {
            bigEndian[i] = raw[RAW_LEN - 1 - i];
        }
        boolean sign = (bigEndian[0] & 0x80) != 0;
        bigEndian[0] &= 0x7f;
        BigInteger y = new BigInteger(1, bigEndian);
        if (y.compareTo(P) >= 0) {
            return false;
        }
        BigInteger ySquared = y.multiply(y).mod(P);
        BigInteger u = ySquared.subtract(BigInteger.ONE).mod(P);
        BigInteger v = D.multiply(ySquared).add(BigInteger.ONE).mod(P);
        BigInteger xSquared = u.multiply(v.modInverse(P)).mod(P);
        if (xSquared.signum() == 0) {
            return !sign;
        }
        BigInteger x = xSquared.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (!x.multiply(x).mod(P).equals(xSquared)) {
            x = x.multiply(SQRT_M1).mod(P);
        }
        return x.multiply(x).mod(P).equals(xSquared);
    }

    /**
     * Refuse a key no verifier should trust: a small-order point, under which one signature
     * verifies over any message (@2kc2c4h5, tick 27eo), or anything that is not a canonical
     * on-curve point (@3kdzr0zn). Called wherever a key is about to be trusted, never by the AID
     * lens itself.
     */
    static byte[] trusted(byte[] raw, String keyid) {
        if (smallOrder(raw)) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                "The key for " + keyid + " is a small-order point, under which a signature can verify "
                    + "over any message, so it is not a key at all.",
                keyid);
        }
        if (!canonicalPoint(raw)) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                "The key for " + keyid + " is not the canonical encoding of a point on the Ed25519 curve.",
                keyid);
        }
        return raw;
    }

    static PublicKey decodePublic(byte[] raw) {
        try {
            return KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(concat(X509_PREFIX, raw)));
        } catch (java.security.GeneralSecurityException e) {
            throw new FikiException(
                FikiException.Kind.MalformedKey, "That is not an Ed25519 public key.");
        }
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
