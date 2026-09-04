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
        return Arrays.copyOfRange(decoded, 1, decoded.length);
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
