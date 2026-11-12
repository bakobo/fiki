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
import java.util.Map;
import java.util.Set;

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

    byte[] publicRaw() {
        return publicRaw.clone();
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

    /**
     * Render a raw 32-byte Ed25519 public key as a non-transferable AID. Any other length is the
     * caller's mistake, refused rather than truncated or padded into some other key's AID (review B8).
     */
    public static String toAid(byte[] raw) {
        if (raw == null || raw.length != RAW_LEN) {
            throw new IllegalArgumentException(
                "An Ed25519 public key is " + RAW_LEN + " bytes; this one is "
                    + (raw == null ? "null" : raw.length + " bytes") + ".");
        }
        byte[] padded = new byte[RAW_LEN + 1];
        System.arraycopy(raw, 0, padded, 1, RAW_LEN);
        return CODE + URL.encodeToString(padded).substring(1);
    }

    /**
     * The canonical AID of the Ed25519 public key {@code text} spells (this.i @0mvgkwnl).
     *
     * <p>{@code text} is an AID, the raw key as 43 characters of unpadded base64url (a JWK's "x"),
     * a base58btc did:key, a did:peer with numalgo 0, or an OpenSSH public line: "ssh-ed25519", one
     * space, the blob, and optionally one space and a printable-ASCII comment that neither begins
     * nor ends with a space. Length, not the first character, tells raw from AID: 43 against 44.
     * Nothing around {@code text} is stripped; that is the caller's, so that one input never has
     * two readings. Call it when registrations are loaded rather than per request.
     *
     * <p>Anything else is a {@code MalformedKey} refusal, including a transferable or digest AID,
     * whose key is not the identifier's to give, and a key that is a small-order or non-canonical
     * point. The message never quotes {@code text} and the detail is empty, because what is handed
     * here by mistake can be a private key: the {@code .key} file instead of the {@code .pub}, or a
     * seed, which in base64url is 43 characters like a raw key. A null is the caller's mistake, an
     * {@link IllegalArgumentException}.
     */
    public static String aidFrom(String text) {
        return Formats.aidFrom(text);
    }

    /**
     * Load an unencrypted openssh-key-v1 Ed25519 private key, as ssh-keygen writes it (this.i
     * {@literal @}0mvgkwnl): the armored text with LF line endings, with or without the final newline.
     *
     * <p>The key must be the only one in the file, its check integers must agree, its padding must
     * be 1, 2, 3, ..., and its public key must match in both places it is stored and must be the
     * one its seed derives. Anything else, an encrypted key included, is a {@code MalformedKey}
     * refusal whose message carries no part of the key and whose detail is empty. A null is the
     * caller's mistake, an {@link IllegalArgumentException}.
     *
     * <p>Use a key dedicated to fiki and never loaded into ssh-agent. Signatures do not cross
     * between protocols -- every base signRequest and signResponse build begins with a double
     * quote, SSH user authentication signs data beginning with a length-prefixed session
     * identifier (RFC 4252 section 7), and SSHSIG signs data beginning "SSHSIG" -- but an agent
     * signs whatever bytes it is asked to, so anyone able to use a forwarded agent could sign fiki
     * requests with a login key. The separation is a property of signRequest, not of the key:
     * {@link #sign} signs any bytes.
     */
    public static Key fromOpenssh(String text) {
        return OpenSsh.read(text);
    }

    /** Recover the Ed25519 public key from a non-transferable AID. */
    public static PublicKey verifyingKey(String aid) {
        return decodePublic(verifyingKeyBytes(aid));
    }

    /**
     * Recover the raw 32 bytes from a non-transferable AID, refusing as MalformedKey anything that
     * is not one and any key a verifier must never trust (a small-order or non-canonical point).
     */
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
        // A well-spelled AID whose key no verifier may trust, such as the identity point, is not an
        // AID of any key (@2kc2c4h5, @7w7nv94j's small-order case).
        return trusted(raw, aid);
    }

    // keripy's PreDex, the prefix derivation codes an AID may carry, with the raw size each encodes
    // (this.i @37rktct3). fiki reads none of them but B; it needs the table only to say whether a
    // keyid is a well-formed AID, which the KERI profile's R1 makes the verifier's job before any
    // key store is asked.
    private static final Map<String, Integer> PREFIX_CODES = Map.ofEntries(
        Map.entry("B", 32), Map.entry("D", 32), Map.entry("E", 32), Map.entry("F", 32),
        Map.entry("G", 32), Map.entry("H", 32), Map.entry("I", 32),
        Map.entry("0D", 64), Map.entry("0E", 64), Map.entry("0F", 64), Map.entry("0G", 64),
        Map.entry("1AAA", 33), Map.entry("1AAB", 33), Map.entry("1AAI", 33), Map.entry("1AAJ", 33),
        Map.entry("1AAC", 57), Map.entry("1AAD", 57),
        Map.entry("1AAE", 114));

    /**
     * The non-transferable codes other than B: secp256k1, Ed448 and secp256r1 keys, whose
     * algorithm the profile does not support.
     */
    static final Set<String> OTHER_NON_TRANSFERABLE = Set.of("1AAA", "1AAC", "1AAI");

    /**
     * The PreDex code of {@code keyid} when it is a well-formed AID, else null (this.i @7w7nv94j,
     * {@literal @}37rktct3).
     *
     * <p>The code is one, two or four characters by its first character, as CESR sizes it; the raw
     * bytes behind it are padded with zero bytes to a multiple of three, base64url-encoded, and the
     * code written over the characters the padding became. Well formed means exactly that spelling:
     * the right length, base64url throughout, and zero pad bits, so that re-encoding gives back the
     * keyid. fiki checks this before any resolver sees a keyid, so a resolver only ever answers
     * about key state.
     */
    static String aidCode(String keyid) {
        if (keyid.isEmpty()) {
            return null;
        }
        char first = keyid.charAt(0);
        int size = (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ? 1 : first == '0' ? 2 : 4;
        if (keyid.length() < size) {
            return null;
        }
        String code = keyid.substring(0, size);
        Integer length = PREFIX_CODES.get(code);
        if (length == null) {
            return null;
        }
        int pad = (3 - length % 3) % 3;
        if (keyid.length() != (pad + length) * 4 / 3 + (size - pad)
                || !keyid.substring(size).matches("[A-Za-z0-9_-]*")) {
            return null;
        }
        byte[] decoded = URL_DECODER.decode("A".repeat(pad) + keyid.substring(size));
        byte[] padded = new byte[decoded.length];
        System.arraycopy(decoded, pad, padded, pad, decoded.length - pad);
        return (code + URL.encodeToString(padded).substring(pad)).equals(keyid) ? code : null;
    }

    /** True when {@code keyid} is a well-formed AID under the KERI vectors' keys_rule. */
    static boolean wellFormedAid(String keyid) {
        return aidCode(keyid) != null;
    }

    /**
     * The key a well-formed B keyid carries, read as an AID's key: canonical, not small-order, and
     * in the prime-order subgroup (this.i @37rktct3).
     */
    static byte[] aidKey(String keyid) {
        byte[] decoded = URL_DECODER.decode("A" + keyid.substring(1));
        return trusted(Arrays.copyOfRange(decoded, 1, decoded.length), keyid, true);
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
        return point(raw) != null;
    }

    /**
     * The affine point {x, y} that {@code raw} canonically encodes, or null. The sign bit picks x
     * only for the canonical-encoding check; nothing here depends on which of the two roots x is.
     */
    private static BigInteger[] point(byte[] raw) {
        byte[] bigEndian = new byte[RAW_LEN];
        for (int i = 0; i < RAW_LEN; i++) {
            bigEndian[i] = raw[RAW_LEN - 1 - i];
        }
        boolean sign = (bigEndian[0] & 0x80) != 0;
        bigEndian[0] &= 0x7f;
        BigInteger y = new BigInteger(1, bigEndian);
        if (y.compareTo(P) >= 0) {
            return null;
        }
        BigInteger ySquared = y.multiply(y).mod(P);
        BigInteger u = ySquared.subtract(BigInteger.ONE).mod(P);
        BigInteger v = D.multiply(ySquared).add(BigInteger.ONE).mod(P);
        BigInteger xSquared = u.multiply(v.modInverse(P)).mod(P);
        if (xSquared.signum() == 0) {
            return sign ? null : new BigInteger[] {BigInteger.ZERO, y};
        }
        BigInteger x = xSquared.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (!x.multiply(x).mod(P).equals(xSquared)) {
            x = x.multiply(SQRT_M1).mod(P);
        }
        return x.multiply(x).mod(P).equals(xSquared) ? new BigInteger[] {x, y} : null;
    }

    // The order of Ed25519's prime-order subgroup, RFC 8032 section 5.1's L.
    private static final BigInteger L =
        BigInteger.TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));

    /** RFC 8032 section 5.1.4's addition, on points in extended coordinates (X, Y, Z, T). */
    private static BigInteger[] add(BigInteger[] a, BigInteger[] b) {
        BigInteger e1 = a[1].subtract(a[0]).multiply(b[1].subtract(b[0])).mod(P);
        BigInteger h1 = a[1].add(a[0]).multiply(b[1].add(b[0])).mod(P);
        BigInteger c = a[3].multiply(BigInteger.TWO).multiply(D).multiply(b[3]).mod(P);
        BigInteger d = a[2].multiply(BigInteger.TWO).multiply(b[2]).mod(P);
        BigInteger e = h1.subtract(e1);
        BigInteger f = d.subtract(c);
        BigInteger g = d.add(c);
        BigInteger h = h1.add(e1);
        return new BigInteger[] {e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P)};
    }

    /**
     * True when [L]P is the identity, so P lies in the prime-order subgroup (this.i @37rktct3).
     *
     * <p>A point of small order is not caught here, since the identity is one; {@link #smallOrder}
     * runs first. What this adds is the mixed-order point, a subgroup point plus a torsion
     * component, which libsodium's crypto_core_ed25519_is_valid_point refuses and keripy follows.
     * Called only with a canonical point.
     */
    static boolean primeOrder(byte[] raw) {
        BigInteger[] affine = point(raw);
        BigInteger[] total = {BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
        BigInteger[] step = {affine[0], affine[1], BigInteger.ONE, affine[0].multiply(affine[1]).mod(P)};
        for (int i = 0; i < L.bitLength(); i++) {
            if (L.testBit(i)) {
                total = add(total, step);
            }
            step = add(step, step);
        }
        return total[0].signum() == 0 && total[1].equals(total[2]);
    }

    /**
     * Refuse a key no verifier should trust: a small-order point, under which one signature
     * verifies over any message (@2kc2c4h5, tick 27eo), or anything that is not a canonical
     * on-curve point (@3kdzr0zn). Called wherever a key is about to be trusted, never by the AID
     * lens itself.
     */
    static byte[] trusted(byte[] raw, String keyid) {
        return trusted(raw, keyid, false);
    }

    /**
     * {@link #trusted(byte[], String)}, and with {@code subgroup}, which is how a key named by an
     * AID is read (KERI profile R1, this.i @37rktct3), a point outside the prime-order subgroup is
     * refused too; fiki's own raw keyid accepts one (@5r75ff4m).
     */
    static byte[] trusted(byte[] raw, String keyid, boolean subgroup) {
        // An empty keyid names no one, for a caller that must not echo what it was given (@0mvgkwnl).
        String subject = keyid.isEmpty() ? "The key given" : "The key for " + keyid;
        if (smallOrder(raw)) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                subject + " is a small-order point, under which a signature can verify "
                    + "over any message, so it is not a key at all.",
                keyid);
        }
        if (!canonicalPoint(raw)) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                subject + " is not the canonical encoding of a point on the Ed25519 curve.",
                keyid);
        }
        if (subgroup && !primeOrder(raw)) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                subject + " is a point of mixed order, outside the prime-order subgroup every honest "
                    + "key lies in, so no signature is checked against it.",
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
