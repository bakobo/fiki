package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * What KERI profile version 1.2 asks of the Java port beyond 1.1, ported from fiki-py's
 * test_profile_v1_2.py (this.i @37rktct3, @84nt4je0).
 *
 * <p>Under a resolver, where the keyid is an AID, a B keyid's key is the prefix's and must lie in
 * the prime-order subgroup, and an AID is any of keripy's PreDex prefix codes. Request content no
 * header announced is refused at the body stage, after the signature and freshness checks, so a
 * message with two defects gets one code whichever kind of verifier reads it.
 *
 * <p>The mixed-order oracle here works in affine coordinates, not the extended ones fiki uses, so
 * a wrong check and a wrong oracle cannot agree by sharing a method.
 */
class ProfileV12Test {

    private static final Key KEY = Key.fromSeed(seed());
    private static final String URL = "https://keria.example.com/identifiers?type=rot";
    private static final byte[] BODY = "{\"hello\": \"world\"}".getBytes(StandardCharsets.UTF_8);
    private static final long AT = 1_700_000_000L;

    private static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger D =
        BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
    private static final BigInteger L =
        BigInteger.TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger[] IDENTITY = {BigInteger.ZERO, BigInteger.ONE};

    // An order-8 point's encoding (libsodium's has_small_order table); orderEightIsOrderEight checks it.
    private static final byte[] ORDER_EIGHT =
        HexFormat.of().parseHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");

    private static final byte[] MIXED = encode(add(decode(raw(KEY)), decode(ORDER_EIGHT)));
    private static final String B_MIXED = cesr("B", MIXED);
    private static final String B_WEAK = cesr("B", identityBytes());
    private static final String E_AID = cesr("E", sha256("a transferable AID"));

    private static byte[] seed() {
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) {
            seed[i] = (byte) i;
        }
        return seed;
    }

    private static byte[] identityBytes() {
        byte[] out = new byte[32];
        out[0] = 1;
        return out;
    }

    private static byte[] sha256(String text) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sha512(String text) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] raw(Key key) {
        return Key.verifyingKeyBytes(key.aid());
    }

    /**
     * CESR's arithmetic: zero bytes in front to a multiple of three, base64url, and the code in
     * place of the characters those bytes became.
     */
    static String cesr(String code, byte[] data) {
        int pad = (3 - data.length % 3) % 3;
        byte[] padded = new byte[pad + data.length];
        System.arraycopy(data, 0, padded, pad, data.length);
        return code + Base64.getUrlEncoder().withoutPadding().encodeToString(padded).substring(pad);
    }

    /* ------------------------------------------- a mixed-order key, built in affine coordinates */

    private static BigInteger[] add(BigInteger[] a, BigInteger[] b) {
        BigInteger t = D.multiply(a[0]).multiply(b[0]).multiply(a[1]).multiply(b[1]).mod(P);
        BigInteger x = a[0].multiply(b[1]).add(a[1].multiply(b[0]))
            .multiply(BigInteger.ONE.add(t).modInverse(P)).mod(P);
        BigInteger y = a[1].multiply(b[1]).add(a[0].multiply(b[0]))
            .multiply(BigInteger.ONE.subtract(t).mod(P).modInverse(P)).mod(P);
        return new BigInteger[] {x, y};
    }

    private static BigInteger xSquared(BigInteger y) {
        BigInteger yy = y.multiply(y).mod(P);
        return yy.subtract(BigInteger.ONE).multiply(D.multiply(yy).add(BigInteger.ONE).modInverse(P)).mod(P);
    }

    private static BigInteger[] decode(byte[] encoded) {
        byte[] bigEndian = new byte[32];
        for (int i = 0; i < 32; i++) {
            bigEndian[i] = encoded[31 - i];
        }
        BigInteger value = new BigInteger(1, bigEndian);
        boolean sign = value.testBit(255);
        BigInteger y = value.clearBit(255);
        BigInteger xx = xSquared(y);
        // Euler's criterion picks between the two candidate roots for p = 5 mod 8.
        BigInteger x = xx.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P);
        if (!x.multiply(x).mod(P).equals(xx)) {
            x = x.multiply(BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P)).mod(P);
        }
        assertEquals(xx, x.multiply(x).mod(P), "not on the curve");
        if (x.testBit(0) != sign) {
            x = P.subtract(x).mod(P);
        }
        return new BigInteger[] {x, y};
    }

    private static byte[] encode(BigInteger[] point) {
        BigInteger value = point[0].testBit(0) ? point[1].setBit(255) : point[1];
        byte[] bigEndian = value.toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < Math.min(32, bigEndian.length); i++) {
            out[i] = bigEndian[bigEndian.length - 1 - i];
        }
        return out;
    }

    private static boolean isIdentity(BigInteger[] point) {
        return point[0].signum() == 0 && point[1].equals(BigInteger.ONE);
    }

    private static BigInteger[] times(BigInteger n, BigInteger[] point) {
        BigInteger[] acc = IDENTITY;
        BigInteger[] step = point;
        for (int i = 0; i < n.bitLength(); i++) {
            if (n.testBit(i)) {
                acc = add(acc, step);
            }
            step = add(step, step);
        }
        return acc;
    }

    @Test
    void orderEightIsOrderEight() {
        BigInteger[] point = decode(ORDER_EIGHT);
        BigInteger[] acc = point;
        int n = 1;
        while (!isIdentity(acc)) {
            acc = add(acc, point);
            n++;
        }
        assertEquals(8, n);
    }

    @Test
    void theOracleKeyIsOnTheCurveAndNotInThePrimeOrderSubgroup() {
        BigInteger[] point = decode(MIXED);
        assertEquals(xSquared(point[1]), point[0].multiply(point[0]).mod(P));
        assertFalse(isIdentity(times(L, point)));
        assertTrue(isIdentity(times(L, decode(raw(KEY)))));
        assertFalse(Key.smallOrder(MIXED));
        assertTrue(Key.canonicalPoint(MIXED));
    }

    /* ------------------------------------------------------------------------------- helpers */

    private record Signed(String method, String url, byte[] body, Map<String, String> headers) {}

    private static Signed sign(String keyid, Map<String, String> given, byte[] body) {
        Map<String, String> headers = new LinkedHashMap<>(given);
        headers.putAll(Fiki.signRequest(KEY, "POST", URL, given,
            Fiki.SignOptions.none().withBody(body).withCreated(AT).withKeyid(keyid)));
        return new Signed("POST", URL, body, headers);
    }

    private static Signed sign(String keyid) {
        return sign(keyid, Map.of(), BODY);
    }

    private static Fiki.VerifyOptions opts(long now) {
        return Fiki.VerifyOptions.maxAge(300).withNow(now).withoutMinimum().withoutAuthorityCheck()
            .withoutKeyidCheck();
    }

    private static Fiki.Verdict verify(Signed s, byte[] body, Fiki.VerifyOptions opts) {
        return Fiki.verifyRequest(s.method(), s.url(), s.headers(), opts.withBody(body));
    }

    private static Fiki.Verdict verify(Signed s, Fiki.VerifyOptions opts) {
        return verify(s, s.body(), opts);
    }

    private static final Fiki.Resolver NEVER = keyid -> {
        throw new AssertionError("the resolver was asked about " + keyid);
    };

    private static FikiException thrown(Runnable body) {
        return assertThrows(FikiException.class, body::run);
    }

    /* ------------------------ B keyids under a resolver: the prefix's key, never the resolver's */

    @Test
    void aBKeyidIsVerifiedFromItsPrefixWithoutAskingTheResolver() {
        Fiki.Verdict verdict = verify(sign(KEY.aid()), opts(AT).withResolver(NEVER));
        assertEquals(KEY.aid(), verdict.keyid());
        assertEquals(KEY.aid(), verdict.aid());
    }

    @Test
    void aMixedOrderBKeyidIsMalformedUnderAResolver() {
        FikiException e = thrown(() -> verify(sign(B_MIXED), opts(AT).withResolver(NEVER)));
        assertEquals(FikiException.Kind.MalformedKey, e.kind());
        assertEquals(B_MIXED, e.detail());
    }

    @Test
    void aSmallOrderBKeyidIsMalformedUnderAResolverWithoutAskingIt() {
        FikiException e = thrown(() -> verify(sign(B_WEAK), opts(AT).withResolver(NEVER)));
        assertEquals(FikiException.Kind.MalformedKey, e.kind());
        assertEquals(B_WEAK, e.detail());
    }

    @ParameterizedTest
    @ValueSource(strings = {"small-order", "mixed-order"})
    void aWeakBKeyidIsMalformedBeforeTheExpectedKeyidIsCompared(String which) {
        String keyid = which.equals("small-order") ? B_WEAK : B_MIXED;
        assertEquals(FikiException.Kind.MalformedKey, thrown(() ->
            verify(sign(keyid), opts(AT).withResolver(NEVER).withExpectedKeyid(E_AID))).kind());
    }

    @Test
    void aMixedOrderKeyFromAResolverIsMalformed() {
        FikiException e = thrown(() -> verify(sign(E_AID),
            opts(AT).withResolver(keyid -> keyid.equals(E_AID) ? MIXED.clone() : null)));
        assertEquals(FikiException.Kind.MalformedKey, e.kind());
        assertEquals(E_AID, e.detail());
    }

    /** keri_vectors_format 4 pins acceptance of a mixed-order raw keyid (@5r75ff4m); only an AID's
     * key must lie in the subgroup, so this one reaches the signature check. */
    @Test
    void aMixedOrderRawKeyidIsStillFikisOwnLensAndNotRefusedForItsOrder() {
        String keyid = Base64.getUrlEncoder().withoutPadding().encodeToString(MIXED);
        assertEquals(FikiException.Kind.SignatureMismatch, thrown(() -> verify(sign(keyid), opts(AT))).kind());
    }

    /* ------------------------------------------------------ an AID is any of keripy's PreDex codes */

    private static final Map<String, Integer> PREDEX = predex();

    private static Map<String, Integer> predex() {
        Map<String, Integer> out = new LinkedHashMap<>();
        for (String code : List.of("B", "D", "E", "F", "G", "H", "I")) {
            out.put(code, 32);
        }
        for (String code : List.of("0D", "0E", "0F", "0G")) {
            out.put(code, 64);
        }
        for (String code : List.of("1AAA", "1AAB", "1AAI", "1AAJ")) {
            out.put(code, 33);
        }
        out.put("1AAC", 57);
        out.put("1AAD", 57);
        out.put("1AAE", 114);
        return out;
    }

    @ParameterizedTest
    @ValueSource(strings = {"B", "D", "E", "F", "G", "H", "I", "0D", "0E", "0F", "0G",
        "1AAA", "1AAB", "1AAI", "1AAJ", "1AAC", "1AAD", "1AAE"})
    void everyPredexCodeSpellsAWellFormedAid(String code) {
        byte[] doubled = Key.concat(sha512(code), sha512(code));
        byte[] data = java.util.Arrays.copyOf(doubled, PREDEX.get(code));
        String keyid = cesr(code, data);
        assertTrue(Key.wellFormedAid(keyid), keyid);
        assertFalse(Key.wellFormedAid(keyid.substring(0, keyid.length() - 1)), keyid);
        assertFalse(Key.wellFormedAid(keyid + "A"), keyid);
    }

    @ParameterizedTest
    @CsvSource({
        "code-A, A", "code-J, J", "code-0A, 0A", "code-1AAF, 1AAF", "1AAD-short, 1AAD",
        "0D-pad-bit-1, 0Dg", "0D-pad-bit-2, 0DQ",
    })
    void otherCodesAndNonCanonicalSpellingsAreNotAids(String name, String prefix) {
        int total = switch (name) {
            case "code-A", "code-J" -> 44;
            case "code-0A" -> 88;
            case "code-1AAF" -> 48;
            case "1AAD-short" -> 79;
            default -> 88;
        };
        String keyid = prefix + "A".repeat(total - prefix.length());
        assertFalse(Key.wellFormedAid(keyid), name);
    }

    @Test
    void aKeyidOfAnyLengthOrAlphabetIsSafelyNotAnAid() {
        for (String keyid : List.of("", "B", "0", "1", "1AA", "9AAA" + "A".repeat(44), "0D" + "!".repeat(86),
                "1AAA" + "=".repeat(44), "E" + "A".repeat(42) + "=")) {
            assertFalse(Key.wellFormedAid(keyid), keyid);
        }
    }

    @Test
    void anEd448TransferableKeyidWithNoKeyStateIsAnUnknownKey() {
        byte[] data = new byte[57];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        String keyid = cesr("1AAD", data);
        List<String> calls = new ArrayList<>();
        assertEquals(FikiException.Kind.UnknownKey, thrown(() -> verify(sign(keyid), opts(AT).withResolver(k -> {
            calls.add(k);
            return null;
        }))).kind());
        assertEquals(List.of(keyid), calls);
    }

    private static byte[] nonTransferable(int size) {
        byte[] data = new byte[size];
        data[0] = 2;
        for (int i = 1; i < size; i++) {
            data[i] = (byte) (i - 1);
        }
        return data;
    }

    @ParameterizedTest
    @CsvSource({"1AAA, 33", "1AAC, 57", "1AAI, 33"})
    void aNonTransferableKeyidOtherThanBIsAnUnsupportedAlgorithm(String code, int size) {
        String keyid = cesr(code, nonTransferable(size));
        assertEquals(FikiException.Kind.UnsupportedAlgorithm,
            thrown(() -> verify(sign(keyid), opts(AT).withResolver(NEVER))).kind());
    }

    @Test
    void aNonTransferableKeyidOtherThanTheExpectedOneIsUnknownFirst() {
        String keyid = cesr("1AAA", nonTransferable(33));
        assertEquals(FikiException.Kind.UnknownKey,
            thrown(() -> verify(sign(keyid), opts(AT).withResolver(NEVER).withExpectedKeyid(E_AID))).kind());
    }

    /* ------------------------------------------ content no header announced, at the body stage */

    @Test
    void anUnannouncedUncoveredRequestBodyIsRefusedAtTheBodyStage() {
        Signed s = sign(KEY.aid(), Map.of(), null);
        assertEquals(FikiException.Kind.InsufficientCoverage, thrown(() ->
            verify(s, BODY, opts(AT).withResolver(NEVER).withMinimum(Fiki.REQUEST_MINIMUM))).kind());
    }

    @Test
    void anUnannouncedUncoveredRequestBodyComesAfterFreshness() {
        Signed s = sign(KEY.aid(), Map.of(), null);
        assertEquals(FikiException.Kind.SignatureTooOld, thrown(() ->
            verify(s, BODY, opts(AT + 1000).withResolver(NEVER).withMinimum(Fiki.REQUEST_MINIMUM))).kind());
    }

    @Test
    void anUnannouncedUncoveredRequestBodyComesAfterTheSignature() {
        Signed s = sign(KEY.aid(), Map.of(), null);
        s.headers().put("Signature", "sig=:" + Base64.getEncoder().encodeToString(new byte[64]) + ":");
        assertEquals(FikiException.Kind.SignatureMismatch, thrown(() ->
            verify(s, BODY, opts(AT).withResolver(NEVER).withMinimum(Fiki.REQUEST_MINIMUM))).kind());
    }

    @Test
    void anUnannouncedRequestBodyIsNotRefusedWithoutAMinimum() {
        Signed s = sign(KEY.aid(), Map.of(), null);
        assertEquals(KEY.aid(), verify(s, BODY, opts(AT).withResolver(NEVER)).keyid());
    }

    @Test
    void anEmptyUnannouncedRequestBodyIsNoBody() {
        Signed s = sign(KEY.aid(), Map.of(), null);
        assertEquals(KEY.aid(),
            verify(s, new byte[0], opts(AT).withResolver(NEVER).withMinimum(Fiki.REQUEST_MINIMUM)).keyid());
    }

    @Test
    void anAnnouncedUncoveredRequestBodyIsStillRefusedAtTheCoveredList() {
        Signed s = sign(KEY.aid(), Map.of("Content-Length", "18"), null);
        assertEquals(FikiException.Kind.InsufficientCoverage, thrown(() ->
            verify(s, null, opts(AT + 1000).withResolver(NEVER).withMinimum(Fiki.REQUEST_MINIMUM))).kind());
    }

    /** A client holds the response's content before verifying it, so the covered-list check judges
     * it there, ahead of the signature (profile section 9, step 12). */
    @Test
    void anUncoveredResponseBodyIsRefusedAtTheCoveredListByItsContent() {
        Fiki.Request request = new Fiki.Request("GET", URL, Map.of(), null);
        Map<String, String> headers = new LinkedHashMap<>(Fiki.signResponse(KEY, 200, request, Map.of(),
            Fiki.SignOptions.none().withCreated(AT).withKeyid(KEY.aid())));
        byte[] body = "{\"done\": true}".getBytes(StandardCharsets.UTF_8);
        assertEquals(FikiException.Kind.InsufficientCoverage, thrown(() -> Fiki.verifyResponse(201, headers, request,
            Fiki.VerifyOptions.maxAge(300).withNow(AT).withBody(body).withResolver(NEVER)
                .withExpectedKeyid(KEY.aid()))).kind());
        assertNotEquals(null, headers.get("Signature"));
    }
}
