package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * What the KERI profile of RFC 9421 asks of a verifier, ported from fiki-py's test_profile.py
 * (this.i @7f28p7xk, @2f227n4r, @7p9s3g9k, @6g9zjsv9, @24tvlxgd), plus this port's own decisions
 * (@8yucn7nv, @2kc2c4h5).
 *
 * <p>Every refusal is written as a positive assertion about a refusal, because a negative
 * requirement that is quietly dropped leaves no failing test behind.
 */
class ProfileTest {

    private static final Key KEY = seeded(0);
    private static final Key OTHER = seeded(1);
    private static final String URL = "https://keria.example.com/identifiers?type=rot";
    private static final byte[] BODY = "{\"hello\": \"world\"}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESPONSE_BODY = "{\"done\": true}".getBytes(StandardCharsets.UTF_8);
    private static final long AT = 1_700_000_000L;
    private static final String AID = cesr("E", sha256("a transferable AID".getBytes(StandardCharsets.UTF_8)));
    private static final Fiki.Request REQUEST =
        new Fiki.Request("POST", URL, Map.of("Content-Digest", Fiki.contentDigest(BODY)), BODY);

    private static Key seeded(int start) {
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) {
            seed[i] = (byte) (start + i);
        }
        return Key.fromSeed(seed);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] raw(Key key) {
        return Key.verifyingKeyBytes(key.aid());
    }

    /** A 44-character qb64 over 32 raw bytes, the arithmetic fiki's own B lens uses. */
    private static String cesr(String code, byte[] raw) {
        byte[] padded = new byte[33];
        System.arraycopy(raw, 0, padded, 1, 32);
        return code + Base64.getUrlEncoder().withoutPadding().encodeToString(padded).substring(1);
    }

    /** The same 32 bytes spelled with a non-zero pad bit, which must never alias the key. */
    private static String paddingBitAlias(String aid) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int index = alphabet.indexOf(aid.charAt(1));
        return aid.charAt(0) + String.valueOf(alphabet.charAt(index ^ 0x10)) + aid.substring(2);
    }

    private static FikiException.Kind kindOf(Runnable body) {
        return assertThrows(FikiException.class, body::run).kind();
    }

    private static FikiException thrown(Runnable body) {
        return assertThrows(FikiException.class, body::run);
    }

    /* ------------------------------------------------------------------ request helpers */

    record Signed(String method, String url, byte[] body, Map<String, String> headers) {
        Signed withBody(byte[] other) {
            return new Signed(method, url, other, headers);
        }

        Signed withMethod(String other) {
            return new Signed(other, url, body, headers);
        }

        Signed mangle(String old, String replacement) {
            String input = headers.get("Signature-Input");
            assertTrue(input.contains(old), input + " lacks " + old);
            headers.put("Signature-Input", input.replace(old, replacement));
            return this;
        }

        String keyid() {
            return headers.get("Signature-Input").split("keyid=\"")[1].split("\"")[0];
        }
    }

    private static Signed sign(Key key, String method, String url, Map<String, String> given,
            Fiki.SignOptions opts) {
        Map<String, String> headers = new LinkedHashMap<>(given);
        headers.putAll(Fiki.signRequest(key, method, url, given,
            opts.created() == null ? opts.withCreated(AT) : opts));
        return new Signed(method, url, opts.body(), headers);
    }

    private static Signed sign(UnaryOperator<Fiki.SignOptions> opts) {
        return sign(KEY, "POST", URL, Map.of(), opts.apply(Fiki.SignOptions.none().withBody(BODY)));
    }

    private static Signed sign() {
        return sign(opts -> opts);
    }

    private static Signed signWith(Map<String, String> given, UnaryOperator<Fiki.SignOptions> opts) {
        return sign(KEY, "POST", URL, given, opts.apply(Fiki.SignOptions.none().withBody(BODY)));
    }

    /**
     * A request signed by a signer that is not fiki and checks nothing: the base built directly
     * and signed, so a verifier test can hold a digest fiki's own signer would refuse.
     */
    private static Signed foreign(Map<String, String> given, List<String> covered, byte[] body) {
        Map<String, String> headers = new LinkedHashMap<>(given);
        byte[] base = Fiki.signatureBase("POST", URL, headers, covered,
            new Fiki.Params(AT, KEY.keyid(), "ed25519", null, null, null));
        String text = new String(base, StandardCharsets.UTF_8);
        headers.put("Signature-Input", "sig=" + text.substring(text.lastIndexOf(": (") + 2));
        headers.put("Signature", "sig=:" + Base64.getEncoder().encodeToString(KEY.sign(base)) + ":");
        return new Signed("POST", URL, body, headers);
    }

    private static Fiki.Verdict verify(Signed s, UnaryOperator<Fiki.VerifyOptions> opts) {
        return Fiki.verifyRequest(s.method(), s.url(), s.headers(),
            opts.apply(OptedOut.decliningFreshness().withBody(s.body())));
    }

    private static Fiki.Verdict verify(Signed s) {
        return verify(s, opts -> opts);
    }

    private static Fiki.Resolver only(String keyid, byte[] raw) {
        return asked -> asked.equals(keyid) ? raw : null;
    }

    /* ----------------------------------------------------------------- response helpers */

    private static Map<String, String> respond(UnaryOperator<Fiki.SignOptions> opts, int status,
            Fiki.Request request, Map<String, String> given) {
        Map<String, String> headers = new LinkedHashMap<>(given);
        headers.putAll(Fiki.signResponse(KEY, status, request, given,
            opts.apply(Fiki.SignOptions.none().withBody(RESPONSE_BODY).withCreated(AT))));
        return headers;
    }

    private static Map<String, String> respond(UnaryOperator<Fiki.SignOptions> opts) {
        return respond(opts, 200, REQUEST, Map.of());
    }

    private static Map<String, String> respond() {
        return respond(opts -> opts);
    }

    private static Fiki.Verdict check(Map<String, String> headers, int status, byte[] body,
            Fiki.Request request, UnaryOperator<Fiki.VerifyOptions> opts) {
        return Fiki.verifyResponse(status, headers, request,
            opts.apply(OptedOut.decliningFreshness().withBody(body)));
    }

    private static Fiki.Verdict check(Map<String, String> headers, UnaryOperator<Fiki.VerifyOptions> opts) {
        return check(headers, 200, RESPONSE_BODY, REQUEST, opts);
    }

    private static Fiki.Verdict check(Map<String, String> headers) {
        return check(headers, opts -> opts);
    }

    private static Map<String, String> mangle(Map<String, String> headers, String old, String replacement) {
        String input = headers.get("Signature-Input");
        assertTrue(input.contains(old), input + " lacks " + old);
        headers.put("Signature-Input", input.replace(old, replacement));
        return headers;
    }

    private static List<String> plus(List<String> base, String... more) {
        List<String> out = new ArrayList<>(base);
        out.addAll(List.of(more));
        return out;
    }

    /* ------------------------------------------- @method is the method as sent (@22g0xkr8) */

    @Test
    void theMethodIsNotUppercasedInTheBase() {
        byte[] base = Fiki.signatureBase("post", URL, Map.of(), List.of("@method"), Fiki.Params.of(AT, "k"));
        assertEquals("\"@method\": post", new String(base, StandardCharsets.UTF_8).split("\n")[0]);
    }

    @Test
    void aRequestSignedWithALowercaseMethodDoesNotVerifyAsUppercase() {
        Signed s = sign(KEY, "post", URL, Map.of(), Fiki.SignOptions.none().withBody(BODY));
        assertEquals(KEY.aid(), verify(s).aid());
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> verify(s.withMethod("POST"))));
    }

    /* ----------------------------------------- Content-Digest: every recognized member */

    @Test
    void twoRecognizedDigestsMustBothMatch() {
        String bad512 = Base64.getEncoder().encodeToString(sha512("other".getBytes(StandardCharsets.UTF_8)));
        Signed s = foreign(Map.of("Content-Digest", Fiki.contentDigest(BODY) + ", sha-512=:" + bad512 + ":"),
            List.of("@method", "@path", "@query", "content-digest"), BODY);
        assertEquals(FikiException.Kind.DigestMismatch, kindOf(() -> verify(s)));
    }

    @Test
    void twoRecognizedDigestsThatBothMatchVerify() {
        String good512 = Base64.getEncoder().encodeToString(sha512(BODY));
        Signed s = signWith(Map.of("Content-Digest", "sha-512=:" + good512 + ":, " + Fiki.contentDigest(BODY)),
            opts -> opts);
        assertEquals(KEY.aid(), verify(s).aid());
    }

    private static byte[] sha512(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(data);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void anUnparsableDigestIsMalformedEvenWhenNoBodyWasSupplied() {
        Signed s = foreign(Map.of("Content-Digest", "(((("), List.of("@method", "content-digest"), null);
        assertEquals(FikiException.Kind.MalformedDigest, kindOf(() -> verify(s)));
    }

    /* ------------------------------ caller-chosen keyid, authoritative resolver (@6g9zjsv9) */

    @Test
    void aCallerMaySignWithAnAidAsTheKeyid() {
        assertTrue(sign(opts -> opts.withKeyid(AID)).headers().get("Signature-Input").contains("keyid=\"" + AID + "\""));
    }

    @Test
    void aResolverSuppliesTheKeyForATransferableAid() {
        Fiki.Verdict verdict = verify(sign(opts -> opts.withKeyid(AID)), opts -> opts.withResolver(only(AID, raw(KEY))));
        assertEquals(AID, verdict.aid());
        assertEquals(AID, verdict.keyid());
    }

    @Test
    void withoutAResolverTheVerdictStillReportsTheRawKeyid() {
        Fiki.Verdict verdict = verify(sign());
        assertEquals(KEY.aid(), verdict.aid());
        assertEquals(KEY.keyid(), verdict.keyid());
    }

    @Test
    void aKeyidTheResolverDoesNotKnowIsAnUnknownKey() {
        FikiException e = thrown(() -> verify(sign(opts -> opts.withKeyid(AID)), opts -> opts.withResolver(k -> null)));
        assertEquals(FikiException.Kind.UnknownKey, e.kind());
        assertEquals(AID, e.detail());
    }

    @Test
    void aResolverReturningSomethingOtherThan32BytesIsAMalformedKey() {
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() ->
            verify(sign(opts -> opts.withKeyid(AID)), opts -> opts.withResolver(k -> new byte[5]))));
    }

    @Test
    void aResolverMayRefuseAMalformedKeyidItself() {
        Fiki.Resolver refusing = keyid -> {
            throw new FikiException(FikiException.Kind.MalformedKey, keyid + " is not an AID.", keyid);
        };
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() ->
            verify(sign(opts -> opts.withKeyid("not-an-aid")), opts -> opts.withResolver(refusing))));
    }

    @Test
    void aResolverMayRefuseAKeyStateWithNoSingleSigner() {
        Fiki.Resolver refusing = keyid -> {
            throw new FikiException(FikiException.Kind.UnsupportedSigner, keyid + " has no single signer.", keyid);
        };
        assertEquals(FikiException.Kind.UnsupportedSigner, kindOf(() ->
            verify(sign(opts -> opts.withKeyid(AID)), opts -> opts.withResolver(refusing))));
    }

    @Test
    void aDPrefixedKeyidIsNeverDecodedAsAKeyWhenAResolverIsSupplied() {
        String inception = cesr("D", raw(KEY));
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() ->
            verify(sign(opts -> opts.withKeyid(inception)), opts -> opts.withResolver(only(inception, raw(OTHER))))));
        Signed byOther = sign(OTHER, "POST", URL, Map.of(), Fiki.SignOptions.none().withBody(BODY).withKeyid(inception));
        assertEquals(inception, verify(byOther, opts -> opts.withResolver(only(inception, raw(OTHER)))).aid());
    }

    @Test
    void aResolverWithNoKeyidToResolveIsAMissingKey() {
        Signed s = sign(opts -> opts.withKeyid(AID)).mangle(";keyid=\"" + AID + "\"", "");
        assertEquals(FikiException.Kind.MissingKey, kindOf(() -> verify(s, opts -> opts.withResolver(only(AID, raw(KEY))))));
    }

    @Test
    void anEmptyKeyidIsAMissingKey() {
        assertEquals(FikiException.Kind.MissingKey, kindOf(() ->
            verify(sign(opts -> opts.withKeyid("")), opts -> opts.withResolver(k -> null))));
    }

    @Test
    void expectedAidAndAResolverTogetherAreAProgrammingError() {
        Signed s = sign();
        assertThrows(IllegalArgumentException.class, () ->
            verify(s, opts -> opts.withResolver(k -> null).withExpectedAid(KEY.aid())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"B", "D", "E"})
    void aPaddingBitAliasIsMalformedEvenThroughAResolver(String code) {
        String alias = paddingBitAlias(cesr(code, raw(KEY)));
        Signed s = sign(opts -> opts.withKeyid(alias));
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> verify(s, opts -> opts.withResolver(k -> raw(KEY)))));
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> verify(s, opts -> opts.withResolver(k -> null))));
    }

    @Test
    void aPaddingBitAliasOfABAidIsMalformedAsAnAidToo() {
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> Key.verifyingKeyBytes(paddingBitAlias(KEY.aid()))));
    }

    @Test
    void anAidShapedKeyidOutsideTheAlphabetIsMalformedThroughAResolver() {
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() ->
            verify(sign(opts -> opts.withKeyid("E" + "!".repeat(43))), opts -> opts.withResolver(k -> raw(KEY)))));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",    // padded
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh",       // short
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh!",      // outside the alphabet
    })
    void aRawKeyidThatIsNotTheKeysOwnSpellingIsMalformed(String keyid) {
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> verify(sign(opts -> opts.withKeyid(keyid)))));
    }

    @Test
    void aRawKeyidWithNonZeroTrailingBitsIsMalformed() {
        // The 43rd character carries two bits past the 32 bytes; only zero bits are the key's.
        String keyid = KEY.keyid();
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        char last = keyid.charAt(42);
        String alias = keyid.substring(0, 42) + alphabet.charAt(alphabet.indexOf(last) ^ 1);
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> verify(sign(opts -> opts.withKeyid(alias)))));
    }

    /* --------------------------------- small-order keys are refused (@2kc2c4h5, tick 27eo) */

    private static final List<String> SMALL_ORDER = List.of(
        "0100000000000000000000000000000000000000000000000000000000000000",  // the identity
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  // order 8
        "0000000000000000000000000000000000000000000000000000000000000080",  // order 4, sign bit set
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"); // p + 1, non-canonical

    /** Under the identity point, this signature verifies over any message in a naive verifier. */
    private static Signed forgedUnder(String keyid) {
        Signed s = sign(opts -> opts.withKeyid(keyid));
        byte[] forged = new byte[64];
        forged[0] = 1;
        s.headers().put("Signature", "sig=:" + Base64.getEncoder().encodeToString(forged) + ":");
        return s;
    }

    @Test
    void aSmallOrderRawKeyidIsMalformed() {
        for (String hex : SMALL_ORDER) {
            String keyid = Base64.getUrlEncoder().withoutPadding().encodeToString(HexFormat.of().parseHex(hex));
            assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> verify(forgedUnder(keyid))), hex);
        }
    }

    @Test
    void aSmallOrderKeyFromAResolverIsMalformed() {
        for (String hex : SMALL_ORDER) {
            byte[] raw = HexFormat.of().parseHex(hex);
            assertEquals(FikiException.Kind.MalformedKey,
                kindOf(() -> verify(forgedUnder(AID), opts -> opts.withResolver(k -> raw))), hex);
        }
    }

    @Test
    void aSmallOrderExpectedAidIsMalformed() {
        String identity = Key.toAid(HexFormat.of().parseHex(SMALL_ORDER.get(0)));
        assertEquals(FikiException.Kind.MalformedKey,
            kindOf(() -> verify(forgedUnder(AID), opts -> opts.withExpectedAid(identity))));
    }

    @Test
    void aSmallOrderKeyIsRefusedBeforeTheAlgorithm() {
        String keyid = Base64.getUrlEncoder().withoutPadding().encodeToString(HexFormat.of().parseHex(SMALL_ORDER.get(0)));
        Signed s = forgedUnder(keyid).mangle("alg=\"ed25519\"", "alg=\"rsa-pss-sha512\"");
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> verify(s)));
    }

    @Test
    void everySmallOrderEncodingIsCaughtWhateverItsSignBit() {
        for (String hex : List.of(
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")) {
            byte[] raw = HexFormat.of().parseHex(hex);
            assertTrue(Key.smallOrder(raw), hex);
            raw[31] |= (byte) 0x80;
            assertTrue(Key.smallOrder(raw), hex + " with the sign bit set");
        }
        assertFalse(Key.smallOrder(raw(KEY)));
        byte[] near = HexFormat.of().parseHex("0100000000000000000000000000000000000000000000000000000000000001");
        assertFalse(Key.smallOrder(near));
    }

    /* ------------------- a key that is not a canonical on-curve point is refused (@3kdzr0zn) */

    // Derived from the curve equation for this test, not remembered: y = 2 has no x on the
    // curve, and y = 3 does, so 3 + p is a non-canonical spelling of an on-curve point.
    private static final List<String> NOT_A_POINT = List.of(
        "0200000000000000000000000000000000000000000000000000000000000000",  // y = 2, off the curve
        "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  // y = 3 + p
        "0100000000000000000000000000000000000000000000000000000000000080"); // x = 0, sign bit set

    @Test
    void aKeyThatIsNotACanonicalPointIsMalformedOnEveryPath() {
        for (String hex : NOT_A_POINT) {
            byte[] raw = HexFormat.of().parseHex(hex);
            assertFalse(Key.canonicalPoint(raw), hex);
            String keyid = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
            assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> verify(forgedUnder(keyid))), hex);
            assertEquals(FikiException.Kind.MalformedKey,
                kindOf(() -> verify(forgedUnder(AID), opts -> opts.withResolver(k -> raw))), hex);
            assertEquals(FikiException.Kind.MalformedKey,
                kindOf(() -> verify(forgedUnder(AID), opts -> opts.withExpectedAid(Key.toAid(raw)))), hex);
        }
        assertTrue(Key.canonicalPoint(raw(KEY)));
        assertTrue(Key.canonicalPoint(raw(OTHER)));
    }

    /* ----------------- a field value is checked raw, and an empty method is refused (@3cceqvg3) */

    @ParameterizedTest
    @ValueSource(strings = {"admin\r\n", "admin\n", "\u0000admin", "admin\r", "ad\u0000min"})
    void aControlCharacterIsRefusedBeforeAnyTrimming(String value) {
        Signed s = signWith(Map.of("X-Role", "admin"),
            opts -> opts.withCovered(List.of("@method", "@path", "@query", "x-role", "content-digest")));
        assertEquals(KEY.aid(), verify(s).aid());
        s.headers().put("X-Role", value);
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> verify(s)));
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> Fiki.signatureBase("GET", URL,
            Map.of("X-Role", value), List.of("x-role"), Fiki.Params.of(AT, "k"))));
    }

    @Test
    void onlySpacesAndTabsAreTrimmed() {
        assertEquals("\"x-role\": admin", firstLine(Fiki.signatureBase("GET", URL,
            Map.of("X-Role", " \tadmin\t "), List.of("x-role"), Fiki.Params.of(AT, "k"))));
        assertEquals("\"@authority\": other.example.com", firstLine(Fiki.signatureBase("GET", "/f",
            Map.of("Host", " Other.Example.com "), List.of("@authority"), Fiki.Params.of(AT, "k"))));
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> Fiki.signatureBase("GET", "/f",
            Map.of("Host", "other.example.com\r\n"), List.of("@authority"), Fiki.Params.of(AT, "k"))));
    }

    @Test
    void anEmptyOrMissingMethodIsTheCallersMistake() {
        for (String method : new String[] {"", null}) {
            assertThrows(IllegalArgumentException.class, () -> Fiki.signRequest(KEY, method, URL, Map.of(),
                Fiki.SignOptions.none().withCreated(AT)));
            assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest(method, URL, sign().headers(),
                OptedOut.decliningFreshness()));
            assertThrows(IllegalArgumentException.class, () -> Fiki.signatureBase(method, URL, Map.of(),
                List.of("@path"), Fiki.Params.of(AT, "k")));
            assertThrows(IllegalArgumentException.class, () -> new Fiki.Request(method, URL, Map.of(), null));
        }
        assertThrows(IllegalArgumentException.class, () -> new Fiki.Request("GET", null, Map.of(), null));
    }

    @Test
    void anyNonEmptyBodyIsABodyAndAnEmptyOneIsNot() {
        Signed bare = sign(KEY, "POST", URL, Map.of(), Fiki.SignOptions.none());
        assertEquals(FikiException.Kind.InsufficientCoverage, kindOf(() ->
            verify(bare.withBody(new byte[] {0}), opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM))));
        assertEquals(KEY.aid(), verify(bare.withBody(new byte[0]), opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM)).aid());
    }

    /* ------------------------------------------- component identifiers with parameters */

    @Test
    void reqNamesARequestComponentFromAResponse() {
        assertEquals("\"@method\";req", Fiki.req("@Method"));
        assertEquals("\"content-digest\";req", Fiki.req("Content-Digest"));
    }

    @Test
    void aCallerMayNameComponentsInTheirSerializedForm() {
        Signed s = sign(opts -> opts.withCovered(List.of("\"@method\"", "\"@PATH\"", "@query", "\"content-digest\"")));
        assertEquals(List.of("@method", "@path", "@query", "content-digest"), verify(s).covered());
    }

    @Test
    void signingADuplicateComponentIsRefused() {
        assertEquals(FikiException.Kind.DuplicateComponent,
            kindOf(() -> sign(opts -> opts.withCovered(List.of("@method", "@method", "content-digest")))));
    }

    @Test
    void aMalformedComponentSpecIsAFikiError() {
        assertEquals(FikiException.Kind.UnsupportedComponent,
            kindOf(() -> sign(opts -> opts.withCovered(List.of("\"@path")))));
        assertEquals(FikiException.Kind.UnsupportedComponent,
            kindOf(() -> sign(opts -> opts.withCovered(List.of("\"@path\" trailing")))));
    }

    @Test
    void aSignerRefusesAnUnsupportedComponentParameter() {
        assertEquals(FikiException.Kind.UnsupportedComponent,
            kindOf(() -> sign(opts -> opts.withCovered(List.of("\"@method\";sf", "@path", "content-digest")))));
    }

    /* ---------------------------------------------------- responses (RFC 9421 section 2.4) */

    @Test
    void aSignedResponseVerifiesAndBindsItsRequest() {
        Fiki.Verdict verdict = check(respond());
        assertEquals(KEY.aid(), verdict.aid());
        assertEquals(List.of("@status", "\"@method\";req", "\"@path\";req", "\"@query\";req", "content-digest",
            "\"content-digest\";req"), verdict.covered());
    }

    @Test
    void theStatusLineIsThreeDigits() {
        assertEquals("\"@status\": 204", firstLine(Fiki.responseSignatureBase(204, Map.of(),
            List.of("@status"), Fiki.Params.of(AT, "k"), null)));
    }

    private static String firstLine(byte[] base) {
        return new String(base, StandardCharsets.UTF_8).split("\n")[0];
    }

    @ParameterizedTest
    @ValueSource(ints = {99, 1000, -200})
    void aStatusThatIsNotThreeDigitsHasNoStatusLine(int status) {
        FikiException e = thrown(() -> Fiki.responseSignatureBase(status, Map.of(), List.of("@status"),
            Fiki.Params.of(AT, "k"), null));
        assertEquals(FikiException.Kind.MissingComponent, e.kind());
        assertEquals("@status", e.detail());
        assertEquals(FikiException.Kind.MissingComponent,
            kindOf(() -> check(respond(), status, RESPONSE_BODY, REQUEST, opts -> opts)));
    }

    @ParameterizedTest
    @ValueSource(ints = {100, 999})
    void theStatusRangeIsInclusive(int status) {
        assertEquals("\"@status\": " + status, firstLine(Fiki.responseSignatureBase(status, Map.of(),
            List.of("@status"), Fiki.Params.of(AT, "k"), null)));
    }

    @Test
    void theReqLinesCarryTheRequestValues() {
        String[] lines = new String(Fiki.responseSignatureBase(200, Map.of(),
            List.of("@status", Fiki.req("@method"), Fiki.req("@path"), Fiki.req("@query"), Fiki.req("content-digest")),
            Fiki.Params.of(AT, "k"), REQUEST), StandardCharsets.UTF_8).split("\n");
        assertEquals(List.of("\"@method\";req: POST", "\"@path\";req: /identifiers", "\"@query\";req: ?type=rot",
            "\"content-digest\";req: " + Fiki.contentDigest(BODY)), List.of(lines).subList(1, 5));
    }

    @Test
    void anAlteredStatusIsRefused() {
        assertEquals(FikiException.Kind.SignatureMismatch,
            kindOf(() -> check(respond(), 201, RESPONSE_BODY, REQUEST, opts -> opts)));
    }

    @Test
    void aSwappedResponseBodyIsRefused() {
        assertEquals(FikiException.Kind.DigestMismatch, kindOf(() -> check(respond(), 200,
            "{\"done\": false}".getBytes(StandardCharsets.UTF_8), REQUEST, opts -> opts)));
    }

    @Test
    void aResponseCheckedAgainstADifferentRequestIsRefused() {
        Fiki.Request other = new Fiki.Request("POST", "https://keria.example.com/other?type=rot", REQUEST.headers(), BODY);
        assertEquals(FikiException.Kind.SignatureMismatch,
            kindOf(() -> check(respond(), 200, RESPONSE_BODY, other, opts -> opts)));
    }

    @Test
    void aResponseWithNoRequestCoversOnlyItsOwnComponents() {
        Map<String, String> headers = respond(opts -> opts, 200, null, Map.of());
        assertEquals(List.of("@status", "content-digest"), check(headers, 200, RESPONSE_BODY, null, opts -> opts).covered());
    }

    @Test
    void aBodylessResponseToABodylessRequestCoversNoDigest() {
        Fiki.Request get = new Fiki.Request("GET", URL, Map.of(), null);
        Map<String, String> headers = respond(opts -> opts.withBody(null), 200, get, Map.of());
        assertEquals(List.of("@status", "\"@method\";req", "\"@path\";req", "\"@query\";req"),
            check(headers, 200, null, get, opts -> opts).covered());
    }

    @Test
    void signingAResponseBodyWithoutItsDigestIsRefused() {
        assertEquals(FikiException.Kind.UncoveredBody, kindOf(() -> respond(opts -> opts.withCovered(List.of("@status")))));
    }

    @Test
    void aReqComponentWithNoRequestToReadItFromIsMissing() {
        assertEquals(FikiException.Kind.MissingComponent, kindOf(() -> respond(
            opts -> opts.withCovered(List.of("@status", Fiki.req("@path"), "content-digest")), 200, null, Map.of())));
        assertEquals(FikiException.Kind.MissingComponent,
            kindOf(() -> check(respond(), 200, RESPONSE_BODY, null, opts -> opts)));
    }

    @Test
    void aReqFieldTheRequestLacksIsMissing() {
        Fiki.Request bare = new Fiki.Request("POST", URL, null, null);
        assertEquals(FikiException.Kind.MissingComponent, kindOf(() -> respond(
            opts -> opts.withCovered(List.of("@status", Fiki.req("content-digest"), "content-digest")), 200, bare, Map.of())));
    }

    /* ------------------------- one canonical header map, linear parsing, honest digests (@0ms4j0ef) */

    private static Map<String, String> twoSpellings() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Digest", Fiki.contentDigest(BODY));
        headers.put("content-digest", "sha-256=:AAAA:");
        return headers;
    }

    @Test
    void aHeaderMapThatNamesAFieldTwiceIsTheCallersMistake() {
        assertThrows(IllegalArgumentException.class, () -> Fiki.signRequest(KEY, "POST", URL, twoSpellings(),
            Fiki.SignOptions.none().withBody(BODY).withCreated(AT)));
        Map<String, String> received = new LinkedHashMap<>(sign().headers());
        received.put("content-digest", "sha-256=:AAAA:");
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest("POST", URL, received,
            OptedOut.decliningFreshness().withBody(BODY)));
        assertThrows(IllegalArgumentException.class, () -> new Fiki.Request("POST", URL, twoSpellings(), BODY));
        Map<String, String> answered = new LinkedHashMap<>(respond());
        answered.put("content-digest", "sha-256=:AAAA:");
        assertThrows(IllegalArgumentException.class, () -> check(answered));
        assertThrows(IllegalArgumentException.class, () -> Fiki.signatureBase("GET", URL, twoSpellings(),
            List.of("@method"), Fiki.Params.of(AT, "k")));
    }

    @Test
    void aRequestKeepsItsOwnCopyOfItsHeaders() {
        Map<String, String> headers = new LinkedHashMap<>(REQUEST.headers());
        Fiki.Request request = new Fiki.Request("POST", URL, headers, BODY);
        headers.put("Content-Digest", "sha-256=:AAAA:");
        assertEquals(Fiki.contentDigest(BODY), request.headers().get("Content-Digest"));
        assertThrows(UnsupportedOperationException.class, () -> request.headers().put("X", "y"));
    }

    @Test
    void parsingIsLinearInRepeatedAndDistinctParametersAndMembers() {
        int n = 200_000;
        StringBuilder repeated = new StringBuilder("a=1");
        StringBuilder distinct = new StringBuilder("a=1");
        StringBuilder members = new StringBuilder("m0=1");
        for (int i = 0; i < n; i++) {
            repeated.append(";p=").append(i % 10);
            distinct.append(";p").append(i).append("=1");
            members.append(", m").append(i % 1000).append("=").append(i % 10);
        }
        org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () -> {
            assertEquals(1, Sfv.parseDictionary(repeated.toString()).get(0).params().size());
            assertEquals(n, Sfv.parseDictionary(distinct.toString()).get(0).params().size());
            assertEquals(1000, Sfv.parseDictionary(members.toString()).size());
        });
    }

    @Test
    void aRepeatedMemberKeepsItsFirstPlaceWithItsLastValue() {
        List<Sfv.Member> parsed = Sfv.parseDictionary("a=1, b=2, a=3");
        assertEquals(List.of("a", "b"), parsed.stream().map(Sfv.Member::key).toList());
        assertEquals(3L, parsed.get(0).value());
    }

    @Test
    void textBetweenAnIpv6LiteralAndItsPortIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> authority("https://[::1]evil:443/"));
    }

    @Test
    void aSignerRefusesACallersDigestItsBodyContradicts() {
        // The call's mistake, not a message's defect (@5zrf8gjk, A7 and E5).
        assertThrows(IllegalArgumentException.class, () ->
            signWith(Map.of("Content-Digest", Fiki.contentDigest("other".getBytes(StandardCharsets.UTF_8))), opts -> opts));
        assertThrows(IllegalArgumentException.class, () ->
            signWith(Map.of("Content-Digest", "sha-1=:AAAA:"), opts -> opts));
        assertThrows(IllegalArgumentException.class, () -> respond(opts -> opts, 200, REQUEST,
            Map.of("content-digest", Fiki.contentDigest(BODY))));
        // A digest of the caller's own that holds is used as given, and covered.
        assertEquals(KEY.aid(), verify(signWith(Map.of("Content-Digest", Fiki.contentDigest(BODY)), opts -> opts)).aid());
    }

    /* --------------------------------- keyid is required under a minimum (@6hsuwdh8) */

    @Test
    void underAMinimumAKeyidIsRequiredEvenWhenTheVerifierNamesTheKey() {
        Signed s = sign();
        s.mangle(";keyid=\"" + s.keyid() + "\"", "");
        assertEquals(FikiException.Kind.MissingKey, kindOf(() ->
            verify(s, opts -> opts.withExpectedAid(KEY.aid()).withMinimum(Fiki.REQUEST_MINIMUM))));
        Signed whole = sign();
        assertEquals(KEY.aid(), verify(whole, opts -> opts.withExpectedAid(KEY.aid()).withMinimum(Fiki.REQUEST_MINIMUM)).aid());
    }

    @Test
    void aResponseWhoseHeadersNameAFieldTwiceIsRefusedAtSigningToo() {
        Map<String, String> twice = new LinkedHashMap<>();
        twice.put("X-Role", "admin");
        twice.put("x-role", "guest");
        assertThrows(IllegalArgumentException.class, () -> respond(opts -> opts, 200, REQUEST, twice));
    }

    @Test
    void duplicateComponentDetectionIsLinear() {
        // A covered list is bounded at MAX_INNER_LIST_ITEMS before anything is compared (@5zrf8gjk),
        // so the duplicate is found within the bound, and the parser itself is shown linear on a
        // list far past it.
        StringBuilder covered = new StringBuilder();
        for (int i = 0; i < Fiki.MAX_INNER_LIST_ITEMS - 6; i++) {
            covered.append(" \"x").append(i).append('"');
        }
        Signed s = sign().mangle("\"@method\"", "\"@method\"" + covered + " \"x0\"");
        assertEquals(FikiException.Kind.DuplicateComponent, kindOf(() -> verify(s)));
        int n = 100_000;
        StringBuilder huge = new StringBuilder("sig=(");
        for (int i = 0; i < n; i++) {
            huge.append(" \"x").append(i).append('"');
        }
        huge.append(')');
        org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () ->
            assertEquals(n, ((Sfv.InnerList) Sfv.parseDictionary(huge.toString()).get(0).value()).items().size()));
    }

    /* ------------------------------------------------ the remaining edges of the new surface */

    @Test
    void theOptionalParametersAreSignedAndVerified() {
        Signed s = sign(opts -> opts.withNonce("n-1").withTag("app").withLabel("mine"));
        String input = s.headers().get("Signature-Input");
        assertTrue(input.startsWith("mine=") && input.contains(";nonce=\"n-1\"") && input.contains(";tag=\"app\""), input);
        assertEquals(KEY.aid(), verify(s).aid());
        String bare = firstLine(Fiki.signatureBase("GET", URL, null, List.of("@method"),
            new Fiki.Params(null, null, null, null, null, null)));
        assertEquals("\"@method\": GET", bare);
        assertTrue(new String(Fiki.signatureBase("GET", URL, null, List.of("@method"),
            new Fiki.Params(null, null, null, null, null, null)), StandardCharsets.UTF_8)
            .endsWith("\"@signature-params\": (\"@method\")"));
    }

    @Test
    void absentAndEmptyInputsAreRefusedForWhatTheyAre() {
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest("GET", null, Map.of(),
            OptedOut.decliningFreshness()));
        assertEquals(FikiException.Kind.MissingSignature, kindOf(() -> Fiki.verifyRequest("GET", URL, null,
            OptedOut.decliningFreshness())));
        Signed s = sign();
        s.headers().put("Signature", "");
        assertEquals(FikiException.Kind.MissingSignature, kindOf(() -> verify(s)));
        Signed t = sign();
        t.headers().put("Signature-Input", "");
        assertEquals(FikiException.Kind.MissingSignatureInput, kindOf(() -> verify(t)));
        Signed u = sign();
        u.headers().remove("Content-Digest");
        assertEquals(FikiException.Kind.MissingComponent, kindOf(() -> verify(u)));
        Map<String, String> headers = Fiki.signResponse(KEY, 204, null, null, Fiki.SignOptions.none().withCreated(AT));
        assertEquals(List.of("@status"), check(headers, 204, null, null, opts -> opts).covered());
    }

    @Test
    void aMaxAgeNeedsACreatedEvenWithoutAMinimum() {
        // Validly signed with no created at all, which RFC 9421 allows and a max age cannot judge.
        byte[] base = Fiki.signatureBase("GET", URL, Map.of(), List.of("@method", "@path"),
            new Fiki.Params(null, KEY.keyid(), "ed25519", null, null, null));
        String text = new String(base, StandardCharsets.UTF_8);
        Map<String, String> headers = Map.of(
            "Signature-Input", "sig=" + text.substring(text.indexOf("(")),
            "Signature", "sig=:" + Base64.getEncoder().encodeToString(KEY.sign(base)) + ":");
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, headers, OptedOut.decliningFreshness()).aid());
        assertEquals(FikiException.Kind.SignatureTooOld, kindOf(() -> Fiki.verifyRequest("GET", URL, headers,
            OptedOut.maxAge(300).withNow(AT))));
    }

    @Test
    void anEmptyOrAllSpaceValueIsAnEmptyValue() {
        assertEquals("\"x-note\": ", firstLine(Fiki.signatureBase("GET", URL, Map.of("X-Note", " \t "),
            List.of("x-note"), Fiki.Params.of(AT, "k"))));
    }

    @Test
    void anAbsoluteUrlWithAnEmptyAuthorityIsRefusedAndOnlyOriginFormTakesTheHostHeader() {
        // Format 3 (@524c8qgv): "https:///f" is neither origin-form nor an absolute URI with an
        // authority, so it no longer falls back to Host; it cannot be read at all.
        assertThrows(IllegalArgumentException.class, () -> Fiki.signatureBase("GET", "https:///f",
            Map.of("Host", "H.example"), List.of("@authority"), Fiki.Params.of(AT, "k")));
        assertEquals("\"@authority\": h.example", firstLine(Fiki.signatureBase("GET", "/f",
            Map.of("Host", "H.example"), List.of("@authority"), Fiki.Params.of(AT, "k"))));
        assertEquals("\"@authority\": x.example:443", firstLine(Fiki.signatureBase("GET", "git+ssh://x.example:443/f",
            Map.of(), List.of("@authority"), Fiki.Params.of(AT, "k"))));
        assertEquals("\"@path\": /p", firstLine(Fiki.signatureBase("GET", "/p?next=a://b",
            Map.of(), List.of("@path"), Fiki.Params.of(AT, "k"))));
        assertEquals("\"@path\": /x", firstLine(Fiki.signatureBase("GET", "/x?u=h%20t://b",
            Map.of(), List.of("@path"), Fiki.Params.of(AT, "k"))));
    }

    @Test
    void anAidShapedKeyidUnderAnotherCodeReachesTheResolver() {
        String other = "A" + AID.substring(1);
        assertEquals(other, verify(sign(opts -> opts.withKeyid(other)), opts -> opts.withResolver(only(other, raw(KEY)))).aid());
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> Key.verifyingKeyBytes(null)));
    }

    @Test
    void theIdentityWithoutItsSignBitIsAPointAndOnlyTheBlocklistRefusesIt() {
        byte[] identity = HexFormat.of().parseHex(SMALL_ORDER.get(0));
        assertTrue(Key.canonicalPoint(identity));
        assertTrue(Key.smallOrder(identity));
    }

    @Test
    void theParsersRemainingShapes() {
        assertEquals(List.of(), Sfv.parseDictionary(""));
        assertEquals(2, Sfv.parseDictionary("a=1,\tb=2").size());
        assertEquals(2, Sfv.parseDictionary("a=1, *b=2").size());
        assertEquals("a\"b\\c", Sfv.parseDictionary("a=\"a\\\"b\\\\c\"").get(0).value());
        assertEquals(new Sfv.Token("Tok"), Sfv.parseDictionary("a=Tok").get(0).value());
        assertEquals(new Sfv.Token("t"), Sfv.parseDictionary("a=t").get(0).value());
        assertEquals(":AQI=:", Sfv.serializeBareItem(new byte[] {1, 2}));
        assertEquals("tok", Sfv.serializeBareItem(new Sfv.Token("tok")));
        // An X.509 Ed25519 key is a fixed 12-byte prefix and the 32 raw bytes.
        assertEquals(KEY.aid(), Key.toAid(java.util.Arrays.copyOfRange(Key.verifyingKey(KEY.aid()).getEncoded(), 12, 44)));
        for (String bad : List.of("a=1;", "a=\"oops\\", "a=[", "a=@", "a=\"x\\n\"", "A=1", "a=1;B", "~=1")) {
            assertThrows(Sfv.SyntaxException.class, () -> Sfv.parseDictionary(bad), bad);
        }
    }

    /* ------------------------------------------------------- the covered list, as received */

    @ParameterizedTest
    @ValueSource(strings = {"\"@method\";sf", "\"@method\";req", "\"@status\"", "\"@target-uri\""})
    void anUnsupportedComponentInARequestIsRefusedNotDropped(String covered) {
        Signed s = sign().mangle("\"@method\"", covered);
        assertEquals(FikiException.Kind.UnsupportedComponent, kindOf(() -> verify(s)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "\"@status\"|\"@status\";req", "\"@path\";req|\"@path\"", "\"@path\";req|\"@path\";req=?0",
        "\"@path\";req|\"@path\";req;bs", "\"@path\";req|\"@path\";req=\"yes\"",
    })
    void anUnsupportedComponentInAResponseIsRefused(String pair) {
        String[] parts = pair.split("\\|");
        Map<String, String> headers = mangle(respond(), parts[0], parts[1]);
        assertEquals(FikiException.Kind.UnsupportedComponent, kindOf(() -> check(headers)));
    }

    @Test
    void aDuplicateComponentIsRefused() {
        Signed s = sign().mangle("\"@path\"", "\"@path\" \"@path\"");
        FikiException e = thrown(() -> verify(s));
        assertEquals(FikiException.Kind.DuplicateComponent, e.kind());
        assertEquals("@path", e.detail());
    }

    @Test
    void aDuplicateIsFoundWhateverTheParameterOrderAndBeforeItIsUnsupported() {
        Map<String, String> headers = mangle(respond(), "\"content-digest\";req",
            "\"content-digest\";req;sf \"content-digest\";sf;req");
        assertEquals(FikiException.Kind.DuplicateComponent, kindOf(() -> check(headers)));
    }

    /* -------------------------------------------------------- Signature-Input, as received */

    @ParameterizedTest
    @ValueSource(strings = {
        "\"content-digest\"|\"Content-Digest\"",
        ";created=1700000000|;created=1700000000;context=\"x\"",
        ";created=1700000000|;created=\"soon\"",
        ";created=1700000000|;created=?1",
        ";created=1700000000|;created=1700000000.5",
        "alg=\"ed25519\"|alg=ed25519",
        "\"@path\"|path",
        "\"@path\"|1",
    })
    void aMalformedSignatureInputMemberIsRefused(String pair) {
        String[] parts = pair.split("\\|");
        Signed s = sign().mangle(parts[0], parts[1]);
        assertEquals(FikiException.Kind.MalformedSignatureInput, kindOf(() -> verify(s)));
    }

    @Test
    void aSignatureInputMemberThatIsNotAnInnerListIsRefused() {
        Signed s = sign();
        s.headers().put("Signature-Input", "sig=\"not a list\"");
        assertEquals(FikiException.Kind.MalformedSignatureInput, kindOf(() -> verify(s)));
    }

    @Test
    void twoLabelsInTheSignatureHeaderAreMalformed() {
        Signed s = sign();
        String value = s.headers().get("Signature").split("=", 2)[1];
        s.headers().put("Signature", s.headers().get("Signature") + ", other=" + value);
        assertEquals(FikiException.Kind.MalformedSignatureLabel, kindOf(() -> verify(s)));
    }

    @Test
    void labelsThatDifferAreAMissingLabel() {
        Signed s = sign();
        s.headers().put("Signature", s.headers().get("Signature").replaceFirst("^sig=", "other="));
        FikiException e = thrown(() -> verify(s));
        assertEquals(FikiException.Kind.MissingSignatureLabel, e.kind());
        assertEquals("sig", e.detail());
    }

    @Test
    void aSignatureThatIsNot64BytesIsAMalformedValue() {
        Signed s = sign();
        s.headers().put("Signature", "sig=:" + Base64.getEncoder().encodeToString(new byte[32]) + ":");
        assertEquals(FikiException.Kind.MalformedSignatureValue, kindOf(() -> verify(s)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sig=\"not bytes\"", "sig=token", "sig=(:AAAA:)", "sig=1.5"})
    void aSignatureMemberThatIsNotAByteSequenceIsFoundBeforeTheLabels(String signature) {
        Signed s = sign();
        String value = s.headers().get("Signature-Input").split("=", 2)[1];
        s.headers().put("Signature-Input", s.headers().get("Signature-Input") + ", other=" + value);
        s.headers().put("Signature", signature);
        assertEquals(FikiException.Kind.MalformedSignatureValue, kindOf(() -> verify(s)));
    }

    /* ---------------------------------------------------------------- the section 9 order */

    @Test
    void anUnsignedMessageIsMissingItsSignatureFirst() {
        Signed s = sign();
        s.headers().remove("Signature");
        s.headers().remove("Signature-Input");
        assertEquals(FikiException.Kind.MissingSignature, kindOf(() -> verify(s)));
    }

    @Test
    void anUnparsableSignatureIsReportedBeforeAnUnparsableInput() {
        Signed s = sign();
        s.headers().put("Signature", "((((");
        s.headers().put("Signature-Input", "((((");
        assertEquals(FikiException.Kind.MalformedSignature, kindOf(() -> verify(s)));
    }

    @Test
    void aMalformedKeyIsReportedBeforeAnUnsupportedAlgorithm() {
        Signed s = sign();
        s.mangle(s.keyid(), "not-a-key").mangle("alg=\"ed25519\"", "alg=\"rsa-pss-sha512\"");
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> verify(s)));
    }

    @Test
    void anUnsupportedAlgorithmIsRefusedAndNamed() {
        Signed s = sign().mangle("alg=\"ed25519\"", "alg=\"rsa-pss-sha512\"");
        FikiException e = thrown(() -> verify(s));
        assertEquals(FikiException.Kind.UnsupportedAlgorithm, e.kind());
        assertEquals("rsa-pss-sha512", e.detail());
    }

    @Test
    void stalenessIsReportedBeforeExpiry() {
        Signed s = sign(opts -> opts.withExpires(AT + 10));
        assertEquals(FikiException.Kind.SignatureTooOld, kindOf(() ->
            Fiki.verifyRequest(s.method(), s.url(), s.headers(),
                OptedOut.maxAge(300).withSkew(60).withNow(AT + 1000).withBody(BODY))));
    }

    /* ------------------------------------------------ the minimum covered set (section 3) */

    @Test
    void theMinimumSetsAreTheProfiles() {
        assertEquals(List.of("@method", "@path", "@query"), Fiki.REQUEST_MINIMUM);
        assertEquals(List.of("@status", Fiki.req("@method"), Fiki.req("@path"), Fiki.req("@query")),
            Fiki.RESPONSE_MINIMUM);
    }

    @Test
    void aRequestCoveringTheMinimumVerifies() {
        assertEquals(KEY.aid(), verify(sign(), opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM)).aid());
    }

    @Test
    void aRequestCoveringLessThanTheMinimumIsRefusedEvenThoughItVerifies() {
        Signed s = sign(opts -> opts.withCovered(List.of("@method", "@path", "content-digest")));
        assertEquals(KEY.aid(), verify(s).aid());
        FikiException e = thrown(() -> verify(s, opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM)));
        assertEquals(FikiException.Kind.InsufficientCoverage, e.kind());
        assertEquals("@query", e.detail());
    }

    @Test
    void aMinimumMayBeNamedInSerializedForm() {
        assertEquals(KEY.aid(), verify(sign(), opts -> opts.withMinimum(List.of("\"@method\"", "\"@PATH\"", "\"@query\""))).aid());
    }

    @ParameterizedTest
    @ValueSource(strings = {"Content-Length:18", "Content-Length:many", "Transfer-Encoding:chunked", "-:arrived",
        "Content-Length:-5", "Content-Length:18 bytes", "Content-Length:+3"})
    void aBodyWithoutACoveredDigestIsInsufficientCoverage(String extra) {
        String[] parts = extra.split(":", 2);
        boolean arrived = parts[0].equals("-");
        Signed s = sign(KEY, "POST", URL, arrived ? Map.of() : Map.of(parts[0], parts[1]), Fiki.SignOptions.none())
            .withBody(arrived ? BODY : null);
        FikiException e = thrown(() -> verify(s, opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM)));
        assertEquals(FikiException.Kind.InsufficientCoverage, e.kind());
        assertEquals("content-digest", e.detail());
    }

    @Test
    void aBodylessRequestNeedsNoDigestUnderAMinimum() {
        Signed s = sign(KEY, "GET", URL, Map.of(), Fiki.SignOptions.none());
        assertEquals(KEY.aid(), verify(s, opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM)).aid());
    }

    @Test
    void aZeroContentLengthIsNoBody() {
        Signed s = sign(KEY, "POST", URL, Map.of("Content-Length", " 000 "), Fiki.SignOptions.none()).withBody(new byte[0]);
        assertEquals(KEY.aid(), verify(s, opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM)).aid());
    }

    @Test
    void insufficientCoverageIsReportedBeforeTheKey() {
        Signed s = sign(opts -> opts.withCovered(List.of("@method", "@path", "content-digest")));
        s.mangle(s.keyid(), "not-a-key");
        assertEquals(FikiException.Kind.InsufficientCoverage,
            kindOf(() -> verify(s, opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM))));
    }

    @Test
    void aResponseCoveringTheMinimumVerifies() {
        assertEquals(KEY.aid(), check(respond(), opts -> opts.withMinimum(Fiki.RESPONSE_MINIMUM)).aid());
    }

    @Test
    void aResponseMissingAReqComponentIsRefused() {
        Map<String, String> headers = respond(opts -> opts.withCovered(List.of("@status", Fiki.req("@method"),
            Fiki.req("@query"), "content-digest", Fiki.req("content-digest"))));
        FikiException e = thrown(() -> check(headers, opts -> opts.withMinimum(Fiki.RESPONSE_MINIMUM)));
        assertEquals(FikiException.Kind.InsufficientCoverage, e.kind());
        assertEquals("\"@path\";req", e.detail());
    }

    @Test
    void aResponseBodyWithoutItsDigestIsRefused() {
        Map<String, String> headers = respond(opts -> opts.withBody(null), 200, REQUEST, Map.of("Content-Length", "14"));
        FikiException e = thrown(() -> check(headers, opts -> opts.withMinimum(Fiki.RESPONSE_MINIMUM)));
        assertEquals(FikiException.Kind.InsufficientCoverage, e.kind());
        assertEquals("content-digest", e.detail());
    }

    @Test
    void aResponseToARequestWithABodyMustCoverTheRequestsDigest() {
        Map<String, String> headers = respond(opts -> opts.withCovered(plus(Fiki.RESPONSE_MINIMUM, "content-digest")));
        FikiException e = thrown(() -> check(headers, opts -> opts.withMinimum(Fiki.RESPONSE_MINIMUM)));
        assertEquals(FikiException.Kind.InsufficientCoverage, e.kind());
        assertEquals("\"content-digest\";req", e.detail());
    }

    @Test
    void aResponseJudgesItsRequestsBodyByContentNotHeaders() {
        Fiki.Request chunked = new Fiki.Request("POST", URL,
            Map.of("Transfer-Encoding", "chunked", "Content-Digest", Fiki.contentDigest(BODY)), null);
        Map<String, String> headers = respond(opts -> opts.withCovered(plus(Fiki.RESPONSE_MINIMUM, "content-digest")),
            200, chunked, Map.of());
        assertEquals(KEY.aid(), check(headers, 200, RESPONSE_BODY, chunked,
            opts -> opts.withMinimum(Fiki.RESPONSE_MINIMUM)).aid());
    }

    @Test
    void aHeadResponseCarryingAContentLengthHasNoBody() {
        Fiki.Request head = new Fiki.Request("HEAD", URL, Map.of(), null);
        Map<String, String> headers = respond(opts -> opts.withBody(null), 200, head, Map.of("Content-Length", "898"));
        assertFalse(check(headers, 200, null, head, opts -> opts.withMinimum(Fiki.RESPONSE_MINIMUM))
            .covered().contains("content-digest"));
    }

    /* ------------------------------------------- the first review and draft 6 (@2f227n4r) */

    @Test
    void aDefaultResponseDoesNotBindARequestBodyOnlyItsHeadersAnnounce() {
        Fiki.Request asked = new Fiki.Request("POST", URL,
            Map.of("Content-Length", "18", "Content-Digest", Fiki.contentDigest(BODY)), null);
        Map<String, String> headers = respond(opts -> opts, 200, asked, Map.of());
        assertFalse(check(headers, 200, RESPONSE_BODY, asked, opts -> opts.withMinimum(Fiki.RESPONSE_MINIMUM))
            .covered().contains(Fiki.req("content-digest")));
    }

    @Test
    void aDefaultResponseToABodyWithNoDigestToBindIsRefusedAtSigning() {
        Fiki.Request asked = new Fiki.Request("POST", URL, Map.of(), BODY);
        assertEquals(FikiException.Kind.UncoveredBody, kindOf(() -> respond(opts -> opts, 200, asked, Map.of())));
    }

    @Test
    void aMissingKeyidIsReportedBeforeTheCoveredList() {
        Signed s = sign(opts -> opts.withCovered(List.of("@method", "content-digest")).withKeyid(AID))
            .mangle(";keyid=\"" + AID + "\"", "");
        assertEquals(FikiException.Kind.MissingKey, kindOf(() ->
            verify(s, opts -> opts.withResolver(only(AID, raw(KEY))).withMinimum(Fiki.REQUEST_MINIMUM))));
    }

    @Test
    void aMissingKeyidIsReportedBeforeTheLabels() {
        Signed s = sign(opts -> opts.withKeyid(AID)).mangle(";keyid=\"" + AID + "\"", "");
        String value = s.headers().get("Signature-Input").split("=", 2)[1];
        s.headers().put("Signature-Input", s.headers().get("Signature-Input") + ", other=" + value);
        assertEquals(FikiException.Kind.MissingKey, kindOf(() -> verify(s, opts -> opts.withResolver(only(AID, raw(KEY))))));
    }

    @Test
    void aMissingKeyidIsFineWhenTheVerifierNamesTheKey() {
        Signed s = sign();
        s.mangle(";keyid=\"" + s.keyid() + "\"", "");
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> verify(s, opts -> opts.withExpectedAid(KEY.aid()))));
    }

    @Test
    void aSignerGivenAMinimumRefusesACoveredListBelowIt() {
        assertEquals(FikiException.Kind.InsufficientCoverage, kindOf(() ->
            sign(opts -> opts.withBody(null).withCovered(List.of("@method", "@path")).withMinimum(Fiki.REQUEST_MINIMUM))));
        Signed s = sign(opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM));
        assertEquals(KEY.aid(), verify(s, opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM)).aid());
    }

    @Test
    void aSignerGivenAMinimumRefusesABodyItWouldNotCover() {
        assertEquals(FikiException.Kind.InsufficientCoverage, kindOf(() ->
            sign(KEY, "POST", URL, Map.of("Transfer-Encoding", "chunked"),
                Fiki.SignOptions.none().withMinimum(Fiki.REQUEST_MINIMUM))));
    }

    @Test
    void aResponseSignerGivenAMinimumRefusesACoveredListBelowIt() {
        assertEquals(FikiException.Kind.InsufficientCoverage, kindOf(() ->
            respond(opts -> opts.withCovered(List.of("@status", "content-digest")).withMinimum(Fiki.RESPONSE_MINIMUM))));
        assertEquals(KEY.aid(), check(respond(opts -> opts.withMinimum(Fiki.RESPONSE_MINIMUM)),
            opts -> opts.withMinimum(Fiki.RESPONSE_MINIMUM)).aid());
    }

    @Test
    void aResponseFromAnAidOtherThanTheExpectedOneIsAnUnknownKey() {
        Map<String, String> headers = respond(opts -> opts.withKeyid(AID));
        assertEquals(AID, check(headers, opts -> opts.withResolver(only(AID, raw(KEY))).withExpectedKeyid(AID)).keyid());
        String stranger = cesr("E", new byte[32]);
        assertEquals(FikiException.Kind.UnknownKey, kindOf(() ->
            check(headers, opts -> opts.withResolver(only(AID, raw(KEY))).withExpectedKeyid(stranger))));
    }

    @Test
    void aCoveredAuthorityOutsideTheServedSetIsASignatureMismatch() {
        Signed s = sign(KEY, "POST", "/identifiers", Map.of("Host", "other.example.com"),
            Fiki.SignOptions.none().withBody(BODY));
        assertEquals(KEY.aid(), verify(s, opts -> opts.withAuthorities(Set.of("other.example.com"))).aid());
        assertEquals(FikiException.Kind.SignatureMismatch,
            kindOf(() -> verify(s, opts -> opts.withAuthorities(Set.of("keria.example.com")))));
    }

    /* --------- supplying authorities makes @authority required (@605z9tnw, tick 7zde) */

    @Test
    void aRequestSignedForAnotherHostWithoutAuthorityIsRefusedGivenAuthorities() {
        // The cross-host replay: a GET signed for attacker.example under the request minimum,
        // which omits @authority, presented to a verifier that serves only victim.example.
        Signed signed = sign(KEY, "GET", "https://attacker.example/identifiers?type=rot", Map.of(),
            Fiki.SignOptions.none().withCovered(Fiki.REQUEST_MINIMUM).withMinimum(Fiki.REQUEST_MINIMUM));
        Signed replayed = new Signed("GET", "https://victim.example/identifiers?type=rot", null, signed.headers());
        FikiException e = thrown(() -> verify(replayed,
            opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM).withAuthorities(Set.of("victim.example"))));
        assertEquals(FikiException.Kind.InsufficientCoverage, e.kind());
        assertEquals("@authority", e.detail());
    }

    @Test
    void withoutAuthoritiesAnUncoveredAuthorityStillVerifies() {
        Signed s = sign(opts -> opts.withCovered(List.of("@method", "@path", "@query", "content-digest")));
        assertEquals(KEY.aid(), verify(s).aid());
    }

    @Test
    void anUncoveredAuthorityUnderAuthoritiesIsRefusedBeforeTheKeyIsResolved() {
        Signed s = sign(opts -> opts.withKeyid(AID).withCovered(List.of("@method", "@path", "@query", "content-digest")));
        assertEquals(FikiException.Kind.InsufficientCoverage, kindOf(() -> verify(s,
            opts -> opts.withResolver(keyid -> null).withAuthorities(Set.of("keria.example.com")))));
    }

    @Test
    void aCoveredAuthorityUnderAuthoritiesVerifiesForTheRightHostOnly() {
        List<String> covered = new ArrayList<>(Fiki.REQUEST_MINIMUM);
        covered.add("@authority");
        Signed s = sign(KEY, "GET", "https://victim.example/identifiers", Map.of(),
            Fiki.SignOptions.none().withCovered(covered));
        assertEquals(KEY.aid(), verify(s, opts -> opts.withAuthorities(Set.of("victim.example"))).aid());
        assertEquals(FikiException.Kind.SignatureMismatch,
            kindOf(() -> verify(s, opts -> opts.withAuthorities(Set.of("attacker.example")))));
    }

    @Test
    void servedAuthoritiesAreARequestPolicyAndAResponseVerifierRefusesThem() {
        // @24tvlxgd: one VerifyOptions serves both directions, and a set option that a direction
        // would silently ignore is the caller's mistake rather than a policy that did not run.
        assertThrows(IllegalArgumentException.class, () ->
            check(respond(), opts -> opts.withAuthorities(Set.of("keria.example.com"))));
    }

    @Test
    void anUnsigned401IsUnauthenticatedBeforeAnythingElse() {
        assertEquals(FikiException.Kind.Unauthenticated, kindOf(() -> check(Map.of("Content-Type", "application/json"),
            401, "{\"title\": \"no\"}".getBytes(StandardCharsets.UTF_8), REQUEST, opts -> opts)));
    }

    @Test
    void anUnsigned200IsMissingItsSignature() {
        assertEquals(FikiException.Kind.MissingSignature, kindOf(() -> check(Map.of(), 200, RESPONSE_BODY, REQUEST, opts -> opts)));
    }

    @Test
    void aSigned401IsVerifiedLikeAnyOtherResponse() {
        Map<String, String> headers = respond(opts -> opts, 401, REQUEST, Map.of());
        assertEquals(KEY.aid(), check(headers, 401, RESPONSE_BODY, REQUEST, opts -> opts).aid());
    }

    @ParameterizedTest
    @ValueSource(strings = {"café", "two\nlines", "bell\u0007"})
    void aBaseThatCannotBeBuiltIsASignatureMismatch(String value) {
        Signed s = signWith(Map.of("X-Note", "plain"),
            opts -> opts.withCovered(List.of("@method", "@path", "@query", "x-note", "content-digest")));
        s.headers().put("X-Note", value);
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> verify(s)));
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> Fiki.signatureBase("GET", URL,
            Map.of("X-Note", value), List.of("x-note"), Fiki.Params.of(AT, "k"))));
    }

    @Test
    void aTabInAFieldValueStillBuilds() {
        Signed s = signWith(Map.of("X-Note", "a\tb"),
            opts -> opts.withCovered(List.of("@method", "@path", "@query", "x-note", "content-digest")));
        assertEquals(KEY.aid(), verify(s).aid());
    }

    /* --------------------------------------- created is required under a minimum (@7p9s3g9k) */

    private static Signed withoutCreated() {
        return sign().mangle(";created=" + AT, "");
    }

    @Test
    void aMinimumRequiresCreatedAsPartOfSignatureInput() {
        Signed s = withoutCreated();
        assertEquals(FikiException.Kind.MalformedSignatureInput,
            kindOf(() -> verify(s, opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM))));
    }

    @Test
    void aMissingCreatedUnderAMinimumIsReportedBeforeTheCoveredList() {
        Signed s = withoutCreated().mangle("\"@path\"", "\"@path\" \"@path\"");
        assertEquals(FikiException.Kind.MalformedSignatureInput,
            kindOf(() -> verify(s, opts -> opts.withMinimum(Fiki.REQUEST_MINIMUM))));
    }

    @Test
    void withoutAMinimumCreatedStaysOptionalAsRfc9421MakesIt() {
        Signed s = withoutCreated();
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> verify(s)));
    }

    /* ------------------------- a covered "content-digest";req is recomputed (bakobo/fiki#4) */

    private static final Fiki.Request SWAPPED = new Fiki.Request("POST", URL, REQUEST.headers(),
        "{\"hello\": \"mallory\"}".getBytes(StandardCharsets.UTF_8));

    @Test
    void aSwappedRequestBodyIsRefusedWhenTheResponseBindsItsDigest() {
        assertEquals(FikiException.Kind.DigestMismatch,
            kindOf(() -> check(respond(), 200, RESPONSE_BODY, SWAPPED, opts -> opts)));
    }

    @Test
    void anUnreadableRequestDigestIsMalformedWhenTheResponseBindsIt() {
        List<String> covered = plus(Fiki.RESPONSE_MINIMUM, Fiki.req("content-digest"), "content-digest");
        Fiki.Request unread = new Fiki.Request("POST", URL, Map.of("Content-Digest", "(((("), null);
        Map<String, String> headers = respond(opts -> opts.withCovered(covered), 200, unread, Map.of());
        Fiki.Request odd = new Fiki.Request("POST", URL, Map.of("Content-Digest", "(((("), BODY);
        assertEquals(FikiException.Kind.MalformedDigest, kindOf(() -> check(headers, 200, RESPONSE_BODY, odd, opts -> opts)));
        // Section 9 again: the malformed request digest outranks a mismatched response digest.
        assertEquals(FikiException.Kind.MalformedDigest, kindOf(() -> check(headers, 200,
            "{\"done\": false}".getBytes(StandardCharsets.UTF_8), odd, opts -> opts)));
    }

    @Test
    void aSignerWillNotBindARequestDigestItsBodyContradicts() {
        assertEquals(FikiException.Kind.DigestMismatch, kindOf(() -> respond(opts -> opts, 200, SWAPPED, Map.of())));
        Fiki.Request odd = new Fiki.Request("POST", URL, Map.of("Content-Digest", "(((("), BODY);
        assertEquals(FikiException.Kind.MalformedDigest, kindOf(() -> respond(opts -> opts, 200, odd, Map.of())));
    }

    @Test
    void aSignerChecksABoundRequestDigestAgainstAnEmptyBodyToo() {
        List<String> covered = plus(Fiki.RESPONSE_MINIMUM, Fiki.req("content-digest"), "content-digest");
        Fiki.Request empty = new Fiki.Request("POST", URL, REQUEST.headers(), new byte[0]);
        assertEquals(FikiException.Kind.DigestMismatch,
            kindOf(() -> respond(opts -> opts.withCovered(covered), 200, empty, Map.of())));
    }

    @Test
    void aBoundRequestDigestWithNoRequestBodyToCheckIsACallerError() {
        Fiki.Request bodiless = new Fiki.Request("POST", URL, REQUEST.headers(), null);
        assertThrows(IllegalArgumentException.class, () -> check(respond(), 200, RESPONSE_BODY, bodiless, opts -> opts));
    }

    /* ----------------------------- a supplied minimum can only add to the profile's (fiki#4) */

    @Test
    void aRequestMinimumBelowTheProfilesIsACallerError() {
        for (List<String> minimum : List.of(List.<String>of(), List.of("@method", "@path"), List.of(Fiki.req("@method")))) {
            Signed s = sign();
            assertThrows(IllegalArgumentException.class, () -> verify(s, opts -> opts.withMinimum(minimum)));
            assertThrows(IllegalArgumentException.class, () -> sign(opts -> opts.withMinimum(minimum)));
        }
    }

    @Test
    void aResponseMinimumBelowTheProfilesIsACallerError() {
        for (List<String> minimum : List.of(List.<String>of(), Fiki.REQUEST_MINIMUM, List.of("@status", Fiki.req("@method")))) {
            Map<String, String> headers = respond();
            assertThrows(IllegalArgumentException.class, () -> check(headers, opts -> opts.withMinimum(minimum)));
            assertThrows(IllegalArgumentException.class, () -> respond(opts -> opts.withMinimum(minimum)));
        }
    }

    @Test
    void aMinimumMayAddRequirementsBeyondTheProfiles() {
        List<String> stricter = plus(Fiki.REQUEST_MINIMUM, "@authority");
        assertEquals(KEY.aid(), verify(sign(), opts -> opts.withMinimum(stricter)).aid());
        Signed narrow = sign(opts -> opts.withCovered(plus(Fiki.REQUEST_MINIMUM, "content-digest")));
        assertEquals(FikiException.Kind.InsufficientCoverage, kindOf(() -> verify(narrow, opts -> opts.withMinimum(stricter))));
    }

    /* ---------------------- the authority, split as py does except IPv6 (@8yucn7nv) */

    private static String authority(String url) {
        return firstLine(Fiki.signatureBase("GET", url, Map.of(), List.of("@authority"), Fiki.Params.of(AT, "k")));
    }

    @Test
    void theAuthorityIsSplitAsSent() {
        assertEquals("\"@authority\": example.com", authority("https://user:pw@Example.COM/f"));
        assertEquals("\"@authority\": example.com", authority("https://example.com:0443/f"));
        assertEquals("\"@authority\": example.com", authority("https://example.com:/f"));
        assertEquals("\"@authority\": example.com:80", authority("https://example.com:80/f"));
        assertEquals("\"@authority\": example.com", authority("http://example.com:80/f"));
        assertEquals("\"@authority\": example.com:0", authority("http://example.com:0/f"));
        assertEquals("\"@authority\": example.com:65535", authority("unknown://example.com:65535/f"));
        assertEquals("\"@authority\": [::1]:8443", authority("https://[::1]:8443/f"));
        assertEquals("\"@authority\": [::1]", authority("https://[::1]:443/f"));
        assertEquals("\"@authority\": [::1]", authority("https://[::1]/f"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://example.com:http/f", "https://example.com:65536/f", "https://example.com:99999999999999999999/f",
        "https://[::1/f", "https://[::1]x/f", "https://example.com:-1/f",
    })
    void anAuthorityWithNoReadablePortIsTheCallersMistake(String url) {
        assertThrows(IllegalArgumentException.class, () -> authority(url));
    }

    @Test
    void thePathAndQueryAreTakenAsSent() {
        String[] lines = new String(Fiki.signatureBase("GET", "https://x.example/a/../b%2Fc?x=%20y", Map.of(),
            List.of("@path", "@query"), Fiki.Params.of(AT, "k")), StandardCharsets.UTF_8).split("\n");
        assertEquals("\"@path\": /a/../b%2Fc", lines[0]);
        assertEquals("\"@query\": ?x=%20y", lines[1]);
        // A fragment is no part of a request target, so format 3 refuses it rather than dropping it.
        assertThrows(IllegalArgumentException.class, () -> Fiki.signatureBase("GET", "https://x.example/a?x=1#frag",
            Map.of(), List.of("@path", "@query"), Fiki.Params.of(AT, "k")));
    }

    /* ------------------------------------ RFC 8941 read as http_sfv reads it (@8yucn7nv) */

    @Test
    void anIntegerHasAtMostFifteenDigits() {
        Sfv.parseDictionary("a=999999999999999");
        Sfv.parseDictionary("a=-999999999999999");
        assertThrows(Sfv.SyntaxException.class, () -> Sfv.parseDictionary("a=1000000000000000"));
        Signed s = sign().mangle(";created=" + AT, ";created=1000000000000000");
        assertEquals(FikiException.Kind.MalformedSignatureInput, kindOf(() -> verify(s)));
    }

    @Test
    void decimalsAndTokensAreRead() {
        assertEquals(new Sfv.Token("abc/d:e*"), Sfv.parseDictionary("a=abc/d:e*").get(0).value());
        assertEquals(new Sfv.Token("*x"), Sfv.parseDictionary("a=*x").get(0).value());
        assertEquals("1.5", Sfv.serializeBareItem(Sfv.parseDictionary("a=1.5").get(0).value()));
        assertEquals("-123456789012.123", Sfv.serializeBareItem(Sfv.parseDictionary("a=-123456789012.123").get(0).value()));
        assertEquals("5.0", Sfv.serializeBareItem(new java.math.BigDecimal("5")));
        for (String bad : List.of("a=1.", "a=1.1234", "a=1234567890123.1", "a=-", "a=-a")) {
            assertThrows(Sfv.SyntaxException.class, () -> Sfv.parseDictionary(bad), bad);
        }
    }

    @Test
    void aStringIsVisibleAsciiAndSpaceOnly() {
        assertEquals("a b~", Sfv.parseDictionary("a=\"a b~\"").get(0).value());
        for (String bad : List.of("a=\"café\"", "a=\"tab\there\"", "a=\"del\u007f\"")) {
            assertThrows(Sfv.SyntaxException.class, () -> Sfv.parseDictionary(bad), bad);
        }
    }

    @Test
    void innerListItemsCarryTheirOwnParametersAndARepeatedParameterOverwrites() {
        Sfv.InnerList list = (Sfv.InnerList) Sfv.parseDictionary("a=(\"@path\";req \"x\";k=1;k=2 1);p=1;p=?0").get(0).value();
        assertEquals(Boolean.TRUE, list.items().get(0).param("req"));
        assertEquals(2L, list.items().get(1).param("k"));
        assertEquals(1, list.items().get(1).params().size());
        assertEquals(Boolean.FALSE, list.param("p"));
        assertEquals("(\"@path\";req \"x\";k=2 1);p=?0", Sfv.serializeInnerList(list));
        assertEquals("?1", Sfv.serializeBareItem(Boolean.TRUE));
    }

    @Test
    void anItemParsesWholeOrNotAtAll() {
        assertEquals("@path", Sfv.parseItem(" \"@path\";req ").value());
        for (String bad : List.of("", "  ", "\"@path\" x", "\"@path")) {
            assertThrows(Sfv.SyntaxException.class, () -> Sfv.parseItem(bad), bad);
        }
    }
}
