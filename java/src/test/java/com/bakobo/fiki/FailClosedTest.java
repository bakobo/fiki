package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * verifyRequest fails closed by default (this.i @524c8qgv).
 *
 * <p>The shared vectors pin what the default minimum refuses and accepts. These pin the API around
 * it, which a vector cannot: authorities is a required decision, only a collection of strings is
 * one, and the opt-outs are explicit and distinct from "not stated". They also pin the Java-only
 * findings of the 2026-10-08 review: B4, the host split at the last colon, and B5, a Unicode
 * lowercase that turned U+212A KELVIN SIGN into "k".
 */
class FailClosedTest {

    private static final Key KEY = Key.fromSeed(new byte[32]);
    private static final String URL = "https://api.example.com/things?limit=1";

    private static Map<String, String> signed() {
        return Fiki.signRequest(KEY, "GET", URL, Map.of(), Fiki.SignOptions.none());
    }

    private static FikiException.Kind kindOf(Runnable body) {
        return assertThrows(FikiException.class, body::run).kind();
    }

    /* ------------------------------------------------------------ authorities is required */

    @Test
    void authoritiesHasNoDefault() {
        Fiki.VerifyOptions unstated = Fiki.VerifyOptions.decliningFreshness();
        assertEquals(null, unstated.authorities());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> Fiki.verifyRequest("GET", URL, signed(), unstated));
        assertTrue(e.getMessage().contains("withoutAuthorityCheck()"), e.getMessage());
    }

    @Test
    void theTypeRefusesAStringWhereACollectionOfHostsBelongs() throws Exception {
        // A string is a sequence of characters, and the A3 fail-open was a substring test. Java's
        // types refuse it before anything runs: no overload takes a String or a CharSequence.
        for (Method method : Fiki.VerifyOptions.class.getMethods()) {
            if (method.getName().equals("withAuthorities")) {
                assertEquals(List.of(Collection.class), List.of(method.getParameterTypes()));
            }
        }
        Method of = Fiki.Authorities.class.getMethod("of", Collection.class);
        assertFalse(of.getParameterTypes()[0].isAssignableFrom(String.class));
    }

    @Test
    void aNullCollectionOfHostsIsACallerErrorThatNamesTheOptOut() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> Fiki.VerifyOptions.decliningFreshness().withAuthorities(null));
        assertTrue(e.getMessage().contains("withoutAuthorityCheck()"), e.getMessage());
    }

    @Test
    void emptyAuthoritiesServeNoHostAndAreACallerError() {
        assertThrows(IllegalArgumentException.class, () -> Fiki.VerifyOptions.decliningFreshness().withAuthorities(Set.of()));
        assertThrows(IllegalArgumentException.class, () -> new Fiki.Authorities(Set.of()));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void anAuthorityThatIsNotAStringIsACallerError() {
        List raw = new ArrayList(List.of("api.example.com", 443));
        assertThrows(IllegalArgumentException.class, () -> Fiki.VerifyOptions.decliningFreshness().withAuthorities(raw));
        assertThrows(IllegalArgumentException.class, () -> new Fiki.Authorities(new HashSet(raw)));
        List withNull = new ArrayList();
        withNull.add(null);
        assertThrows(IllegalArgumentException.class, () -> Fiki.Authorities.of(withNull));
    }

    @Test
    void anyCollectionOfHostsServes() {
        for (Collection<String> hosts : List.<Collection<String>>of(Set.of("api.example.com"), List.of("api.example.com"),
                List.of("x.example", "api.example.com"), new TreeSet<>(Set.of("api.example.com")))) {
            assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, signed(),
                Fiki.VerifyOptions.decliningFreshness().withAuthorities(hosts)).aid());
        }
    }

    @Test
    void theHostsAreCopiedSoTheCallerCannotChangeThemAfterwards() {
        Set<String> hosts = new HashSet<>(Set.of("api.example.com"));
        Fiki.VerifyOptions opts = Fiki.VerifyOptions.decliningFreshness().withAuthorities(hosts);
        hosts.clear();
        hosts.add("elsewhere.example");
        assertEquals(Set.of("api.example.com"), opts.authorities().hosts());
        assertThrows(UnsupportedOperationException.class, () -> opts.authorities().hosts().add("x"));
    }

    @Test
    void withoutAuthorityCheckDeclinesIt() {
        Fiki.VerifyOptions opts = Fiki.VerifyOptions.decliningFreshness().withoutAuthorityCheck();
        assertEquals(Fiki.Authorities.DECLINED, opts.authorities());
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, signed(), opts).aid());
    }

    @Test
    void aResponseVerifierNeedsNoAuthoritiesAndAcceptsTheExplicitOptOut() {
        Fiki.Request asked = new Fiki.Request("GET", URL, signed(), null);
        Map<String, String> answer = Fiki.signResponse(KEY, 200, asked, Map.of(), Fiki.SignOptions.none());
        // The keyid stated, so that what each call tests is the authorities alone.
        Fiki.VerifyOptions stated = Fiki.VerifyOptions.decliningFreshness().withExpectedKeyid(KEY.keyid());
        assertEquals(KEY.aid(), Fiki.verifyResponse(200, answer, asked, stated).aid());
        assertEquals(KEY.aid(), Fiki.verifyResponse(200, answer, asked, stated.withoutAuthorityCheck()).aid());
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyResponse(200, answer, asked,
            stated.withAuthorities(Set.of("api.example.com"))));
    }

    /* ------------------------------------------------- verifyResponse fails closed (part two) */

    private static Fiki.Request asked() {
        return new Fiki.Request("GET", URL, signed(), null);
    }

    @Test
    void aResponsesExpectedKeyidHasNoDefault() {
        Fiki.Request asked = asked();
        Map<String, String> answer = Fiki.signResponse(KEY, 200, asked, Map.of(), Fiki.SignOptions.none());
        Fiki.VerifyOptions unstated = Fiki.VerifyOptions.decliningFreshness();
        assertEquals(null, unstated.expectedKeyid());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> Fiki.verifyResponse(200, answer, asked, unstated));
        assertTrue(e.getMessage().contains("withoutKeyidCheck()"), e.getMessage());
        // Checked before the message is read: an unsigned 401 does not get past it either.
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyResponse(401, Map.of(), asked, unstated));
    }

    @Test
    void withoutKeyidCheckAcceptsAnySignerAndTheVerdictNamesIt() {
        Fiki.Request asked = asked();
        Map<String, String> answer = Fiki.signResponse(KEY, 200, asked, Map.of(), Fiki.SignOptions.none());
        Fiki.VerifyOptions opts = Fiki.VerifyOptions.decliningFreshness().withoutKeyidCheck();
        assertEquals(Fiki.ExpectedKeyid.DECLINED, opts.expectedKeyid());
        assertEquals(KEY.keyid(), Fiki.verifyResponse(200, answer, asked, opts).keyid());
        // A later withExpectedKeyid replaces the decline, and holds the signer to it.
        assertEquals(FikiException.Kind.UnknownKey, kindOf(() -> Fiki.verifyResponse(200, answer, asked,
            opts.withExpectedKeyid(Key.fromSeed(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}).keyid()))));
    }

    @Test
    void anEmptyOrNullExpectedKeyidIsACallerErrorNeverTheDecline() {
        Fiki.VerifyOptions opts = Fiki.VerifyOptions.decliningFreshness();
        assertThrows(IllegalArgumentException.class, () -> opts.withExpectedKeyid(""));
        assertThrows(IllegalArgumentException.class, () -> opts.withExpectedKeyid(null));
        assertThrows(IllegalArgumentException.class, () -> new Fiki.ExpectedKeyid(""));
        // In both verify functions: a request verifier may leave it out, and still may not pass "".
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest("GET", URL, signed(),
            new Fiki.VerifyOptions(Fiki.Freshness.DECLINED, null, null, null, null, null, null,
                new Fiki.ExpectedKeyid(""), Fiki.Authorities.DECLINED)));
    }

    @Test
    void aResponsesMinimumDefaultsToTheProfilesAndOptsOutExplicitly() {
        Fiki.Request asked = asked();
        Map<String, String> statusOnly = Fiki.signResponse(KEY, 200, asked, Map.of(),
            Fiki.SignOptions.none().withCovered(List.of("@status")));
        Fiki.VerifyOptions opts = Fiki.VerifyOptions.decliningFreshness().withoutKeyidCheck();
        assertEquals(FikiException.Kind.InsufficientCoverage,
            kindOf(() -> Fiki.verifyResponse(200, statusOnly, asked, opts)));
        assertEquals(List.of("@status"), Fiki.verifyResponse(200, statusOnly, asked, opts.withoutMinimum()).covered());
        assertThrows(IllegalArgumentException.class,
            () -> Fiki.verifyResponse(200, statusOnly, asked, opts.withMinimum(List.of("@status"))));
    }

    /* ------------------------------------------------------- every untrusted value is bounded */

    private static final String HOST = "https://api.example.com/";

    @Test
    void aUrlOfExactlyTheBoundIsReadAndOneByteMoreIsNot() {
        String atBound = HOST + "p".repeat(Fiki.MAX_FIELD_BYTES - HOST.length());
        assertEquals(Fiki.MAX_FIELD_BYTES, atBound.length());
        Map<String, String> headers = Fiki.signRequest(KEY, "GET", atBound, Map.of(), Fiki.SignOptions.none());
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", atBound, headers, OptedOut.decliningFreshness()).aid());
        String over = atBound + "p";
        assertThrows(IllegalArgumentException.class,
            () -> Fiki.signRequest(KEY, "GET", over, Map.of(), Fiki.SignOptions.none()));
        assertEquals(FikiException.Kind.SignatureMismatch,
            kindOf(() -> Fiki.verifyRequest("GET", over, headers, OptedOut.decliningFreshness())));
    }

    @Test
    void theBoundIsInUtf8BytesNotCharacters() {
        // 4097 two-byte characters: 4097 characters, 8194 bytes.
        String value = "\u00e9".repeat(4097);
        Map<String, String> headers = new LinkedHashMap<>(Map.of("X-Note", value));
        FikiException e = assertThrows(FikiException.class, () -> Fiki.signRequest(KEY, "GET", URL, headers,
            Fiki.SignOptions.none().withCovered(List.of("@method", "@path", "@query", "x-note"))));
        assertEquals(FikiException.Kind.SignatureMismatch, e.kind());
        assertTrue(e.getMessage().contains("over 8192 bytes"), e.getMessage());
    }

    @Test
    void aHostOverTheBoundIsRefusedBeforeItsShapeIsRead() {
        Map<String, String> headers = new LinkedHashMap<>(Map.of("Host", "h".repeat(Fiki.MAX_FIELD_BYTES + 1)));
        FikiException e = assertThrows(FikiException.class,
            () -> Fiki.signRequest(KEY, "GET", "/p", headers, Fiki.SignOptions.none()));
        assertEquals(FikiException.Kind.SignatureMismatch, e.kind());
        assertTrue(e.getMessage().contains("over 8192 bytes"), e.getMessage());
    }

    @Test
    void contentDigestKeepsItsOwnBoundAndClass() {
        // Signed over a digest too long to read, with no body handed to the signer: the field
        // bound does not claim it on either side, and the verifier's digest parse refuses it as
        // MalformedDigest, format 2's class (@5zrf8gjk).
        Map<String, String> headers = new LinkedHashMap<>(
            Map.of("Content-Digest", "sha-256=:" + "A".repeat(Fiki.MAX_FIELD_BYTES) + ":"));
        headers.putAll(Fiki.signRequest(KEY, "POST", URL, headers,
            Fiki.SignOptions.none().withCovered(List.of("@method", "@path", "@query", "content-digest"))));
        assertEquals(FikiException.Kind.MalformedDigest,
            kindOf(() -> Fiki.verifyRequest("POST", URL, headers, OptedOut.decliningFreshness())));
    }

    /* ------------------------------------------------ errors quote at most 64 characters */

    @Test
    void anErrorQuotesAtMost64CharactersOfAnUntrustedUrlAndEscapesControls() {
        // Review A9, B9: a 5 MB URL made a 10 MB error message, and js echoed controls raw.
        String url = HOST + "p".repeat(9000);
        FikiException e = assertThrows(FikiException.class,
            () -> Fiki.verifyRequest("GET", url, signed(), OptedOut.decliningFreshness()));
        assertEquals(FikiException.Kind.SignatureMismatch, e.kind());
        assertTrue(e.getMessage().length() < 400, e.getMessage());
        assertTrue(e.getMessage().contains("cut from 9024 characters"), e.getMessage());
        FikiException control = assertThrows(FikiException.class,
            () -> Fiki.verifyRequest("GET", HOST + "a\u001bb", signed(), OptedOut.decliningFreshness()));
        assertFalse(control.getMessage().contains("\u001b"), control.getMessage());
        assertTrue(control.getMessage().contains("\\u001b"), control.getMessage());
    }

    @Test
    void shownEscapesQuotesAndCutsByCodePoint() {
        assertEquals("\"a\\\"b\\\\c\"", Fiki.shown("a\"b\\c"));
        assertEquals("nothing", Fiki.shown(null));
        String exactly = "x".repeat(64);
        assertEquals("\"" + exactly + "\"", Fiki.shown(exactly));
        // A character outside the BMP is one character, two UTF-16 units, and never split.
        String astral = "\ud83d\ude00".repeat(65);
        assertEquals("\"" + "\\ud83d\\ude00".repeat(64) + "\" (cut from 65 characters)", Fiki.shown(astral));
    }

    @Test
    void aLongKeyidIsQuotedCut() {
        Map<String, String> headers = Fiki.signRequest(KEY, "GET", URL, Map.of(),
            Fiki.SignOptions.none().withKeyid("k".repeat(2000)));
        FikiException e = assertThrows(FikiException.class,
            () -> Fiki.verifyRequest("GET", URL, headers, OptedOut.decliningFreshness()));
        assertEquals(FikiException.Kind.MalformedKey, e.kind());
        assertTrue(e.getMessage().length() < 400, e.getMessage());
        assertTrue(e.getMessage().contains("cut from 2000 characters"), e.getMessage());
    }

    /* ------------------------------------------- userinfo, created and expires, Content-Length */

    @Test
    void userinfoIsRefusedNotStripped() {
        String url = "https://user@api.example.com/things";
        assertThrows(IllegalArgumentException.class,
            () -> Fiki.signRequest(KEY, "GET", url, Map.of(), Fiki.SignOptions.none()));
        Map<String, String> headers = Fiki.signRequest(KEY, "GET", "https://api.example.com/things", Map.of(),
            Fiki.SignOptions.none());
        FikiException e = assertThrows(FikiException.class,
            () -> Fiki.verifyRequest("GET", url, headers, OptedOut.decliningFreshness()));
        assertEquals(FikiException.Kind.SignatureMismatch, e.kind());
        assertTrue(e.getMessage().contains("user information"), e.getMessage());
    }

    @Test
    void createdAndExpiresOfZeroAreValid() {
        // A port testing them for truthiness gets both wrong (@524c8qgv).
        Map<String, String> headers = Fiki.signRequest(KEY, "GET", URL, Map.of(),
            Fiki.SignOptions.none().withCreated(0).withExpires(0));
        assertTrue(headers.get("Signature-Input").contains(";created=0;expires=0;"), headers.get("Signature-Input"));
        assertEquals(FikiException.Kind.SignatureExpired, kindOf(() -> Fiki.verifyRequest("GET", URL, headers,
            OptedOut.decliningFreshness().withNow(1_000))));
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, headers, OptedOut.decliningFreshness().withNow(0)).aid());
    }

    @Test
    void aContentLengthPastEighteenDigitsAnnouncesABodyWithoutBeingParsed() {
        String nineteen = "1" + "0".repeat(18);
        String padded = "0".repeat(5000) + "1";
        for (String length : List.of(nineteen, "9".repeat(5000), padded)) {
            Map<String, String> headers = new LinkedHashMap<>(signed());
            headers.put("Content-Length", length);
            assertEquals(FikiException.Kind.InsufficientCoverage, kindOf(() -> Fiki.verifyRequest("GET", URL, headers,
                Fiki.VerifyOptions.decliningFreshness().withoutAuthorityCheck())), length.substring(0, Math.min(20, length.length())));
        }
        Map<String, String> zeroes = new LinkedHashMap<>(signed());
        zeroes.put("Content-Length", "0".repeat(5000));
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, zeroes,
            Fiki.VerifyOptions.decliningFreshness().withoutAuthorityCheck()).aid());
    }

    /* ---------------------------------------------------------------------- review B8 */

    @Test
    void toAidRefusesAKeyThatIsNot32Bytes() {
        assertThrows(IllegalArgumentException.class, () -> Key.toAid(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> Key.toAid(new byte[33]));
        assertThrows(IllegalArgumentException.class, () -> Key.toAid(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> Key.toAid(null));
        assertEquals(KEY.aid(), Key.toAid(Key.verifyingKeyBytes(KEY.aid())));
    }

    /* ------------------------------------------------------------------ the default minimum */

    @Test
    void theDefaultMinimumIsFikisOwnSigningDefaultAndCoversTheProfiles() {
        assertEquals(Fiki.DEFAULT_COVERED, Fiki.DEFAULT_MINIMUM);
        assertTrue(Fiki.DEFAULT_MINIMUM.containsAll(Fiki.REQUEST_MINIMUM));
    }

    @Test
    void anUnstatedMinimumIsTheDefaultAndTheOptOutIsDistinctFromIt() {
        Map<String, String> narrow = Fiki.signRequest(KEY, "GET", URL, Map.of(),
            Fiki.SignOptions.none().withCovered(List.of("@method", "@path", "@query")));
        Fiki.VerifyOptions declined = Fiki.VerifyOptions.decliningFreshness().withoutAuthorityCheck();
        assertEquals(null, declined.minimum());
        assertEquals(FikiException.Kind.InsufficientCoverage, kindOf(() -> Fiki.verifyRequest("GET", URL, narrow, declined)));
        assertEquals(Fiki.Minimum.DECLINED, declined.withoutMinimum().minimum());
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, narrow, declined.withoutMinimum()).aid());
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, narrow, declined.withMinimum(Fiki.REQUEST_MINIMUM)).aid());
    }

    @Test
    void aNullMinimumIsACallerErrorThatNamesTheOptOut() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> Fiki.VerifyOptions.decliningFreshness().withMinimum(null));
        assertTrue(e.getMessage().contains("withoutMinimum()"), e.getMessage());
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void aMinimumHoldingSomethingOtherThanAStringIsACallerError() {
        List raw = new ArrayList(List.of("@method", 7));
        assertThrows(IllegalArgumentException.class, () -> Fiki.VerifyOptions.decliningFreshness().withMinimum(raw));
    }

    @Test
    void aStatedMinimumIsCopied() {
        List<String> minimum = new ArrayList<>(Fiki.REQUEST_MINIMUM);
        Fiki.VerifyOptions opts = Fiki.VerifyOptions.decliningFreshness().withMinimum(minimum);
        minimum.clear();
        assertEquals(Fiki.REQUEST_MINIMUM, opts.minimum().components());
    }

    /* ----------------------------------------------- targets and Host (B4, B5, @524c8qgv) */

    private static String authority(String url, Map<String, String> headers) {
        String base = new String(Fiki.signatureBase("GET", url, headers, List.of("@authority"),
            new Fiki.Params(null, null, null, null, null, null)), StandardCharsets.UTF_8);
        return base.substring("\"@authority\": ".length(), base.indexOf('\n'));
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://a:1:2/p", "https://::1/p", "https://a::/p"})
    void aHostIsSplitFromItsPortAtTheFirstColon(String url) {
        assertThrows(IllegalArgumentException.class, () -> authority(url, Map.of()));
        assertEquals(FikiException.Kind.SignatureMismatch,
            kindOf(() -> Fiki.verifyRequest("GET", url, signed(), OptedOut.decliningFreshness())));
    }

    @Test
    void aSchemeIsAsciiLettersDigitsAndPlusMinusDot() {
        assertEquals("x.example:443", authority("git+ssh://x.example:443/f", Map.of()));
        for (String url : List.of("héttps://x.example/f", "1https://x.example/f", "://x.example/f", "x.example/f")) {
            assertThrows(IllegalArgumentException.class, () -> authority(url, Map.of()), url);
        }
    }

    @Test
    void theKelvinSignIsNotLowercasedIntoAK() {
        // U+212A lowercases to "k" under String.toLowerCase; fiki lowercases ASCII only (B5). In a
        // URL it is a host that is not ASCII, an unreadable target and so the signer's mistake, as
        // in fiki-py; in a Host header it is a value no base can carry.
        IllegalArgumentException unreadable = assertThrows(IllegalArgumentException.class,
            () -> authority("https://Keria.example/p", Map.of()));
        assertTrue(unreadable.getMessage().contains("its host is not ASCII"), unreadable.getMessage());
        assertEquals(FikiException.Kind.SignatureMismatch,
            kindOf(() -> authority("/p", Map.of("Host", "Keria.example"))));
        // A header named with it is not the ASCII field it imitates, so a signature covering that
        // field finds no value for it.
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Key", "v");
        assertEquals(FikiException.Kind.MissingComponent, kindOf(() -> Fiki.signatureBase("GET", URL, headers,
            List.of("x-key"), new Fiki.Params(null, null, null, null, null, null))));
    }

    @Test
    void anOriginFormTargetTakesHostAndKeepsItsPort() {
        assertEquals("api.example.com:443", authority("/p", Map.of("Host", "API.example.com:443")));
        assertEquals("api.example.com:80", authority("/p", Map.of("Host", "api.example.com:080")));
        assertEquals("[::1]:8443", authority("/p", Map.of("Host", " [::1]:8443 ")));
        assertEquals("api.example.com", authority("//api.example.com/p", Map.of("Host", "api.example.com")));
    }

    @Test
    void anEmptyHostIsAnEmptyAuthorityAsBefore() {
        // The brief pins no behaviour for an empty Host; this port keeps 0.8's, an empty value.
        assertEquals("", authority("/p", Map.of("Host", "")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"user@api.example.com", "a.example, b.example", "api.example.com:99999",
        "api.example.com:x", "[::1", "[::1]x", "[nope]", "a]b", "a:1:2"})
    void aHostThatIsNotASingleHostAndPortCannotBeRead(String host) {
        assertThrows(IllegalArgumentException.class, () -> authority("/p", Map.of("Host", host)));
        Map<String, String> headers = new LinkedHashMap<>(Fiki.signRequest(KEY, "GET", "/p", Map.of("Host", "api.example.com"),
            Fiki.SignOptions.none()));
        headers.put("Host", host);
        assertEquals(FikiException.Kind.SignatureMismatch,
            kindOf(() -> Fiki.verifyRequest("GET", "/p", headers, OptedOut.decliningFreshness())));
    }

    @Test
    void aTargetIsReadOnlyWhenACoveredComponentNeedsIt() {
        // As in every other port: a signature over @method alone builds no part of the target.
        Map<String, String> headers = Fiki.signRequest(KEY, "GET", URL, Map.of(),
            Fiki.SignOptions.none().withCovered(List.of("@method")));
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", "not a target#at all", headers,
            OptedOut.decliningFreshness()).aid());
    }
}
