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
        assertEquals(KEY.aid(), Fiki.verifyResponse(200, answer, asked, Fiki.VerifyOptions.decliningFreshness()).aid());
        assertEquals(KEY.aid(), Fiki.verifyResponse(200, answer, asked,
            Fiki.VerifyOptions.decliningFreshness().withoutAuthorityCheck()).aid());
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyResponse(200, answer, asked,
            Fiki.VerifyOptions.decliningFreshness().withAuthorities(Set.of("api.example.com"))));
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
        // U+212A lowercases to "k" under String.toLowerCase; fiki lowercases ASCII only (B5).
        assertEquals(FikiException.Kind.SignatureMismatch,
            kindOf(() -> authority("https://Keria.example/p", Map.of())));
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
