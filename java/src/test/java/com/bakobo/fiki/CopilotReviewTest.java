package com.bakobo.fiki;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Copilot's review of bakobo/fiki#10 (this.i @3e7wnyvg). */
class CopilotReviewTest {

    private static final Key KEY = Key.fromSeed(new byte[32]);
    private static final long AT = 1_700_000_000L;

    private static String authority(String url) {
        String base = new String(Fiki.signatureBase("GET", url, Map.of(), List.of("@authority"),
            Fiki.Params.of(AT, "k")), UTF_8);
        return base.split("\n")[0];
    }

    /* ---------------------------------------------------------------------- ports */

    @Test
    void aZeroPaddedPortIsItsNumericValue() {
        assertEquals("\"@authority\": example.com", authority("http://example.com:000080/p"));
        assertEquals("\"@authority\": example.com", authority("http://example.com:00000000000000000080/p"));
        assertEquals("\"@authority\": example.com:8080", authority("http://example.com:0000000000008080/p"));
        assertEquals("\"@authority\": example.com:0", authority("http://example.com:0000/p"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"00000000000000065536", "99999999999999999999", "65536", "0x50", "８０"})
    void aPortOutsideTheRangeIsRefusedWithoutAnUncaughtException(String port) {
        String url = "https://example.com:" + port + "/p";
        assertThrows(IllegalArgumentException.class, () -> authority(url));
        Map<String, String> headers = Fiki.signRequest(KEY, "GET", "https://example.com/p", Map.of(),
            Fiki.SignOptions.none().withCreated(AT));
        FikiException e = assertThrows(FikiException.class, () ->
            Fiki.verifyRequest("GET", url, headers, Fiki.VerifyOptions.decliningFreshness()));
        assertEquals(FikiException.Kind.SignatureMismatch, e.kind());
    }

    /* ------------------------------------------- a bound request digest that is absent */

    @Test
    void aBoundRequestDigestTheRequestDoesNotCarryIsAMissingComponentAtSigning() {
        Fiki.Request asked = new Fiki.Request("POST", "https://example.com/p", Map.of(), "x".getBytes(UTF_8));
        FikiException e = assertThrows(FikiException.class, () -> Fiki.signResponse(KEY, 200, asked, Map.of(),
            Fiki.SignOptions.none().withCreated(AT).withCovered(List.of("@status", Fiki.req("content-digest")))));
        assertEquals(FikiException.Kind.MissingComponent, e.kind());
        assertEquals("\"content-digest\";req", e.detail());
    }

    /* ------------------------------------------------------ freshness is a value */

    @Test
    void noConstructorLeavesTheFreshnessDecisionUnstated() {
        assertThrows(IllegalArgumentException.class, () ->
            new Fiki.VerifyOptions(null, null, null, null, null, null, null, null, null));
        assertEquals(null, new Fiki.VerifyOptions(Fiki.Freshness.DECLINED, null, null, null, null, null, null, null, null)
            .maxAge());
        assertEquals(300L, Fiki.VerifyOptions.maxAge(300).maxAge());
    }

    @Test
    void aMaxAgeOrSkewThatIsNotPositiveIsTheCallersMistake() {
        assertThrows(IllegalArgumentException.class, () -> Fiki.VerifyOptions.maxAge(0));
        assertThrows(IllegalArgumentException.class, () -> Fiki.VerifyOptions.maxAge(-1));
        assertThrows(IllegalArgumentException.class, () -> Fiki.VerifyOptions.maxAge(300).withSkew(0));
        assertThrows(IllegalArgumentException.class, () -> Fiki.VerifyOptions.decliningFreshness().withSkew(-5));
    }

    @Test
    void theFreshnessArithmeticDoesNotWrap() {
        Map<String, String> old = Fiki.signRequest(KEY, "GET", "https://example.com/p", Map.of(),
            Fiki.SignOptions.none().withCreated(-999_999_999_999_999L).withExpires(999_999_999_999_999L));
        // maxAge + skew would wrap past Long.MAX_VALUE; it means no limit instead.
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", "https://example.com/p", old,
            Fiki.VerifyOptions.maxAge(Long.MAX_VALUE).withNow(Long.MAX_VALUE).withSkew(Long.MAX_VALUE)).aid());
        // now - created would wrap below Long.MIN_VALUE's mirror; it is simply very old.
        assertEquals(FikiException.Kind.SignatureTooOld, assertThrows(FikiException.class, () ->
            Fiki.verifyRequest("GET", "https://example.com/p", old,
                Fiki.VerifyOptions.maxAge(300).withNow(Long.MAX_VALUE))).kind());
        Map<String, String> future = Fiki.signRequest(KEY, "GET", "https://example.com/p", Map.of(),
            Fiki.SignOptions.none().withCreated(999_999_999_999_999L));
        assertEquals(FikiException.Kind.SignatureTooOld, assertThrows(FikiException.class, () ->
            Fiki.verifyRequest("GET", "https://example.com/p", future,
                Fiki.VerifyOptions.maxAge(300).withNow(Long.MIN_VALUE))).kind());
        Map<String, String> expiring = Fiki.signRequest(KEY, "GET", "https://example.com/p", Map.of(),
            Fiki.SignOptions.none().withCreated(AT).withExpires(AT));
        assertEquals(FikiException.Kind.SignatureExpired, assertThrows(FikiException.class, () ->
            Fiki.verifyRequest("GET", "https://example.com/p", expiring,
                Fiki.VerifyOptions.decliningFreshness().withNow(Long.MAX_VALUE))).kind());
    }

    /* --------------------------------------------------------- component names */

    @ParameterizedTest
    @ValueSource(strings = {"x\r\ninjected", "x-note\n", "X Note", "", "café", "\"a b\"", "a,b", "a\"b"})
    void aComponentNameThatIsNotAFieldNameIsTheCallersMistake(String spec) {
        assertThrows(IllegalArgumentException.class, () -> Fiki.signRequest(KEY, "GET", "https://example.com/p",
            Map.of(), Fiki.SignOptions.none().withCreated(AT).withCovered(List.of("@method", spec))));
        Map<String, String> headers = Fiki.signRequest(KEY, "GET", "https://example.com/p", Map.of(),
            Fiki.SignOptions.none().withCreated(AT));
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest("GET", "https://example.com/p", headers,
            Fiki.VerifyOptions.decliningFreshness().withMinimum(List.of("@method", "@path", "@query", spec))));
    }

    @Test
    void aDerivedNameIsAStringAndOrdinaryFieldNamesStillSign() {
        for (String derived : List.of("@me\nthod", "@café")) {
            assertThrows(IllegalArgumentException.class, () -> Fiki.signatureBase("GET", "https://example.com/p",
                Map.of(), List.of(derived), Fiki.Params.of(AT, "k")));
        }
        Map<String, String> sent = Map.of("X-Note!#$%&'*+.^_`|~", "v");
        String line = new String(Fiki.signatureBase("GET", "https://example.com/p", sent,
            List.of("x-note!#$%&'*+.^_`|~"), Fiki.Params.of(AT, "k")), UTF_8)
            .split("\n")[0];
        assertEquals("\"x-note!#$%&'*+.^_`|~\": v", line);
    }
}
