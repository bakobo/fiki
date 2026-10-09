package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Hostile review of bakobo/fiki#10, items 3 and 5 (this.i @2r05k9g0). */
class VerifySideRefusalTest {

    private static final Key KEY = Key.fromSeed(new byte[32]);

    @ParameterizedTest
    @ValueSource(strings = {"https://example.com:bogus/p", "https://example.com:65536/p", "https://[::1/p",
        "https://[::1]evil:443/p"})
    void aReceivedUrlWithNoReadableAuthorityIsASignatureMismatch(String received) {
        Map<String, String> headers = Fiki.signRequest(KEY, "GET", "https://example.com/p", Map.of(),
            Fiki.SignOptions.none().withCreated(1));
        FikiException e = assertThrows(FikiException.class, () ->
            Fiki.verifyRequest("GET", received, headers, OptedOut.decliningFreshness()));
        assertEquals(FikiException.Kind.SignatureMismatch, e.kind());
        // The same URL handed to a signer is still the caller's own mistake.
        assertThrows(IllegalArgumentException.class, () -> Fiki.signRequest(KEY, "GET", received, Map.of(),
            Fiki.SignOptions.none().withCreated(1)));
    }

    @Test
    void aBadPortInTheRequestAResponseAnswersIsASignatureMismatchToo() {
        Fiki.Request good = new Fiki.Request("GET", "https://example.com/p", Map.of(), null);
        Map<String, String> headers = Fiki.signResponse(KEY, 200, good, Map.of(),
            Fiki.SignOptions.none().withCreated(1).withCovered(List.of("@status", Fiki.req("@authority"))));
        Fiki.Request bad = new Fiki.Request("GET", "https://example.com:bogus/p", Map.of(), null);
        FikiException e = assertThrows(FikiException.class, () ->
            Fiki.verifyResponse(200, headers, bad, OptedOut.decliningFreshness()));
        assertEquals(FikiException.Kind.SignatureMismatch, e.kind());
    }

    @Test
    void a401WithAnEmptySignatureHeaderIsUnauthenticated() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Signature", "");
        headers.put("Signature-Input", "sig=(\"@status\");created=1;keyid=\"k\"");
        FikiException e = assertThrows(FikiException.class, () -> Fiki.verifyResponse(401, headers, null,
            OptedOut.decliningFreshness()));
        assertEquals(FikiException.Kind.Unauthenticated, e.kind());
        // Any other status with an empty Signature header is still missing its signature.
        FikiException other = assertThrows(FikiException.class, () -> Fiki.verifyResponse(200, headers, null,
            OptedOut.decliningFreshness()));
        assertEquals(FikiException.Kind.MissingSignature, other.kind());
    }
}
