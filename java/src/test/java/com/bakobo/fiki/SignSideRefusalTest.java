package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * A signer refuses what its own verifier would refuse, before anything is serialized (this.i
 * @2r05k9g0; hostile review of bakobo/fiki#10, items 2 and 6).
 */
class SignSideRefusalTest {

    private static final Key KEY = Key.fromSeed(new byte[32]);
    private static final String URL = "https://example.com/p";

    private static Map<String, String> sign(Fiki.SignOptions opts) {
        return Fiki.signRequest(KEY, "GET", URL, Map.of(), opts);
    }

    @ParameterizedTest
    @ValueSource(strings = {"a\r\nb", "a\nb", "tab\there", "café", "\u0000", "del\u007f"})
    void aStringParameterThatIsNotAnSfStringIsTheCallersMistake(String bad) {
        Fiki.SignOptions base = Fiki.SignOptions.none().withCreated(1);
        Caller.refused("The signature parameter keyid contains a character outside visible ASCII", () -> sign(base.withKeyid(bad)));
        Caller.refused("The signature parameter nonce contains a character outside visible ASCII", () -> sign(base.withNonce(bad)));
        Caller.refused("The signature parameter tag contains a character outside visible ASCII", () -> sign(base.withTag(bad)));
        Caller.refused("The signature parameter keyid contains a character outside visible ASCII", () -> Fiki.signatureBase("GET", URL, Map.of(),
            List.of("@method"), new Fiki.Params(1L, bad, null, null, null, null)));
        Caller.refused("The signature parameter nonce contains a character outside visible ASCII", () -> Fiki.signResponse(KEY, 200, null, Map.of(),
            base.withNonce(bad)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"a\r\nb", "Sig", "1sig", "", "a b", "sig=x"})
    void aLabelThatIsNotAnSfKeyIsTheCallersMistake(String bad) {
        Caller.refused("is not an RFC 8941 key", () -> sign(Fiki.SignOptions.none().withCreated(1).withLabel(bad)));
    }

    @Test
    void ordinaryStringsAndLabelsStillSign() {
        Map<String, String> out = sign(Fiki.SignOptions.none().withCreated(1).withNonce("n o~\"\\").withTag("app")
            .withLabel("*sig-1._x"));
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, out, OptedOut.decliningFreshness()).aid());
    }

    @Test
    void anIntegerBeyondFifteenDigitsIsTheCallersMistake() {
        long big = 1_000_000_000_000_000L;
        Caller.refused("fiki signs a timestamp from 0 to 999999999999999", () -> sign(Fiki.SignOptions.none().withCreated(big)));
        Caller.refused("fiki signs a timestamp from 0 to 999999999999999", () -> sign(Fiki.SignOptions.none().withCreated(1).withExpires(big)));
        Caller.refused("fiki signs a timestamp from 0 to 999999999999999", () -> sign(Fiki.SignOptions.none().withCreated(-big)));
        // Not negative either (@5zrf8gjk, B16): the range is 0 to fifteen nines.
        Caller.refused("fiki signs a timestamp from 0 to 999999999999999", () -> sign(Fiki.SignOptions.none().withCreated(1).withExpires(-1)));
        Map<String, String> edge = sign(Fiki.SignOptions.none().withCreated(999_999_999_999_999L)
            .withExpires(0));
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, edge, OptedOut.decliningFreshness()
            .withNow(0)).aid());
    }
}
