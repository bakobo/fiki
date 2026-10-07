package com.bakobo.fiki;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Hostile review of bakobo/fiki#10, item 4, and CodeQL on Request (this.i @2r05k9g0). */
class HeaderMapTest {

    private static final Key KEY = Key.fromSeed(new byte[32]);
    private static final String URL = "https://example.com/p";

    @Test
    void aNullValueCannotHideASecondSpellingOfTheSameName() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("host", null);
        headers.put("Host", "example.com");
        assertThrows(IllegalArgumentException.class, () -> Fiki.signRequest(KEY, "GET", "/p", headers,
            Fiki.SignOptions.none().withCreated(1)));
    }

    @Test
    void aNullNameOrValueIsTheCallersMistake() {
        Map<String, String> nullValue = new HashMap<>();
        nullValue.put("X-Note", null);
        Map<String, String> nullName = new HashMap<>();
        nullName.put(null, "v");
        for (Map<String, String> headers : java.util.List.of(nullValue, nullName)) {
            assertThrows(IllegalArgumentException.class, () -> Fiki.signRequest(KEY, "GET", URL, headers,
                Fiki.SignOptions.none().withCreated(1)));
            assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest("GET", URL, headers,
                Fiki.VerifyOptions.decliningFreshness()));
            assertThrows(IllegalArgumentException.class, () -> new Fiki.Request("GET", URL, headers, null));
        }
    }

    @Test
    void aRequestHandsOutCopiesOfWhatItHolds() {
        byte[] body = "abc".getBytes(UTF_8);
        Fiki.Request request = new Fiki.Request("POST", URL, Map.of("X", "1"), body);
        body[0] = 'z';
        assertArrayEquals("abc".getBytes(UTF_8), request.body());
        request.body()[0] = 'z';
        assertArrayEquals("abc".getBytes(UTF_8), request.body());
        assertThrows(UnsupportedOperationException.class, () -> request.headers().put("Y", "2"));
        assertEquals(Map.of("X", "1"), request.headers());
        assertEquals(null, new Fiki.Request("GET", URL, null, null).body());
    }
}
