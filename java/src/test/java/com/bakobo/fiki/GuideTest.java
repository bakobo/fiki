package com.bakobo.fiki;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** Runs the samples in docs/user-guide.md, so a reader's copy-paste works. */
class GuideTest {

    @Test
    void theGuidesSamplesRun() {
        Key key = Key.generate();
        assertEquals(44, key.aid().length());

        String url = "https://api.example.com/things?limit=1";
        byte[] body = "{\"hello\": \"world\"}".getBytes(UTF_8);
        Map<String, String> headers = Fiki.signRequest(key, "POST", url, Map.of(),
            Fiki.SignOptions.none().withBody(body));

        Fiki.Verdict verdict = Fiki.verifyRequest("POST", url, headers,
            Fiki.VerifyOptions.maxAge(300).withBody(body));
        assertEquals(key.aid(), verdict.aid());
    }
}
