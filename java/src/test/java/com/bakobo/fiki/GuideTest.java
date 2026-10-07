package com.bakobo.fiki;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Runs the samples in docs/user-guide.md, and the KERI-profile samples for the Java port, so a
 * reader's copy-paste works. Each KERI test below is one snippet of the guide, kept in the same
 * words, and uses the controller and agent of vectors/keri/requests.json so its values are real.
 */
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

    /* The KERI profile: the controller signs a request under its AID, the agent answers. */

    private static final String CONTROLLER_SEED = "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021";
    private static final String AGENT_SEED = "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122";

    /** (a) Signing a request with a KERI AID as the keyid. */
    private static Map<String, String> snippetA(String url, byte[] body) {
        Key key = Key.fromSeed(HexFormat.of().parseHex(CONTROLLER_SEED));
        String aid = "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx";   // whose current key is `key`

        Map<String, String> headers = Fiki.signRequest(key, "POST", url, Map.of(),
            Fiki.SignOptions.none().withBody(body).withKeyid(aid).withMinimum(Fiki.REQUEST_MINIMUM));
        return headers;
    }

    /** Stands in for a KEL: each AID to the raw bytes of its current signing key. */
    private static Map<String, byte[]> keyState() {
        Map<String, byte[]> state = new LinkedHashMap<>();
        state.put("ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx",
            Key.verifyingKeyBytes(Key.fromSeed(HexFormat.of().parseHex(CONTROLLER_SEED)).aid()));
        state.put("EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6",
            Key.verifyingKeyBytes(Key.fromSeed(HexFormat.of().parseHex(AGENT_SEED)).aid()));
        return state;
    }

    @Test
    void snippetsAAndBSignAndVerifyARequestUnderAnAid() {
        String url = "https://keria.example.com/identifiers";
        byte[] body = "{\"name\": \"alice\"}".getBytes(UTF_8);
        Map<String, String> headers = snippetA(url, body);
        Map<String, byte[]> keyState = keyState();

        // (b) Verifying with a resolver.
        Fiki.Resolver resolver = keyid -> keyState.get(keyid);   // 32 raw bytes, or null if unknown
        Fiki.Verdict verdict = Fiki.verifyRequest("POST", url, headers,
            Fiki.VerifyOptions.maxAge(300).withBody(body).withResolver(resolver)
                .withMinimum(Fiki.REQUEST_MINIMUM));
        String signer = verdict.keyid();   // the AID the resolver vouched for

        assertEquals("ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx", signer);
        assertEquals(List.of("@method", "@authority", "@path", "@query", "content-digest"), verdict.covered());
    }

    @Test
    void snippetsCAndDSignAndVerifyAResponse() {
        String url = "https://keria.example.com/identifiers";
        byte[] body = "{\"name\": \"alice\"}".getBytes(UTF_8);
        Map<String, String> requestHeaders = snippetA(url, body);
        Fiki.Resolver resolver = keyState()::get;

        // (c) Signing a response, bound to the request it answers.
        Key agent = Key.fromSeed(HexFormat.of().parseHex(AGENT_SEED));
        String agentAid = "EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6";
        byte[] responseBody = "{\"done\": true}".getBytes(UTF_8);

        Fiki.Request asked = new Fiki.Request("POST", url, requestHeaders, body);
        Map<String, String> responseHeaders = Fiki.signResponse(agent, 201, asked, Map.of(),
            Fiki.SignOptions.none().withBody(responseBody).withKeyid(agentAid)
                .withMinimum(Fiki.RESPONSE_MINIMUM));

        // (d) Verifying a response, from the agent this client is talking to.
        Fiki.Verdict answer = Fiki.verifyResponse(201, responseHeaders, asked,
            Fiki.VerifyOptions.maxAge(300).withBody(responseBody).withResolver(resolver)
                .withExpectedKeyid(agentAid).withMinimum(Fiki.RESPONSE_MINIMUM));

        assertEquals(agentAid, answer.keyid());
        assertEquals(List.of("@status", "\"@method\";req", "\"@path\";req", "\"@query\";req",
            "content-digest", "\"content-digest\";req"), answer.covered());
    }

    /** (e) The refusals the KERI profile added, discriminated by kind. */
    private static String snippetE(Runnable verifying) {
        try {
            verifying.run();
            return "verified";
        } catch (FikiException e) {
            return switch (e.kind()) {
                case UnknownKey -> "no key state for " + e.detail();
                case UnsupportedSigner -> "no single signer for " + e.detail();
                case InsufficientCoverage -> "does not cover " + e.detail();
                case DuplicateComponent -> "covers " + e.detail() + " twice";
                case Unauthenticated -> "refused before the agent was known";
                default -> e.kind().name();
            };
        }
    }

    @Test
    void snippetEDiscriminatesTheNewRefusals() {
        String url = "https://keria.example.com/identifiers";
        byte[] body = "{\"name\": \"alice\"}".getBytes(UTF_8);
        Map<String, String> headers = snippetA(url, body);
        Fiki.VerifyOptions policy = Fiki.VerifyOptions.maxAge(300).withBody(body).withMinimum(Fiki.REQUEST_MINIMUM);

        assertEquals("no key state for ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx", snippetE(() ->
            Fiki.verifyRequest("POST", url, headers, policy.withResolver(keyid -> null))));

        // A resolver refuses a key state with no single signer in fiki's own terms.
        Fiki.Resolver group = keyid -> {
            throw new FikiException(FikiException.Kind.UnsupportedSigner,
                "The key state of " + keyid + " needs two signatures.", keyid);
        };
        assertEquals("no single signer for ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx", snippetE(() ->
            Fiki.verifyRequest("POST", url, headers, policy.withResolver(group))));

        Map<String, String> narrow = new LinkedHashMap<>(headers);
        narrow.put("Signature-Input", headers.get("Signature-Input").replace(" \"@query\"", ""));
        assertEquals("does not cover @query", snippetE(() ->
            Fiki.verifyRequest("POST", url, narrow, policy.withResolver(keyState()::get))));

        Map<String, String> twice = new LinkedHashMap<>(headers);
        twice.put("Signature-Input", headers.get("Signature-Input").replace("\"@path\"", "\"@path\" \"@path\""));
        assertEquals("covers @path twice", snippetE(() ->
            Fiki.verifyRequest("POST", url, twice, policy.withResolver(keyState()::get))));

        Fiki.Request asked = new Fiki.Request("POST", url, headers, body);
        assertEquals("refused before the agent was known", snippetE(() ->
            Fiki.verifyResponse(401, Map.of(), asked, Fiki.VerifyOptions.maxAge(300))));

        assertTrue(snippetE(() -> Fiki.verifyRequest("POST", url, headers,
            policy.withResolver(keyState()::get))).equals("verified"));
    }
}
