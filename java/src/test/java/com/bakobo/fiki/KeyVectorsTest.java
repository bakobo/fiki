package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The key-spelling vectors, vectors/keys/keys.json, run in place (this.i @0mvgkwnl).
 *
 * <p>{@link Key#aidFrom} turns any of the public-key spellings into the canonical AID, and
 * {@link Key#fromOpenssh} loads an unencrypted OpenSSH private key. Neither touches the wire: a
 * fiki-signed request still carries the raw key in its keyid (@7xrx5evg), and a verifier still
 * compares AIDs. A separate vector set from vectors/, with its own format number.
 */
class KeyVectorsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String FILE = "keys.json";
    private static final JsonNode VECTORS = load();

    /*
     * Each list's case count at key_vectors_format 1, read from keys.json once when these constants
     * were written and never at test time (tick 7xbw, T8).
     */
    private static final int PUBLIC_ACCEPTS = 18;
    private static final int PUBLIC_REFUSALS = 72;
    private static final int PRIVATE_ACCEPTS = 7;
    private static final int PRIVATE_REFUSALS = 43;

    // Every field a case may carry. One this driver does not know fails the case rather than being
    // ignored, so a field added to the vectors cannot be silently dropped (review V-M8).
    private static final Set<String> FIELDS =
        Set.of("id", "input", "aid", "source", "signature", "error", "why", "ssh_keygen_refuses");

    private static JsonNode load() {
        File file = new File("../vectors/keys/" + FILE);
        assertTrue(file.isFile(), "the key vectors are not where every port reaches them: " + file);
        try {
            return MAPPER.readTree(file);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void knownFields(JsonNode c) {
        Set<String> fields = new HashSet<>();
        c.fieldNames().forEachRemaining(fields::add);
        fields.removeAll(FIELDS);
        assertTrue(fields.isEmpty(), c.get("id").asText() + " carries fields this driver does not know: " + fields);
    }

    private static JsonNode named(String section, String kind, String id) {
        for (JsonNode c : VECTORS.get(section).get(kind)) {
            if (c.get("id").asText().equals(id)) {
                return c;
            }
        }
        throw new AssertionError(section + " " + kind + " has no case " + id);
    }

    private static String input(String section, String kind, String id) {
        return named(section, kind, id).get("input").asText();
    }

    /** Whether {@code e} carries {@code text}, or any run of it long enough to hold key material. */
    private static boolean echoes(FikiException e, String text) {
        String message = e.getMessage();
        if (e.detail() != null && !e.detail().isEmpty()) {
            return true;
        }
        if (text.length() >= 12 && message.contains(text)) {
            return true;
        }
        Matcher run = Pattern.compile("[A-Za-z0-9+/=_-]{12,}").matcher(text);
        while (run.find()) {
            if (message.contains(run.group())) {
                return true;
            }
        }
        return false;
    }

    private static FikiException malformed(Runnable body) {
        FikiException e = assertThrows(FikiException.class, body::run);
        assertEquals(FikiException.Kind.MalformedKey, e.kind(), e.getMessage());
        // Nor chained to an exception that might carry the input.
        assertNull(e.getCause());
        return e;
    }

    @Test
    void theFileDeclaresTheFormatThisPortSatisfies() {
        assertEquals(Fiki.KEY_VECTORS_FORMAT, VECTORS.get("key_vectors_format").asInt());
        // The bounds the file was generated against are the ones this port checks.
        assertEquals(Formats.MAX_PUBLIC_CHARS, VECTORS.get("max_public_chars").asInt());
        assertEquals(OpenSsh.MAX_PRIVATE_CHARS, VECTORS.get("max_private_chars").asInt());
    }

    @TestFactory
    Stream<DynamicTest> aPublicSpellingConvertsToItsAid() {
        return Counted.each(FILE + " public accepts", VECTORS.get("public").get("accepts"), PUBLIC_ACCEPTS, c -> {
            knownFields(c);
            assertEquals(c.get("aid").asText(), Key.aidFrom(c.get("input").asText()));
        });
    }

    @TestFactory
    Stream<DynamicTest> aMalformedPublicSpellingIsRefusedWithoutEchoingIt() {
        // Never echoed, because what a caller hands aidFrom by mistake can be a private key: the
        // .key file instead of the .pub, or a seed in base64url, which is 43 characters like a raw key.
        return Counted.each(FILE + " public refusals", VECTORS.get("public").get("refusals"), PUBLIC_REFUSALS, c -> {
            knownFields(c);
            assertEquals("MalformedKey", c.get("error").asText());
            String text = c.get("input").asText();
            FikiException e = malformed(() -> Key.aidFrom(text));
            assertEquals("", e.detail());
            assertFalse(echoes(e, text), e.getMessage());
        });
    }

    @TestFactory
    Stream<DynamicTest> anOpensshKeyLoadsAndSignsAsItsSeed() {
        byte[] message = VECTORS.get("signed_message").asText().getBytes(StandardCharsets.US_ASCII);
        return Counted.each(FILE + " private accepts", VECTORS.get("private").get("accepts"), PRIVATE_ACCEPTS, c -> {
            knownFields(c);
            Key key = Key.fromOpenssh(c.get("input").asText());
            assertEquals(c.get("aid").asText(), key.aid());
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(key.sign(message));
            assertEquals(c.get("signature").asText(), signature);
        });
    }

    @TestFactory
    Stream<DynamicTest> aMalformedOpensshKeyIsRefusedWithoutEchoingIt() {
        return Counted.each(FILE + " private refusals", VECTORS.get("private").get("refusals"), PRIVATE_REFUSALS, c -> {
            knownFields(c);
            assertEquals("MalformedKey", c.get("error").asText());
            String text = c.get("input").asText();
            FikiException e = malformed(() -> Key.fromOpenssh(text));
            // A private key never reaches an error: not its text, not any run of its base64 body
            // long enough to carry key material, and not the detail a consumer might log.
            assertEquals("", e.detail());
            Matcher run = Pattern.compile("[A-Za-z0-9+/=]{16,}").matcher(text);
            while (run.find()) {
                assertFalse(e.getMessage().contains(run.group()), e.getMessage());
            }
        });
    }

    @TestFactory
    Stream<DynamicTest> aWeakKeyIsRefusedForItsWeaknessWhateverItsSpelling() {
        // Not merely refused: refused by the point check, so the spelling parsed and the key reached
        // it (@37wdchu5). A parser bug that refused these earlier would pass the vector alone.
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : VECTORS.get("public").get("refusals")) {
            String id = c.get("id").asText();
            if (id.endsWith("small-order") || id.endsWith("not-on-curve")) {
                tests.add(DynamicTest.dynamicTest(id, () -> {
                    String message = malformed(() -> Key.aidFrom(c.get("input").asText())).getMessage();
                    assertTrue(message.contains("small-order") || message.contains("canonical encoding of a point"),
                        message);
                }));
            }
        }
        assertEquals(6, tests.size());
        return tests.stream();
    }

    @Test
    void aPrivateKeyWithAWeakPublicKeyIsRefused() {
        String message = malformed(() -> Key.fromOpenssh(input("private", "refusals", "public-small-order")))
            .getMessage();
        assertTrue(message.contains("does not derive") || message.contains("small-order"), message);
    }

    @Test
    void aNullKeyIsACallerErrorNotARefusal() {
        // The guide's "Handling errors": a mistake in the call is reported in the port's own idiom,
        // so that catching FikiException for a bad message cannot swallow a bug in the caller's code.
        Caller.refused("is text", () -> Key.aidFrom(null));
        Caller.refused("is text", () -> Key.fromOpenssh(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"aid-transferable", "aid-digest"})
    void aCanonicalTransferableOrDigestAidIsToldToResolveIt(String id) {
        String message = malformed(() -> Key.aidFrom(input("public", "refusals", id))).getMessage();
        assertTrue(message.contains("resolve it"), message);
    }

    @ParameterizedTest
    @ValueSource(strings = {"aid-transferable-not-base64", "aid-transferable-misspelled"})
    void aMalformedDPrefixIsNotCalledAnAid(String id) {
        // Shape before meaning: text that merely starts with D is not told it is a transferable AID.
        String message = malformed(() -> Key.aidFrom(input("public", "refusals", id))).getMessage();
        assertFalse(message.contains("resolve it"), message);
    }

    @Test
    void aSeedMistakenForARawKeyIsNotEchoedWhenRefused() {
        // About half of all seeds, written as 43 characters of base64url, are not a valid point and
        // so are refused by the curve check rather than by the parser. That refusal must not quote it.
        byte[] seed = null;
        for (int n = 0; n < 256 && seed == null; n++) {
            byte[] candidate = new byte[32];
            java.util.Arrays.fill(candidate, (byte) n);
            if (!Key.canonicalPoint(candidate) && !Key.smallOrder(candidate)) {
                seed = candidate;
            }
        }
        String text = Base64.getUrlEncoder().withoutPadding().encodeToString(seed);
        FikiException e = malformed(() -> Key.aidFrom(text));
        assertTrue(e.getMessage().contains("not the canonical encoding of a point"), e.getMessage());
        assertFalse(echoes(e, text), e.getMessage());
    }

    @Test
    void theEncryptedRefusalSaysToKeepADedicatedKey() {
        String message = malformed(() -> Key.fromOpenssh(input("private", "refusals", "encrypted"))).getMessage();
        assertTrue(message.contains("dedicated"), message);
    }

    @Test
    void anSshKeySignsARequestThatVerifiesAgainstItsRegisteredPublicLine() {
        Key key = Key.fromOpenssh(input("private", "accepts", "ssh-keygen"));
        String aid = Key.aidFrom(input("public", "accepts", "ssh-keygen-pub"));
        Map<String, String> headers = Fiki.signRequest(key, "GET", "https://example.com/x", Map.of(),
            Fiki.SignOptions.none());
        Fiki.Verdict verdict = Fiki.verifyRequest("GET", "https://example.com/x", headers,
            Fiki.VerifyOptions.maxAge(60).withoutAuthorityCheck().withExpectedAid(aid));
        assertEquals(aid, verdict.aid());
    }
}
