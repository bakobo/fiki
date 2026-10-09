package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * The shared conformance vectors (this.i @5gf6r08f, @2tt6fmc0).
 *
 * <p>They live at the repository root rather than under java/ so this implementation and the other
 * four are held to the same bytes. A copy under each language is the drift the polyglot layout
 * exists to prevent, which is why this file reaches up rather than embedding anything.
 */
class VectorsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode load(String name) throws Exception {
        File file = new File("../vectors/" + name);
        assertTrue(file.isFile(), "the shared vectors are not where every port reaches them: " + file);
        return MAPPER.readTree(file);
    }

    private static Map<String, String> headers(JsonNode node) {
        Map<String, String> out = new LinkedHashMap<>();
        if (node != null && node.isObject()) {
            node.fields().forEachRemaining(e -> out.put(e.getKey(), e.getValue().asText()));
        }
        return out;
    }

    private static List<String> strings(JsonNode node) {
        List<String> out = new ArrayList<>();
        node.forEach(item -> out.add(item.asText()));
        return out;
    }

    private static byte[] body(JsonNode node) {
        JsonNode body = node.get("body");
        return body == null || body.isNull() ? null : body.asText().getBytes(StandardCharsets.UTF_8);
    }

    // Every field a verify case may carry. A field this driver does not know fails the case rather
    // than being ignored, so a field added to the vectors cannot be silently dropped by a port that
    // never learned it (review V-M8).
    private static final Set<String> VERIFY_FIELDS = Set.of(
        "id", "method", "url", "headers", "body", "max_age", "now", "minimum", "authorities",
        "expected_aid", "note", "error", "aid", "keyid", "covered", "omit", "kind", "status", "request",
        "expected_keyid");

    // Every field a sign case may carry, held to the same rule.
    private static final Set<String> SIGN_FIELDS = Set.of(
        "id", "kind", "seed_hex", "method", "url", "headers", "body", "covered", "created", "expires",
        "nonce", "tag", "minimum", "status", "request", "expected_headers", "error", "note", "keyid", "label");

    private static void knownFields(JsonNode c, Set<String> known) {
        Set<String> fields = new HashSet<>();
        c.fieldNames().forEachRemaining(fields::add);
        fields.removeAll(known);
        assertTrue(fields.isEmpty(), "unknown fields " + fields);
    }

    /**
     * Every refusal's message holds no control character and is at most 1024 characters, so an
     * untrusted value is quoted escaped and cut (@524c8qgv, part-two refinements).
     */
    private static void wellFormed(Throwable error) {
        String message = error.getMessage();
        assertTrue(message.length() <= 1024, "message of " + message.length() + " characters");
        assertTrue(message.chars().noneMatch(ch -> ch < 0x20 || ch == 0x7f),
            () -> "a control character in " + message.substring(0, Math.min(200, message.length())));
    }

    /**
     * The verifier's stated policy (format 3, @524c8qgv). minimum "default" leaves it unstated,
     * null is the explicit opt-out, a list is that minimum; authorities null is the explicit
     * opt-out and a list is the hosts served; a field named in omit is left out of the call.
     */
    private static Fiki.VerifyOptions options(JsonNode c) throws Exception {
        knownFields(c, VERIFY_FIELDS);
        Set<String> omit = new HashSet<>();
        if (c.has("omit")) {
            omit.addAll(strings(c.get("omit")));
        }
        JsonNode maxAge = c.get("max_age");
        Fiki.VerifyOptions opts = maxAge.isNull()
            ? Fiki.VerifyOptions.decliningFreshness()
            : Fiki.VerifyOptions.maxAge(maxAge.asLong());
        opts = opts.withBody(body(c));
        JsonNode now = c.get("now");
        if (!now.isNull()) {
            opts = opts.withNow(now.asLong());
        }
        if (!omit.contains("expected_aid") && !c.get("expected_aid").isNull()) {
            opts = opts.withExpectedAid(c.get("expected_aid").asText());
        }
        JsonNode minimum = c.get("minimum");
        if (!omit.contains("minimum") && !(minimum.isTextual() && minimum.asText().equals("default"))) {
            opts = minimum.isNull() ? opts.withoutMinimum() : opts.withMinimum(strings(minimum));
        }
        if (!omit.contains("authorities")) {
            opts = withAuthorities(opts, c.get("authorities"));
        }
        return opts;
    }

    /**
     * Java's types refuse two of the misuse vectors' shapes before anything runs: a string where a
     * collection of hosts belongs does not compile, and neither does a non-string member without an
     * unchecked conversion. The driver makes each call anyway, so the vector is exercised rather than
     * skipped: the string through reflection, which the JVM refuses as the same
     * IllegalArgumentException, and the mixed list through a raw collection, which fiki checks itself.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Fiki.VerifyOptions withAuthorities(Fiki.VerifyOptions opts, JsonNode authorities) throws Exception {
        if (authorities.isNull()) {
            return opts.withoutAuthorityCheck();
        }
        if (authorities.isTextual()) {
            Method method = Fiki.VerifyOptions.class.getMethod("withAuthorities", Collection.class);
            assertFalse(method.getParameterTypes()[0].isAssignableFrom(String.class));
            try {
                return (Fiki.VerifyOptions) method.invoke(opts, authorities.asText());
            } catch (InvocationTargetException e) {
                throw (Exception) e.getCause();
            }
        }
        List raw = new ArrayList();
        authorities.forEach(item -> raw.add(item.isTextual() ? item.asText() : (Object) item.asLong()));
        return opts.withAuthorities(raw);
    }

    /*
     * The number of cases in each file at hardening-a, read from the files once when these constants
     * were written and never at test time: a driver looping over an emptied cases array asserted
     * nothing and passed (tick 7xbw, T8). Counted.each holds each file to its number.
     */
    private static final int AID_LENS_CASES = 3;
    private static final int SIGNATURE_BASE_CASES = 14;
    private static final int ACCEPTS_CASES = 44;
    private static final int REFUSALS_CASES = 144;
    private static final int RESPONSES_CASES = 13;
    private static final int SIGNS_CASES = 16;
    private static final int MISUSE_CASES = 10;

    /*
     * The message fragment each caller-error vector must carry (tick 7xbw, T3), since a vector names
     * only the class. The two string-authorities cases are the exception: Java's types refuse a
     * string where a collection of hosts belongs, so the driver reaches withAuthorities through
     * reflection, and the JDK refuses the call before any fiki code runs, with its own message.
     */
    private static final Map<String, String> CALLER_ERRORS = Map.ofEntries(
        Map.entry("authorities-is-a-string", "argument type mismatch"),
        Map.entry("authorities-is-a-string-containing-the-host", "argument type mismatch"),
        Map.entry("authorities-is-empty", "authorities is empty, which serves no host at all"),
        Map.entry("authorities-holds-a-non-string", "Every authority is a string"),
        Map.entry("authorities-omitted", "State the authorities this verifier serves"),
        Map.entry("minimum-below-the-profiles", "A minimum covered set must include the profile's own"),
        Map.entry("minimum-empty", "A minimum covered set must include the profile's own"),
        Map.entry("response-expected-keyid-omitted", "State the AID this client expects the response to be signed by"),
        Map.entry("response-minimum-below-the-profiles", "A minimum covered set must include the profile's own"),
        Map.entry("response-expected-keyid-empty", "expected keyid is empty, which names no AID"),
        Map.entry("url-over-8192-bytes", "cannot be read: it is over 8192 bytes"));

    @TestFactory
    Stream<DynamicTest> vectorsFormat() {
        List<DynamicTest> tests = new ArrayList<>();
        for (String name : List.of("aid-lens.json", "signature-base.json", "accepts.json", "refusals.json", "misuse.json",
                "signs.json", "responses.json")) {
            tests.add(DynamicTest.dynamicTest(name, () -> {
                // A port running newer vectors fails here rather than passing a subset and
                // reporting conformance it no longer has.
                assertEquals(Fiki.VECTORS_FORMAT, load(name).get("vectors_format").asInt());
            }));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> aidLens() throws Exception {
        return Counted.each("aid-lens.json", load("aid-lens.json").get("cases"), AID_LENS_CASES, c -> {
            Key key = Key.fromSeed(HexFormat.of().parseHex(c.get("seed_hex").asText()));
            assertEquals(c.get("aid").asText(), key.aid());
            assertEquals(c.get("keyid").asText(), key.keyid());
            assertArrayEquals(
                HexFormat.of().parseHex(c.get("public_key_hex").asText()),
                Key.verifyingKeyBytes(c.get("aid").asText()));
        });
    }

    @TestFactory
    Stream<DynamicTest> signatureBases() throws Exception {
        return Counted.each("signature-base.json", load("signature-base.json").get("cases"), SIGNATURE_BASE_CASES, c -> {
            JsonNode alg = c.get("alg");
            Fiki.Params params = new Fiki.Params(
                c.get("created").asLong(), c.get("keyid").asText(),
                alg == null ? null : alg.asText(), null, null, null);
            byte[] base = Fiki.signatureBase(
                c.get("method").asText(), c.get("url").asText(), headers(c.get("headers")),
                strings(c.get("covered")), params);
            assertEquals(c.get("base").asText(), new String(base, StandardCharsets.UTF_8));
            // Ed25519 is deterministic, so a port that builds the right base produces the
            // right bytes: byte equality, not a verification round trip.
            Key key = Key.fromSeed(HexFormat.of().parseHex(c.get("seed_hex").asText()));
            assertEquals(
                c.get("signature").asText(),
                Base64.getEncoder().encodeToString(key.sign(base)));
        });
    }

    @TestFactory
    Stream<DynamicTest> accepts() throws Exception {
        JsonNode doc = load("accepts.json");
        return Counted.each("accepts.json", doc.get("cases"), ACCEPTS_CASES, c -> {
            Fiki.Verdict verdict = Fiki.verifyRequest(
                c.get("method").asText(), c.get("url").asText(), headers(c.get("headers")), options(c));
            assertEquals(c.get("aid").asText(), verdict.aid());
            assertEquals(strings(c.get("covered")), verdict.covered());
            // The keyid as it appeared on the wire (@5zrf8gjk, rule B18).
            assertEquals(c.get("keyid").asText(), verdict.keyid());
        });
    }

    @TestFactory
    Stream<DynamicTest> refusals() throws Exception {
        JsonNode doc = load("refusals.json");
        return Counted.each("refusals.json", doc.get("cases"), REFUSALS_CASES, c -> {
            // Every entry names the kind fiki reports, so this port maps its own onto the same
            // condition rather than inventing a taxonomy of its own.
            FikiException thrown = assertThrows(FikiException.class, () -> Fiki.verifyRequest(
                c.get("method").asText(), c.get("url").asText(), headers(c.get("headers")), options(c)));
            assertEquals(c.get("error").asText(), thrown.kind().name());
            wellFormed(thrown);
        });
    }

    private static Fiki.Request requestOf(JsonNode message) {
        if (message == null || message.isNull()) {
            return null;
        }
        return new Fiki.Request(message.get("method").asText(), message.get("url").asText(),
            headers(message.get("headers")), body(message));
    }

    /**
     * verifyResponse's own policy (format 3 part two): minimum "default" leaves it unstated, which
     * is RESPONSE_MINIMUM, null is the explicit opt-out and a list is that minimum; expected_keyid
     * null is the explicit decline and an AID is that AID; a field named in omit is left out.
     */
    private static Fiki.Verdict verifyResponse(JsonNode c) {
        knownFields(c, VERIFY_FIELDS);
        Set<String> omit = new HashSet<>();
        if (c.has("omit")) {
            omit.addAll(strings(c.get("omit")));
        }
        JsonNode maxAge = c.get("max_age");
        Fiki.VerifyOptions opts = maxAge.isNull()
            ? Fiki.VerifyOptions.decliningFreshness()
            : Fiki.VerifyOptions.maxAge(maxAge.asLong());
        opts = opts.withBody(body(c));
        if (!c.get("now").isNull()) {
            opts = opts.withNow(c.get("now").asLong());
        }
        JsonNode minimum = c.get("minimum");
        if (!omit.contains("minimum") && !(minimum.isTextual() && minimum.asText().equals("default"))) {
            opts = minimum.isNull() ? opts.withoutMinimum() : opts.withMinimum(strings(minimum));
        }
        JsonNode keyid = c.get("expected_keyid");
        if (!omit.contains("expected_keyid")) {
            opts = keyid.isNull() ? opts.withoutKeyidCheck() : opts.withExpectedKeyid(keyid.asText());
        }
        return Fiki.verifyResponse(c.get("status").asInt(), headers(c.get("headers")), requestOf(c.get("request")),
            opts);
    }

    @TestFactory
    Stream<DynamicTest> responses() throws Exception {
        JsonNode doc = load("responses.json");
        return Counted.each("responses.json", doc.get("cases"), RESPONSES_CASES, c -> {
            if (c.has("error")) {
                FikiException thrown = assertThrows(FikiException.class, () -> verifyResponse(c));
                assertEquals(c.get("error").asText(), thrown.kind().name());
                wellFormed(thrown);
            } else {
                Fiki.Verdict verdict = verifyResponse(c);
                assertEquals(c.get("keyid").asText(), verdict.keyid());
                assertEquals(strings(c.get("covered")), verdict.covered());
            }
        });
    }

    /** What the signer emits, byte for byte (review V-C4). */
    private static Map<String, String> sign(JsonNode c) {
        Key key = Key.fromSeed(HexFormat.of().parseHex(c.get("seed_hex").asText()));
        Fiki.SignOptions opts = Fiki.SignOptions.none().withBody(body(c));
        if (!c.get("covered").isNull()) {
            opts = opts.withCovered(strings(c.get("covered")));
        }
        if (!c.get("created").isNull()) {
            opts = opts.withCreated(c.get("created").asLong());
        }
        if (!c.get("expires").isNull()) {
            opts = opts.withExpires(c.get("expires").asLong());
        }
        if (!c.get("nonce").isNull()) {
            opts = opts.withNonce(c.get("nonce").asText());
        }
        if (!c.get("tag").isNull()) {
            opts = opts.withTag(c.get("tag").asText());
        }
        if (!c.get("minimum").isNull()) {
            opts = opts.withMinimum(strings(c.get("minimum")));
        }
        if (!c.get("keyid").isNull()) {
            opts = opts.withKeyid(c.get("keyid").asText());
        }
        if (!c.get("label").isNull()) {
            opts = opts.withLabel(c.get("label").asText());
        }
        Map<String, String> headers = headers(c.get("headers"));
        return switch (c.get("kind").asText()) {
            case "request" -> Fiki.signRequest(key, c.get("method").asText(), c.get("url").asText(), headers, opts);
            case "response" -> Fiki.signResponse(key, c.get("status").asInt(), requestOf(c.get("request")), headers, opts);
            default -> throw new AssertionError("unknown kind " + c.get("kind"));
        };
    }

    @TestFactory
    Stream<DynamicTest> signs() throws Exception {
        JsonNode doc = load("signs.json");
        return Counted.each("signs.json", doc.get("cases"), SIGNS_CASES, c -> {
            knownFields(c, SIGN_FIELDS);
            if (c.has("error") && c.get("error").asText().equals("caller")) {
                Caller.refused(CALLER_ERRORS.get(c.get("id").asText()), () -> sign(c), c.get("id").asText());
            } else if (c.has("error")) {
                FikiException thrown = assertThrows(FikiException.class, () -> sign(c));
                assertEquals(c.get("error").asText(), thrown.kind().name());
                wellFormed(thrown);
            } else {
                // Byte for byte, names and order included: a LinkedHashMap compares neither
                // order nor spelling, so both are checked as lists.
                Map<String, String> expected = headers(c.get("expected_headers"));
                Map<String, String> made = sign(c);
                assertEquals(new ArrayList<>(expected.entrySet()), new ArrayList<>(made.entrySet()));
            }
        });
    }

    @TestFactory
    Stream<DynamicTest> misuse() throws Exception {
        JsonNode doc = load("misuse.json");
        return Counted.each("misuse.json", doc.get("cases"), MISUSE_CASES, c -> {
            // A mistake in the call is an IllegalArgumentException, never a FikiException
            // (@5zrf8gjk), and one carrying fiki's own message for that mistake (tick 7xbw, T3).
            assertEquals("caller", c.get("error").asText());
            String id = c.get("id").asText();
            if (c.has("kind") && c.get("kind").asText().equals("response")) {
                Caller.refused(CALLER_ERRORS.get(id), () -> verifyResponse(c), id);
            } else {
                Caller.refused(CALLER_ERRORS.get(id), () -> Fiki.verifyRequest(
                    c.get("method").asText(), c.get("url").asText(), headers(c.get("headers")), options(c)), id);
            }
        });
    }
}
