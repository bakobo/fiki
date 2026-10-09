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
        "expected_aid", "note", "error", "aid", "keyid", "covered", "omit");

    /**
     * The verifier's stated policy (format 3, @524c8qgv). minimum "default" leaves it unstated,
     * null is the explicit opt-out, a list is that minimum; authorities null is the explicit
     * opt-out and a list is the hosts served; a field named in omit is left out of the call.
     */
    private static Fiki.VerifyOptions options(JsonNode c) throws Exception {
        Set<String> fields = new HashSet<>();
        c.fieldNames().forEachRemaining(fields::add);
        fields.removeAll(VERIFY_FIELDS);
        assertTrue(fields.isEmpty(), "unknown fields " + fields);
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

    private static void loadedCases(JsonNode doc) {
        assertTrue(doc.get("cases").size() > 5, "a vector file with no cases checks nothing");
    }

    @TestFactory
    Stream<DynamicTest> vectorsFormat() {
        List<DynamicTest> tests = new ArrayList<>();
        for (String name : List.of("aid-lens.json", "signature-base.json", "accepts.json", "refusals.json", "misuse.json")) {
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
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : load("aid-lens.json").get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
                Key key = Key.fromSeed(HexFormat.of().parseHex(c.get("seed_hex").asText()));
                assertEquals(c.get("aid").asText(), key.aid());
                assertEquals(c.get("keyid").asText(), key.keyid());
                assertArrayEquals(
                    HexFormat.of().parseHex(c.get("public_key_hex").asText()),
                    Key.verifyingKeyBytes(c.get("aid").asText()));
            }));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> signatureBases() throws Exception {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : load("signature-base.json").get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
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
            }));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> accepts() throws Exception {
        List<DynamicTest> tests = new ArrayList<>();
        JsonNode doc = load("accepts.json");
        loadedCases(doc);
        for (JsonNode c : doc.get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
                Fiki.Verdict verdict = Fiki.verifyRequest(
                    c.get("method").asText(), c.get("url").asText(), headers(c.get("headers")), options(c));
                assertEquals(c.get("aid").asText(), verdict.aid());
                assertEquals(strings(c.get("covered")), verdict.covered());
                // The keyid as it appeared on the wire (@5zrf8gjk, rule B18).
                assertEquals(c.get("keyid").asText(), verdict.keyid());
            }));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> refusals() throws Exception {
        List<DynamicTest> tests = new ArrayList<>();
        JsonNode doc = load("refusals.json");
        loadedCases(doc);
        for (JsonNode c : doc.get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
                // Every entry names the kind fiki reports, so this port maps its own onto the same
                // condition rather than inventing a taxonomy of its own.
                FikiException thrown = assertThrows(FikiException.class, () -> Fiki.verifyRequest(
                    c.get("method").asText(), c.get("url").asText(), headers(c.get("headers")), options(c)));
                assertEquals(c.get("error").asText(), thrown.kind().name());
            }));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> misuse() throws Exception {
        List<DynamicTest> tests = new ArrayList<>();
        JsonNode doc = load("misuse.json");
        loadedCases(doc);
        for (JsonNode c : doc.get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
                // A mistake in the call is an IllegalArgumentException, never a FikiException
                // (@5zrf8gjk); FikiException is not one, so assertThrows alone shows both.
                assertEquals("caller", c.get("error").asText());
                Throwable thrown = assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest(
                    c.get("method").asText(), c.get("url").asText(), headers(c.get("headers")), options(c)));
                assertFalse(thrown instanceof FikiException);
            }));
        }
        return tests.stream();
    }
}
