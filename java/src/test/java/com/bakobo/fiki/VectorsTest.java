package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    private static Fiki.VerifyOptions options(JsonNode c) {
        JsonNode maxAge = c.get("max_age");
        Fiki.VerifyOptions opts = maxAge == null || maxAge.isNull()
            ? Fiki.VerifyOptions.decliningFreshness()
            : Fiki.VerifyOptions.maxAge(maxAge.asLong());
        opts = opts.withBody(body(c));
        JsonNode now = c.get("now");
        return now == null || now.isNull() ? opts : opts.withNow(now.asLong());
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
        for (JsonNode c : load("accepts.json").get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
                Fiki.Verdict verdict = Fiki.verifyRequest(
                    c.get("method").asText(), c.get("url").asText(), headers(c.get("headers")), options(c));
                assertEquals(c.get("aid").asText(), verdict.aid());
                assertEquals(strings(c.get("covered")), verdict.covered());
            }));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> refusals() throws Exception {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : load("refusals.json").get("cases")) {
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
}
