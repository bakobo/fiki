package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * The KERI profile's vector set, vectors/keri/, run in place (this.i @8vwrexxc, @24tvlxgd).
 *
 * <p>A separate contract from the shared vectors/: its own format number, and refusals named by
 * the profile's neutral section 9 codes rather than fiki's class names. fiki-py's driver imports
 * the resolver, the well-formedness rule and the policy-applying verifier from
 * vectors/keri/generate.py (@4tkkp50h). This one cannot import Python, so it reads the
 * class-to-code table out of that file's text rather than copying it, and reimplements only what
 * each file's keys_rule and policy prose state normatively: the resolver, the AID rule, and the
 * policy wiring.
 *
 * <p>The resolver is authoritative (@6g9zjsv9). It derives a non-transferable B keyid's key from
 * the prefix, looks every other well-formed keyid up in the file's keys table, answers null for
 * one it has no key state for, throws UnsupportedSigner for a key state with no single effective
 * signer, and refuses a keyid that is not an AID at all. It never decodes a D keyid as a key,
 * which is exactly what one of the vectors is there to catch.
 */
class KeriVectorsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final File KERI = new File("../vectors/keri");
    private static final List<String> FILES =
        List.of("rfc9421.json", "requests.json", "responses.json", "refusals.json", "legacy.json");
    private static final List<String> POLICY_FILES = List.of("requests.json", "responses.json", "refusals.json");
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
    private static final Map<String, String> CODES = codes();

    private static JsonNode load(String name) throws Exception {
        File file = new File(KERI, name);
        assertTrue(file.isFile(), "the KERI vectors are not where every port reaches them: " + file);
        return MAPPER.readTree(file);
    }

    /** fiki's class names to the profile's codes, read from the generator rather than copied. */
    private static Map<String, String> codes() {
        try {
            String source = Files.readString(new File(KERI, "generate.py").toPath(), StandardCharsets.UTF_8);
            Matcher block = Pattern.compile("(?s)\\nCODES = \\{(.*?)\\n\\}").matcher(source);
            assertTrue(block.find(), "vectors/keri/generate.py has no CODES table");
            Map<String, String> out = new LinkedHashMap<>();
            Matcher entry = Pattern.compile("\"(\\w+)\": \"([a-z-]+)\"").matcher(block.group(1));
            while (entry.find()) {
                out.put(entry.group(1), entry.group(2));
            }
            return out;
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, String> headers(JsonNode node) {
        Map<String, String> out = new LinkedHashMap<>();
        node.fields().forEachRemaining(e -> out.put(e.getKey(), e.getValue().asText()));
        return out;
    }

    private static List<String> strings(JsonNode node) {
        List<String> out = new ArrayList<>();
        node.forEach(item -> out.add(item.asText()));
        return out;
    }

    private static byte[] body(JsonNode message) {
        JsonNode body = message.get("body");
        return body == null || body.isNull() ? null : body.asText().getBytes(StandardCharsets.UTF_8);
    }

    private static Fiki.Request request(JsonNode message) {
        return new Fiki.Request(message.get("method").asText(), message.get("url").asText(),
            headers(message.get("headers")), body(message));
    }

    private static byte[] b64url(String text) {
        return URL_DECODER.decode(text);
    }

    /** The keys_rule's test: 44 characters, B, D or E, and the canonical spelling of 32 bytes. */
    static boolean wellFormedAid(String keyid) {
        if (keyid.length() != 44 || "BDE".indexOf(keyid.charAt(0)) < 0) {
            return false;
        }
        byte[] decoded;
        try {
            decoded = URL_DECODER.decode("A" + keyid.substring(1));
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] padded = new byte[33];
        System.arraycopy(decoded, 1, padded, 1, 32);
        String canonical = keyid.charAt(0) + Base64.getUrlEncoder().withoutPadding().encodeToString(padded).substring(1);
        return decoded.length == 33 && canonical.equals(keyid);
    }

    /** What a KERI verifier's key lookup does, for a keys table: authoritative, never a decode. */
    private static Fiki.Resolver resolver(JsonNode keys) {
        Map<String, JsonNode> table = new HashMap<>();
        keys.forEach(entry -> {
            if (entry.get("kind").asText().equals("transferable")) {
                table.put(entry.get("keyid").asText(), entry);
            }
        });
        return keyid -> {
            if (!wellFormedAid(keyid)) {
                throw new FikiException(FikiException.Kind.MalformedKey, "\"" + keyid + "\" is not a well-formed AID.", keyid);
            }
            if (keyid.startsWith("B")) {
                return Key.verifyingKeyBytes(keyid);
            }
            JsonNode entry = table.get(keyid);
            if (entry == null) {
                return null;
            }
            if (entry.get("effective_key").isNull()) {
                throw new FikiException(FikiException.Kind.UnsupportedSigner,
                    "The key state of \"" + keyid + "\" has no single key that satisfies its threshold.", keyid);
            }
            return b64url(entry.get("effective_key").asText());
        };
    }

    /** Verify as a KERI verifier would, under the file's policy extended by the case's. */
    private static Fiki.Verdict run(JsonNode c, JsonNode data, JsonNode response) {
        return run(c, data, response, c.get("policy"));
    }

    private static Fiki.Verdict run(JsonNode c, JsonNode data, JsonNode response, JsonNode extra) {
        JsonNode policy = data.get("policy");
        JsonNode expectedKeyid = extra == null ? null : extra.get("expected_keyid");
        JsonNode authorities = extra == null ? null : extra.get("authorities");
        Fiki.VerifyOptions common = Fiki.VerifyOptions.maxAge(policy.get("max_age").asLong())
            .withSkew(policy.get("skew").asLong())
            .withNow(c.get("now").asLong())
            .withResolver(resolver(data.get("keys")))
            .withExpectedKeyid(expectedKeyid == null ? null : expectedKeyid.asText());
        JsonNode request = c.get("request");
        if (response != null) {
            return Fiki.verifyResponse(response.get("status").asInt(), headers(response.get("headers")),
                request(request),
                common.withBody(body(response)).withMinimum(strings(policy.get("response_minimum"))));
        }
        return Fiki.verifyRequest(request.get("method").asText(), request.get("url").asText(),
            headers(request.get("headers")),
            common.withBody(body(request)).withMinimum(strings(policy.get("request_minimum")))
                .withAuthorities(authorities == null ? null : new HashSet<>(strings(authorities))));
    }

    private static Fiki.Verdict run(JsonNode c, JsonNode data) {
        JsonNode response = c.get("response");
        return run(c, data, response == null || response.isNull() ? null : response);
    }

    private static List<String> serialized(List<String> covered) {
        return covered.stream().map(spec -> spec.startsWith("\"") ? spec : "\"" + spec + "\"").toList();
    }

    /**
     * The base a signer builds from the parameters its Signature-Input carries, and its signature,
     * rebuilt through the port's signing-side base functions and checked against the signature on
     * the message, so the base an accept case publishes is the one this port would sign.
     */
    private static void assertBase(JsonNode c, JsonNode data) throws Exception {
        JsonNode responseNode = c.get("response");
        boolean isResponse = responseNode != null && !responseNode.isNull();
        JsonNode message = isResponse ? responseNode : c.get("request");
        Map<String, String> sent = headers(message.get("headers"));
        Sfv.InnerList inner = (Sfv.InnerList) Sfv.parseDictionary(sent.get("Signature-Input")).get(0).value();
        List<String> covered = inner.items().stream().map(Sfv::serializeItem).toList();
        Fiki.Params params = new Fiki.Params((Long) inner.param("created"), (String) inner.param("keyid"),
            (String) inner.param("alg"), (Long) inner.param("expires"), (String) inner.param("nonce"),
            (String) inner.param("tag"));
        byte[] base = isResponse
            ? Fiki.responseSignatureBase(message.get("status").asInt(), sent, covered, params, request(c.get("request")))
            : Fiki.signatureBase(message.get("method").asText(), message.get("url").asText(), sent, covered, params);
        String signature = sent.get("Signature").split("=", 2)[1].replace(":", "");
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(Key.decodePublic(resolver(data.get("keys")).resolve(params.keyid())));
        verifier.update(base);
        assertTrue(verifier.verify(Base64.getDecoder().decode(signature)));
        JsonNode expected = c.get("expected");
        assertEquals(expected.get("base").asText(), new String(base, StandardCharsets.UTF_8));
        assertEquals(expected.get("signature").asText(), signature);
    }

    /* ------------------------------------------------------------------ the files themselves */

    @TestFactory
    Stream<DynamicTest> thisPortSatisfiesTheKeriVectorsFormatItIsRunning() {
        // The same guard @4fhrre0m gives the shared set, against its own number.
        return FILES.stream().map(name -> DynamicTest.dynamicTest(name, () -> {
            JsonNode data = load(name);
            assertEquals(Fiki.KERI_VECTORS_FORMAT, data.get("keri_vectors_format").asInt());
            assertFalse(data.has("vectors_format"));
            assertFalse(data.get("cases").isEmpty());
        }));
    }

    @TestFactory
    Stream<DynamicTest> eachFileNamesThePublishedProfileItPins() {
        return FILES.stream().map(name -> DynamicTest.dynamicTest(name, () -> {
            JsonNode profile = load(name).get("profile");
            assertEquals(1, profile.get("version").asInt());
            assertEquals("https://github.com/bakobo/fiki/blob/main/docs/keri-profile.md", profile.get("where").asText());
            String doc = Files.readString(new File("../docs/keri-profile.md").toPath(), StandardCharsets.UTF_8);
            assertTrue(doc.startsWith("# " + profile.get("title").asText() + "\n\nVersion 1, "));
        }));
    }

    @TestFactory
    Stream<DynamicTest> eachFileStatesThePolicyItAssumes() {
        return POLICY_FILES.stream().map(name -> DynamicTest.dynamicTest(name, () -> {
            JsonNode policy = load(name).get("policy");
            assertEquals(300, policy.get("max_age").asInt());
            assertEquals(60, policy.get("skew").asInt());
            assertEquals(serialized(Fiki.REQUEST_MINIMUM), strings(policy.get("request_minimum")));
            assertEquals(serialized(Fiki.RESPONSE_MINIMUM), strings(policy.get("response_minimum")));
        }));
    }

    @TestFactory
    Stream<DynamicTest> theKeysTableAgreesWithItsSeedsAndKeyStates() {
        // A table entry that disagrees with its own seed would make every case using it a lie.
        return POLICY_FILES.stream().map(name -> DynamicTest.dynamicTest(name, () -> {
            JsonNode data = load(name);
            assertFalse(data.get("keys_rule").asText().isEmpty());
            for (JsonNode entry : data.get("keys")) {
                String keyid = entry.get("keyid").asText();
                assertTrue(wellFormedAid(keyid), keyid);
                Key signer = Key.fromSeed(HexFormat.of().parseHex(entry.get("seed_hex").asText()));
                byte[] signerRaw = Key.verifyingKeyBytes(signer.aid());
                if (entry.get("kind").asText().equals("non-transferable")) {
                    assertEquals(signer.aid(), keyid);
                    continue;
                }
                List<byte[]> state = new ArrayList<>();
                for (JsonNode key : entry.get("key_state").get("keys")) {
                    assertTrue(key.asText().startsWith("D") && key.asText().length() == 44);
                    state.add(Arrays.copyOfRange(URL_DECODER.decode("A" + key.asText().substring(1)), 1, 33));
                }
                if (entry.get("effective_key").isNull()) {
                    assertTrue(Arrays.equals(signerRaw, state.get(0)));
                } else {
                    assertTrue(Arrays.equals(b64url(entry.get("effective_key").asText()), signerRaw));
                    assertTrue(state.stream().anyMatch(k -> Arrays.equals(k, signerRaw)));
                }
            }
        }));
    }

    @Test
    void theWellFormednessRuleRefusesNearMisses() throws Exception {
        assertFalse(wellFormedAid("E" + "!".repeat(43)));
        assertFalse(wellFormedAid("A" + "A".repeat(43)));
        assertFalse(wellFormedAid("not-an-aid"));
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (JsonNode entry : load("requests.json").get("keys")) {
            String keyid = entry.get("keyid").asText();
            String alias = keyid.charAt(0) + String.valueOf(alphabet.charAt(alphabet.indexOf(keyid.charAt(1)) ^ 0x10))
                + keyid.substring(2);
            assertTrue(wellFormedAid(keyid));
            assertFalse(wellFormedAid(alias), "bakobo/fiki#4: a non-zero pad bit would alias the same key");
        }
    }

    @Test
    void everyRefusalNamesAProfileCodeAndEveryProfileCodeIsExercised() throws Exception {
        JsonNode data = load("refusals.json");
        Set<String> named = new HashSet<>();
        data.get("cases").forEach(c -> named.add(c.get("error").asText()));
        assertEquals(new HashSet<>(strings(data.get("codes"))), named);
        assertTrue(named.containsAll(CODES.values()));
    }

    @Test
    void everyFikiErrorHasAProfileCode() {
        // The totality heti's boundary test enforces (@8zw78n0v), against the profile's codes.
        Set<String> kinds = EnumSet.allOf(FikiException.Kind.class).stream().map(Enum::name).collect(Collectors.toSet());
        assertEquals(CODES.keySet(), kinds);
    }

    @Test
    void theRefusalCodesAreNeutralRatherThanFikiClassNames() throws Exception {
        for (JsonNode c : load("refusals.json").get("cases")) {
            String error = c.get("error").asText();
            assertEquals(error.toLowerCase(java.util.Locale.ROOT), error);
            assertFalse(CODES.containsKey(error));
        }
    }

    /* ------------------- RFC 9421 B.2.6, which anchors the set to something no Bakobo party wrote */

    @Test
    void rfc9421B26IsTheRfcsOwnBaseAndSignature() throws Exception {
        JsonNode cases = load("rfc9421.json").get("cases");
        assertEquals(1, cases.size());
        JsonNode c = cases.get(0);
        JsonNode request = c.get("request");
        byte[] base = Fiki.signatureBase(request.get("method").asText(), request.get("url").asText(),
            headers(request.get("headers")), strings(c.get("covered")),
            Fiki.Params.of(c.get("created").asLong(), c.get("keyid").asText()));
        assertEquals(c.get("expected").get("base").asText(), new String(base, StandardCharsets.UTF_8));
        Key key = Key.fromSeed(HexFormat.of().parseHex(c.get("seed_hex").asText()));
        assertEquals(c.get("public_key").asText(), key.keyid());
        assertEquals(c.get("expected").get("signature").asText(), Base64.getEncoder().encodeToString(key.sign(base)));
    }

    /* -------------------------------------------------------------------- the accept cases */

    @TestFactory
    Stream<DynamicTest> requestAcceptVectors() throws Exception {
        JsonNode data = load("requests.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : data.get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
                Fiki.Verdict verdict = run(c, data);
                JsonNode expected = c.get("expected");
                assertEquals(expected.get("keyid").asText(), verdict.keyid());
                assertEquals(strings(expected.get("covered")), serialized(verdict.covered()));
                assertBase(c, data);
            }));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> responseAcceptVectors() throws Exception {
        JsonNode data = load("responses.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : data.get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
                // The request the response answers is itself a valid canonical request, under the
                // file's policy alone: the case's policy is the client's, for the response.
                assertNotNull(run(c, data, null, null));
                Fiki.Verdict verdict = run(c, data);
                JsonNode expected = c.get("expected");
                assertEquals(expected.get("keyid").asText(), verdict.keyid());
                assertEquals(strings(expected.get("covered")), serialized(verdict.covered()));
                assertBase(c, data);
            }));
        }
        return tests.stream();
    }

    @Test
    void theSha512CasesAreMarkedVerifyOnly() throws Exception {
        JsonNode data = load("requests.json");
        Set<String> ids = new HashSet<>();
        data.get("cases").forEach(c -> ids.add(c.get("id").asText()));
        List<String> verifyOnly = strings(data.get("verify_only"));
        assertTrue(ids.containsAll(verifyOnly));
        for (JsonNode c : data.get("cases")) {
            JsonNode digest = c.get("request").get("headers").get("Content-Digest");
            String text = digest == null ? "" : digest.asText();
            if (!text.isEmpty() && !text.startsWith("sha-256=") || text.contains(",")) {
                assertTrue(verifyOnly.contains(c.get("id").asText()));
            }
        }
    }

    /* ----------------------------------------------------------------------- the refusals */

    @TestFactory
    Stream<DynamicTest> refusalVectors() throws Exception {
        // Each case has one defect and so one correct code under the profile's section 9 order.
        JsonNode data = load("refusals.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : data.get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
                JsonNode verified = c.get("verified_by_fiki");
                if (verified != null && !verified.asBoolean()) {
                    // Carried as data (@4tkkp50h): fiki has no legacy mode to detect it with.
                    assertEquals("mode-mismatch", c.get("error").asText());
                    assertFalse(c.get("why").asText().isEmpty());
                    return;
                }
                FikiException thrown = assertThrows(FikiException.class, () -> {
                    if (c.get("kind").asText().equals("sign-request")) {
                        JsonNode request = c.get("request");
                        Fiki.signRequest(Key.fromSeed(HexFormat.of().parseHex(c.get("seed_hex").asText())),
                            request.get("method").asText(), request.get("url").asText(), headers(request.get("headers")),
                            Fiki.SignOptions.none().withBody(body(request)).withCovered(strings(c.get("covered")))
                                .withKeyid(c.get("keyid").asText())
                                .withMinimum(strings(data.get("policy").get("request_minimum"))));
                    } else {
                        run(c, data);
                    }
                });
                assertEquals(c.get("error").asText(), CODES.get(thrown.kind().name()), thrown.getMessage());
            }));
        }
        return tests.stream();
    }

    /* ---------------------------------- legacy material, which fiki carries and never verifies */

    @Test
    void legacyVectorsCarryWhatALegacyVerifierNeedsAndTheirProvenance() throws Exception {
        for (JsonNode c : load("legacy.json").get("cases")) {
            JsonNode source = c.get("source");
            assertTrue(Set.of("WebOfTrust/keria", "WebOfTrust/signify-ts").contains(source.get("repo").asText()));
            assertEquals(40, source.get("commit").asText().length());
            assertFalse(source.get("file").asText().isEmpty());
            assertFalse(source.get("lines").asText().isEmpty());
            for (String field : List.of("kind", "method", "path", "headers", "key", "keyid", "created")) {
                assertTrue(c.has(field), field);
            }
            assertTrue(c.get("headers").get("Signature-Input").asText().startsWith("signify="));
            assertTrue(c.get("headers").get("Signature").asText().startsWith("indexed=\"?0\";signify=\"0B"));
        }
    }

    @TestFactory
    Stream<DynamicTest> eachLegacySignatureVerifiesOverItsStatedBase() throws Exception {
        // Transcription check only: pure Ed25519 over the base the file states, no legacy logic.
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : load("legacy.json").get("cases")) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
                String signature = c.get("headers").get("Signature").asText().split("signify=\"", 2)[1];
                signature = signature.substring(0, signature.length() - 1);
                byte[] rawSignature = Arrays.copyOfRange(URL_DECODER.decode("AA" + signature.substring(2)), 2, 66);
                String key = c.get("key").asText();
                byte[] rawKey = Arrays.copyOfRange(URL_DECODER.decode("A" + key.substring(1)), 1, 33);
                Signature verifier = Signature.getInstance("Ed25519");
                verifier.initVerify(Key.decodePublic(rawKey));
                verifier.update(c.get("base").asText().getBytes(StandardCharsets.UTF_8));
                assertTrue(verifier.verify(rawSignature));
            }));
        }
        return tests.stream();
    }
}
