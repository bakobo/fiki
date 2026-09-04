package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The ground the shared vectors do not cover: signing a fresh request, generating a key, the
 * parser's own refusal branches, and the freshness rules beyond the three cases refusals.json
 * pins. Those are not cross-implementation contracts — they are this port working.
 */
class UnitTest {

    private static final String SEED_AID = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    private static final String URL_QUERY = "https://api.example.com/things?limit=1&sort=name";
    private static final long SIGNED_AT = 1_700_000_000L;
    private static final byte[] BODY = "{\"hello\": \"world\"}".getBytes(StandardCharsets.UTF_8);

    private static Key key() {
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) {
            seed[i] = (byte) i;
        }
        return Key.fromSeed(seed);
    }

    private static Map<String, String> headers(String... pairs) {
        Map<String, String> out = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            out.put(pairs[i], pairs[i + 1]);
        }
        return out;
    }

    private static String line(String component, String method, String url, Map<String, String> hdrs) {
        byte[] base = Fiki.signatureBase(method, url, hdrs, List.of(component),
            Fiki.Params.of(SIGNED_AT, "k"));
        return new String(base, StandardCharsets.UTF_8).split("\n")[0];
    }

    private static Map<String, String> signed(Fiki.SignOptions opts) {
        Fiki.SignOptions withCreated = opts.created() == null ? opts.withCreated(SIGNED_AT) : opts;
        return Fiki.signRequest(key(), "POST", URL_QUERY, Map.of(), withCreated);
    }

    private static FikiException.Kind kindOf(Executable body) {
        return assertThrows(FikiException.class, body::run).kind();
    }

    private interface Executable {
        void run();
    }

    @Test
    void theSeedYieldsTheAidEveryOtherPortDerives() {
        assertEquals(SEED_AID, key().aid());
        assertEquals(32, key().seed().length);
        assertNotEquals(key().aid(), Key.generate().aid());
        assertEquals(SEED_AID, Key.toAid(Key.verifyingKeyBytes(SEED_AID)));
    }

    @Test
    void aSeedOfTheWrongLengthIsRefused() {
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> Key.fromSeed(new byte[31])));
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> Key.fromSeed(null)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",   // too short
        "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // too long
        "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  // transferable prefix
        "B!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",  // outside the alphabet
        // "=" is inside base64's alphabet, so a lenient decoder would take this and decode short.
        "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
    })
    void malformedAidsAreRefused(String aid) {
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> Key.verifyingKeyBytes(aid)));
    }

    @Test
    void derivedComponents() {
        assertEquals("\"@authority\": api.example.com",
            line("@authority", "GET", "/things", headers("Host", "API.example.com")));
        assertEquals("\"@authority\": example.com",
            line("@authority", "GET", "https://EXAMPLE.com:443/f", Map.of()));
        assertEquals("\"@authority\": example.com:8443",
            line("@authority", "GET", "https://example.com:8443/f", Map.of()));
        assertEquals("\"@path\": /", line("@path", "GET", "https://example.com", Map.of()));
        assertEquals("\"@path\": /f", line("@path", "GET", "https://example.com/f#frag", Map.of()));
        assertEquals("\"@query\": ?", line("@query", "GET", "https://example.com/f", Map.of()));
        assertEquals("\"@query\": ?baz=bat%2Dman",
            line("@query", "GET", "https://example.com/p?baz=bat%2Dman", Map.of()));
        assertEquals("\"@method\": POST", line("@method", "post", "https://example.com/f", Map.of()));
        assertEquals("\"content-type\": application/json",
            line("Content-Type", "GET", "https://x.example/f", headers("Content-Type", "  application/json  ")));
    }

    @Test
    void unbuildableAndMissingComponentsAreRefused() {
        assertEquals(FikiException.Kind.UnsupportedComponent,
            kindOf(() -> line("@target-uri", "GET", "https://x.example/f", Map.of())));
        assertEquals(FikiException.Kind.MissingComponent,
            kindOf(() -> line("x-absent", "GET", "https://x.example/f", Map.of())));
        assertEquals(FikiException.Kind.MissingComponent,
            kindOf(() -> line("@authority", "GET", "/things", Map.of())));
    }

    @Test
    void optionalParametersSerializeInAFixedOrder() {
        byte[] base = Fiki.signatureBase("GET", "https://x.example/f", Map.of(), List.of("@method"),
            new Fiki.Params(SIGNED_AT, "k", "ed25519", SIGNED_AT + 60, "abc", "app"));
        String[] lines = new String(base, StandardCharsets.UTF_8).split("\n");
        assertEquals(
            "\"@signature-params\": (\"@method\");created=1700000000;expires=1700000060;"
                + "nonce=\"abc\";alg=\"ed25519\";keyid=\"k\";tag=\"app\"",
            lines[lines.length - 1]);
    }

    @Test
    void signAndVerifyRoundTrip() {
        Map<String, String> out = signed(Fiki.SignOptions.none().withBody(BODY));
        assertTrue(out.containsKey("Content-Digest"));
        Fiki.Verdict verdict = Fiki.verifyRequest("POST", URL_QUERY, out,
            Fiki.VerifyOptions.decliningFreshness().withBody(BODY));
        assertEquals(SEED_AID, verdict.aid());
        assertTrue(verdict.covered().contains("content-digest"));
    }

    @Test
    void theKeyidCarriesTheRawKeyRatherThanTheAid() {
        Map<String, String> out = signed(Fiki.SignOptions.none());
        String keyid = out.get("Signature-Input").split("keyid=\"")[1].split("\"")[0];
        assertEquals(43, keyid.length());
    }

    @Test
    void aChosenCoveredSetOmittingTheDigestRefusesABody() {
        assertEquals(FikiException.Kind.UncoveredBody, kindOf(() -> Fiki.signRequest(
            key(), "POST", URL_QUERY, Map.of(),
            Fiki.SignOptions.none().withBody(BODY).withCovered(List.of("@method")))));
    }

    @Test
    void aChosenCoveredSetIncludingTheDigestSignsABody() {
        Map<String, String> out = signed(Fiki.SignOptions.none().withBody(BODY)
            .withCovered(List.of("@method", "@path", "content-digest")).withLabel("mine"));
        assertTrue(out.get("Signature-Input").startsWith("mine="));
        Fiki.verifyRequest("POST", URL_QUERY, out,
            Fiki.VerifyOptions.decliningFreshness().withBody(BODY));
    }

    @Test
    void aCallerSuppliedDigestIsUsedRatherThanRecomputed() {
        Map<String, String> supplied = headers("Content-Digest", Fiki.contentDigest(BODY));
        Map<String, String> out = Fiki.signRequest(key(), "POST", URL_QUERY, supplied,
            Fiki.SignOptions.none().withBody(BODY).withCreated(SIGNED_AT));
        assertFalse(out.containsKey("Content-Digest"), "fiki should not echo back a digest it was given");
        Map<String, String> all = new LinkedHashMap<>(supplied);
        all.putAll(out);
        Fiki.verifyRequest("POST", URL_QUERY, all,
            Fiki.VerifyOptions.decliningFreshness().withBody(BODY));
    }

    @Test
    void signingWithoutACreatedUsesTheWallClock() {
        Map<String, String> out =
            Fiki.signRequest(key(), "GET", URL_QUERY, null, Fiki.SignOptions.none());
        Fiki.verifyRequest("GET", URL_QUERY, out, Fiki.VerifyOptions.maxAge(300));
    }

    @Test
    void anExpectedAidIsAuthoritativeOverTheInlineKeyid() {
        Map<String, String> out = signed(Fiki.SignOptions.none());
        assertEquals(SEED_AID, Fiki.verifyRequest("POST", URL_QUERY, out,
            Fiki.VerifyOptions.decliningFreshness().withExpectedAid(SEED_AID)).aid());
        String stranger = Key.generate().aid();
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> Fiki.verifyRequest(
            "POST", URL_QUERY, out, Fiki.VerifyOptions.decliningFreshness().withExpectedAid(stranger))));
    }

    @Test
    void aMalformedExpectedAidIsRefused() {
        Map<String, String> out = signed(Fiki.SignOptions.none());
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() -> Fiki.verifyRequest(
            "POST", URL_QUERY, out, Fiki.VerifyOptions.decliningFreshness().withExpectedAid("nope"))));
    }

    @Test
    void aCoveredComponentTheVerifierCannotBuildIsRefused() {
        Map<String, String> out = new LinkedHashMap<>(signed(Fiki.SignOptions.none()));
        out.put("Signature-Input",
            out.get("Signature-Input").replaceFirst("\\(\"@method\"", "(\"@target-uri\""));
        assertEquals(FikiException.Kind.UnsupportedComponent, kindOf(() ->
            Fiki.verifyRequest("POST", URL_QUERY, out, Fiki.VerifyOptions.decliningFreshness())));
    }

    @Test
    void digestHandling() {
        record Case(String digest, FikiException.Kind expected) {}
        List<Case> cases = List.of(
            new Case("sha-1=:AAAA:, " + Fiki.contentDigest(BODY), null),
            new Case("sha-1=:AAAA:", FikiException.Kind.MalformedDigest),
            new Case("sha-256=\"not bytes\"", FikiException.Kind.MalformedDigest),
            new Case("((( not sfv", FikiException.Kind.MalformedDigest));
        for (Case c : cases) {
            Map<String, String> supplied = headers("Content-Digest", c.digest());
            Map<String, String> out = Fiki.signRequest(key(), "POST", URL_QUERY, supplied,
                Fiki.SignOptions.none().withBody(BODY).withCreated(SIGNED_AT));
            Map<String, String> all = new LinkedHashMap<>(supplied);
            all.putAll(out);
            if (c.expected() == null) {
                Fiki.verifyRequest("POST", URL_QUERY, all,
                    Fiki.VerifyOptions.decliningFreshness().withBody(BODY));
            } else {
                assertEquals(c.expected(), kindOf(() -> Fiki.verifyRequest("POST", URL_QUERY, all,
                    Fiki.VerifyOptions.decliningFreshness().withBody(BODY))), c.digest());
            }
        }
    }

    @Test
    void freshness() {
        Map<String, String> out = signed(Fiki.SignOptions.none());
        Fiki.verifyRequest("POST", URL_QUERY, out, Fiki.VerifyOptions.maxAge(300).withNow(SIGNED_AT + 299));
        Fiki.verifyRequest("POST", URL_QUERY, out, Fiki.VerifyOptions.maxAge(300).withNow(SIGNED_AT + 303));
        assertEquals(FikiException.Kind.SignatureTooOld, kindOf(() -> Fiki.verifyRequest(
            "POST", URL_QUERY, out, Fiki.VerifyOptions.maxAge(300).withNow(SIGNED_AT + 400))));
        assertEquals(FikiException.Kind.SignatureTooOld, kindOf(() -> Fiki.verifyRequest(
            "POST", URL_QUERY, out, Fiki.VerifyOptions.maxAge(300).withSkew(0).withNow(SIGNED_AT + 301))));
        assertEquals(FikiException.Kind.SignatureTooOld, kindOf(() -> Fiki.verifyRequest(
            "POST", URL_QUERY, out, Fiki.VerifyOptions.maxAge(300).withNow(SIGNED_AT - 60))));
        Fiki.verifyRequest("POST", URL_QUERY, out,
            Fiki.VerifyOptions.decliningFreshness().withNow(SIGNED_AT + 1_000_000));
    }

    @Test
    void expiresIsEnforcedEvenWhenMaxAgeIsDeclined() {
        Map<String, String> out = signed(Fiki.SignOptions.none().withExpires(SIGNED_AT + 60));
        Fiki.verifyRequest("POST", URL_QUERY, out,
            Fiki.VerifyOptions.decliningFreshness().withNow(SIGNED_AT + 30));
        assertEquals(FikiException.Kind.SignatureExpired, kindOf(() -> Fiki.verifyRequest(
            "POST", URL_QUERY, out, Fiki.VerifyOptions.decliningFreshness().withNow(SIGNED_AT + 66))));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "1=2", "a=\"oops", "a=\"o\\ps\"", "a=:not base64!:", "a=:AAAA", "a=?2", "a=?",
        "a=%bad", "a=(\"@method\"", "a=(\"@method\";q=1)", "a=(1)", "a=(\"@method\"\"@path\")",
        "a=1 b=2", "a=1, ", "a=-", "a=", "a;x=%", "a=(%)",
    })
    void theParserRefusesWhatItShould(String text) {
        assertThrows(Sfv.SyntaxException.class, () -> Sfv.parseDictionary(text));
    }

    @Test
    void theParserRoundTripsWhatRfc9421PutsInSignatureInput() {
        List<Sfv.Member> parsed =
            Sfv.parseDictionary("sig=(\"@method\" \"@path\");created=1;keyid=\"k\";alg=\"ed25519\"");
        assertEquals("(\"@method\" \"@path\");created=1;keyid=\"k\";alg=\"ed25519\"",
            Sfv.serializeInnerList(parsed.get(0).list()));
        assertEquals("(\"a\\\"b\\\\c\");f;g=?0", Sfv.serializeInnerList(new Sfv.InnerList(
            List.of("a\"b\\c"), List.of(Map.entry("f", Boolean.TRUE), Map.entry("g", Boolean.FALSE)))));
    }

    @Test
    void theParserReadsTheShapesRfc8941AllowsHere() {
        for (String text : List.of("a=?1", "a=?0", "a=-12", "a", "a;x", "a=()", "  a=1  ", "a=:AAAA:")) {
            Sfv.parseDictionary(text);
        }
    }
}
