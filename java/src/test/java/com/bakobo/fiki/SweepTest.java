package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The 0.8.0 cross-port sweep's rules that no vector can pin, because they are API behaviour
 * (this.i @5zrf8gjk): caller errors, exported constants and documentation. Each test names its
 * rule from the sweep spec.
 */
class SweepTest {

    private static final Key KEY = Key.fromSeed(new byte[32]);
    private static final String URL = "https://example.com/p?q=1";
    private static final long AT = 1_700_000_000L;
    private static final byte[] BODY = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);

    private static Map<String, String> sign(String method, String url, Map<String, String> given,
            UnaryOperator<Fiki.SignOptions> opts) {
        Map<String, String> headers = new LinkedHashMap<>(given);
        headers.putAll(Fiki.signRequest(KEY, method, url, given, opts.apply(Fiki.SignOptions.none().withCreated(AT))));
        return headers;
    }

    private static Map<String, String> sign() {
        return sign("GET", URL, Map.of(), opts -> opts);
    }

    private static Fiki.VerifyOptions declined() {
        return Fiki.VerifyOptions.decliningFreshness();
    }

    private static FikiException.Kind kindOf(Runnable body) {
        return assertThrows(FikiException.class, body::run).kind();
    }

    /* ------------------------------------------------------------------------- A4 headers */

    @Test
    void a4TwoHeaderNamesEqualIgnoringCaseAreACallerErrorEverywhere() {
        Map<String, String> twice = new LinkedHashMap<>();
        twice.put("X-Role", "admin");
        twice.put("x-role", "guest");
        assertThrows(IllegalArgumentException.class, () -> sign("GET", URL, twice, opts -> opts));
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest("GET", URL, twice, declined()));
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyResponse(200, twice, null, declined()));
        assertThrows(IllegalArgumentException.class, () -> new Fiki.Request("GET", URL, twice, null));
    }

    @Test
    void a4ANullHeaderNameOrValueIsACallerError() {
        Map<String, String> nullName = new HashMap<>();
        nullName.put(null, "x");
        Map<String, String> nullValue = new HashMap<>();
        nullValue.put("x", null);
        for (Map<String, String> bad : List.of(nullName, nullValue)) {
            assertThrows(IllegalArgumentException.class, () -> sign("GET", URL, bad, opts -> opts));
            assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest("GET", URL, bad, declined()));
            assertThrows(IllegalArgumentException.class, () -> new Fiki.Request("GET", URL, bad, null));
        }
    }

    /* ------------------------------------------------------------------ A6 linear parsing */

    @Test
    void a6ParametersAndMembersParseInLinearTime() {
        int n = 100_000;
        StringBuilder params = new StringBuilder("sig=(\"@method\")");
        StringBuilder members = new StringBuilder();
        for (int i = 0; i < n; i++) {
            params.append(";p").append(i).append('=').append(i);
            members.append(i == 0 ? "" : ", ").append('m').append(i).append("=1");
        }
        org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
            assertEquals(n, ((Sfv.InnerList) Sfv.parseDictionary(params.toString()).get(0).value()).params().size());
            assertEquals(n, Sfv.parseDictionary(members.toString()).size());
        });
    }

    /* ------------------------------------------------- A7 and E5: a caller-supplied digest */

    @ParameterizedTest
    @ValueSource(strings = {"sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:", "x-unknown=:AAAA:", "(((", "sha-256=1"})
    void a7ASuppliedDigestTheBodyDoesNotMatchIsACallerError(String digest) {
        Map<String, String> given = Map.of("Content-Digest", digest);
        assertThrows(IllegalArgumentException.class, () -> sign("POST", URL, given, opts -> opts.withBody(BODY)));
        assertThrows(IllegalArgumentException.class, () -> Fiki.signResponse(KEY, 200, null, given,
            Fiki.SignOptions.none().withCreated(AT).withBody(BODY)));
    }

    @Test
    void a7ASuppliedDigestThatMatchesIsSignedAsGiven() {
        String digest = Fiki.contentDigest(BODY);
        Map<String, String> signed = sign("POST", URL, Map.of("content-digest", digest), opts -> opts.withBody(BODY));
        assertEquals(digest, signed.get("content-digest"));
        assertEquals(KEY.aid(), Fiki.verifyRequest("POST", URL, signed, declined().withBody(BODY)).aid());
    }

    /* --------------------------------------------------------- A8 Content-Length whitespace */

    @ParameterizedTest
    @ValueSource(strings = {"0\u000b", "\u000c0", "0 ", " 0", "0\r"})
    void a8AContentLengthPaddedWithOtherWhitespaceCountsAsABody(String length) {
        Map<String, String> signed = sign("GET", URL, Map.of("Content-Length", length), opts -> opts);
        assertEquals(FikiException.Kind.InsufficientCoverage, kindOf(() ->
            Fiki.verifyRequest("GET", URL, signed, declined().withMinimum(Fiki.REQUEST_MINIMUM))));
    }

    @Test
    void a8AContentLengthPaddedWithSpAndHtabIsStillZero() {
        Map<String, String> signed = sign("GET", URL, Map.of("Content-Length", " \t0\t "), opts -> opts);
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, signed, declined().withMinimum(Fiki.REQUEST_MINIMUM)).aid());
    }

    /* ----------------------------------------------- A9 lookups keyed by untrusted input */

    @ParameterizedTest
    @ValueSource(strings = {"constructor", "hashcode", "getclass", "tostring", "__proto__"})
    void a9AnInheritedMemberNameIsNeverASignatureParameter(String name) {
        Map<String, String> signed = sign();
        String input = signed.get("Signature-Input");
        signed.put("Signature-Input", input + ";" + name + "=1");
        assertEquals(FikiException.Kind.MalformedSignatureInput, kindOf(() -> Fiki.verifyRequest("GET", URL, signed, declined())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"constructor", "hashcode", "getclass", "tostring", "__proto__"})
    void a9AnInheritedMemberNameIsNeverADigestAlgorithm(String name) {
        Map<String, String> given = Map.of("Content-Digest", name + "=:AAAA:");
        Map<String, String> signed = new LinkedHashMap<>(given);
        byte[] base = Fiki.signatureBase("POST", URL, given, List.of("@method", "content-digest"),
            new Fiki.Params(AT, KEY.keyid(), null, null, null, null));
        String text = new String(base, StandardCharsets.UTF_8);
        signed.put("Signature-Input", "sig=" + text.substring(text.lastIndexOf(": (") + 2));
        signed.put("Signature", "sig=:" + java.util.Base64.getEncoder().encodeToString(KEY.sign(base)) + ":");
        assertEquals(FikiException.Kind.MalformedDigest, kindOf(() ->
            Fiki.verifyRequest("POST", URL, signed, declined().withBody(BODY))));
    }

    /* ------------------------------------------------------- A10 with A1: the keyid order */

    @Test
    void a10ASmallOrderRawKeyidBesideAnExpectedKeyidIsMalformedNotUnknown() {
        String identity = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            java.util.HexFormat.of().parseHex("0100000000000000000000000000000000000000000000000000000000000000"));
        Map<String, String> signed = sign("GET", URL, Map.of(), opts -> opts.withKeyid(identity));
        assertEquals(FikiException.Kind.MalformedKey, kindOf(() ->
            Fiki.verifyRequest("GET", URL, signed, declined().withExpectedKeyid(KEY.keyid()))));
    }

    @Test
    void a10AnUnexpectedKeyidIsUnknownWithoutAskingTheResolver() {
        String aid = "E" + "A".repeat(43);
        Map<String, String> signed = sign("GET", URL, Map.of(), opts -> opts.withKeyid(aid));
        AtomicInteger asked = new AtomicInteger();
        assertEquals(FikiException.Kind.UnknownKey, kindOf(() -> Fiki.verifyRequest("GET", URL, signed,
            declined().withExpectedKeyid("E" + "B".repeat(43)).withResolver(k -> {
                asked.incrementAndGet();
                return null;
            }))));
        assertEquals(0, asked.get());
    }

    /* ----------------------------------------------------------------------- B13 methods */

    @ParameterizedTest
    @ValueSource(strings = {"", "GET ", "G\tT", "GE\r\nT", "GET\n", "(GET)", "GÉT", "a,b"})
    void b13AMethodThatIsNotATokenIsACallerErrorWhereverARequestIsBuilt(String method) {
        assertThrows(IllegalArgumentException.class, () -> sign(method, URL, Map.of(), opts -> opts));
        assertThrows(IllegalArgumentException.class, () -> sign(method, URL, Map.of(), opts -> opts.withCovered(List.of("@path"))));
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest(method, URL, sign(), declined()));
        assertThrows(IllegalArgumentException.class, () -> Fiki.signatureBase(method, URL, Map.of(), List.of("@path"),
            new Fiki.Params(AT, null, null, null, null, null)));
        assertThrows(IllegalArgumentException.class, () -> new Fiki.Request(method, URL, Map.of(), null));
    }

    @Test
    void b13ANullMethodIsACallerError() {
        assertThrows(IllegalArgumentException.class, () -> sign(null, URL, Map.of(), opts -> opts));
        assertThrows(IllegalArgumentException.class, () -> Fiki.verifyRequest(null, URL, sign(), declined()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"get", "M-SEARCH", "PROPFIND", "x!#$%&'*+.^_`|~1"})
    void b13AnyTokenIsAMethodAndKeepsItsCase(String method) {
        Map<String, String> signed = sign(method, URL, Map.of(), opts -> opts);
        assertEquals(KEY.aid(), Fiki.verifyRequest(method, URL, signed, declined()).aid());
        String base = new String(Fiki.signatureBase(method, URL, Map.of(), List.of("@method"),
            new Fiki.Params(null, null, null, null, null, null)), StandardCharsets.UTF_8);
        assertTrue(base.startsWith("\"@method\": " + method + "\n"), base);
    }

    /* ------------------------------------------------------------------------- B14 ports */

    @ParameterizedTest
    @ValueSource(strings = {"65536", "44x", "-1", "８０", "99999999999999999999", "+80"})
    void b14APortThatIsNotOneIsACallerErrorWhenSigningAndAMismatchWhenVerifying(String port) {
        String bad = "https://example.com:" + port + "/p";
        assertThrows(IllegalArgumentException.class, () -> sign("GET", bad, Map.of(), opts -> opts));
        Map<String, String> signed = sign();
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> Fiki.verifyRequest("GET", bad, signed, declined())));
    }

    @Test
    void b14ABadPortIsNeverReadWhenAuthorityIsNotCovered() {
        String bad = "https://example.com:44x/p";
        Map<String, String> signed = sign("GET", bad, Map.of(), opts -> opts.withCovered(List.of("@method", "@path")));
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", bad, signed, declined()).aid());
    }

    /* ---------------------------- A3 and PR #14's hostile pass: what an IP-literal holds */

    private static String authorityOf(String url) {
        String base = new String(Fiki.signatureBase("GET", url, Map.of(), List.of("@authority"),
            Fiki.Params.of(AT, "k")), StandardCharsets.UTF_8);
        return base.substring("\"@authority\": ".length(), base.indexOf('\n'));
    }

    // The same lists as fiki-py's tests/test_sweep.py, whose oracle is Python's own ipaddress.
    @ParameterizedTest
    @ValueSource(strings = {"not-an-ip", "1.2.3.4", "vZ.x", "v1.", "V1.x", "v.x", "::1%", "fe80::1%a%b",
        "1:2:3:4:5:6:7:8:9", "::01.2.3.4", "::256.1.1.1", "12345::", "", "1::2::3"})
    void a3ABracketedHostThatIsNotAnAddressIsUnreadable(String inside) {
        String url = "https://[" + inside + "]/x";
        assertThrows(IllegalArgumentException.class, () -> authorityOf(url));
        Map<String, String> signed = sign("GET", "https://[::1]/x", Map.of(), opts -> opts);
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> Fiki.verifyRequest("GET", url, signed, declined())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"::1", "::", "1::", "2001:DB8::1", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::",
        "::ffff:1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "fe80::1%25eth0", "v1.x", "vF.a:b", "v12.["})
    void a3AnIpv6AddressOrIpvFutureIsAnIpLiteral(String inside) {
        assertEquals("[" + inside.toLowerCase(java.util.Locale.ROOT) + "]", authorityOf("https://[" + inside + "]/x"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"a]b[", "a]b", "a[b"})
    void a3ABracketOutsideAnIpLiteralIsUnreadable(String host) {
        String url = "https://" + host + "/x";
        assertThrows(IllegalArgumentException.class, () -> authorityOf(url));
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> Fiki.verifyRequest("GET", url, sign(), declined())));
    }

    /* ------------------------ B14 and PR #14's hostile pass: ports of thousands of digits */

    @Test
    void b14APortOfThousandsOfLeadingZerosIsReadAsItsNumber() {
        String zeros = "0".repeat(5000);
        assertEquals("a.example", authorityOf("https://a.example:" + zeros + "443/x"));
        assertEquals("a.example:8443", authorityOf("https://a.example:" + zeros + "8443/x"));
        for (String port : List.of(zeros + "65536", "1" + zeros, "9".repeat(5000))) {
            assertThrows(IllegalArgumentException.class, () -> authorityOf("https://a.example:" + port + "/x"));
        }
    }

    /* ------------------- PR #14's hostile pass: a header that cannot be encoded as UTF-8 */

    @ParameterizedTest
    @ValueSource(strings = {"\ud800", "sig=:\udfff:"})
    void aSignatureHeaderHoldingAnUnpairedSurrogateIsMalformed(String value) {
        Map<String, String> signature = sign();
        signature.put("Signature", value);
        assertEquals(FikiException.Kind.MalformedSignature, kindOf(() -> Fiki.verifyRequest("GET", URL, signature, declined())));
        Map<String, String> input = sign();
        input.put("Signature-Input", value);
        assertEquals(FikiException.Kind.MalformedSignatureInput, kindOf(() -> Fiki.verifyRequest("GET", URL, input, declined())));
    }

    @Test
    void b14ABadPortInTheRequestAResponseAnswersIsAMismatch() {
        Fiki.Request good = new Fiki.Request("GET", "https://example.com/p", Map.of(), null);
        Map<String, String> headers = new LinkedHashMap<>(Fiki.signResponse(KEY, 200, good, Map.of(),
            Fiki.SignOptions.none().withCreated(AT).withCovered(List.of("@status", Fiki.req("@authority")))));
        Fiki.Request bad = new Fiki.Request("GET", "https://example.com:70000/p", Map.of(), null);
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() -> Fiki.verifyResponse(200, headers, bad, declined())));
        assertThrows(IllegalArgumentException.class, () -> Fiki.signResponse(KEY, 200, bad, Map.of(),
            Fiki.SignOptions.none().withCreated(AT).withCovered(List.of("@status", Fiki.req("@authority")))));
    }

    @Test
    void b14AnEmptyPortIsNoPortAndZeroesAreRead() {
        Fiki.Params params = new Fiki.Params(null, null, null, null, null, null);
        for (String[] pair : new String[][] {
                {"https://example.com:/p", "example.com"}, {"https://example.com:000443/p", "example.com"},
                {"https://example.com:08443/p", "example.com:8443"}, {"http://example.com:0/p", "example.com:0"}}) {
            String base = new String(Fiki.signatureBase("GET", pair[0], Map.of(), List.of("@authority"), params),
                StandardCharsets.UTF_8);
            assertTrue(base.startsWith("\"@authority\": " + pair[1] + "\n"), base);
        }
    }

    @Test
    void tabCrAndLfAreRemovedFromAUrlAsPythonsUrlsplitRemovesThem() {
        // The conductor's ruling of 2026-10-08 for the spec's open item: match py and go.
        String base = new String(Fiki.signatureBase("GET", "ht\ttps://h.exa\tmple:84\r43/a\r\nb?q=\t1#f\n",
            Map.of(), List.of("@authority", "@path", "@query"), new Fiki.Params(null, null, null, null, null, null)),
            StandardCharsets.UTF_8);
        assertTrue(base.startsWith("\"@authority\": h.example:8443\n\"@path\": /ab\n\"@query\": ?q=1\n"), base);
        Map<String, String> signed = sign();
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", "https://exam\tple.com/p?q=\r\n1", signed, declined()).aid());
    }

    @Test
    void leadingC0ControlsAndSpacesAreStrippedFromAUrlAndTrailingOnesAreNot() {
        // As Python's urlsplit strips them, checked against fiki-py on this branch.
        Fiki.Params params = new Fiki.Params(null, null, null, null, null, null);
        List<String> covered = List.of("@authority", "@path", "@query");
        String clean = new String(Fiki.signatureBase("GET", "https://api.example.com/x?q=1", Map.of(), covered, params),
            StandardCharsets.UTF_8);
        for (String url : List.of(" \u0001https://api.example.com/x?q=1", "\u0000\u001f https://api.example.com/x?q=1")) {
            assertEquals(clean, new String(Fiki.signatureBase("GET", url, Map.of(), covered, params), StandardCharsets.UTF_8));
        }
        assertEquals(FikiException.Kind.SignatureMismatch, kindOf(() ->
            Fiki.signatureBase("GET", "https://api.example.com/x \u0001", Map.of(), covered, params)));
    }

    /* ----------------------------------------------- B15 what the signer serializes */

    @ParameterizedTest
    @ValueSource(strings = {"Bad Name", "x:y", "a\r\nb", "café", "", "x\"y"})
    void b15AComponentNameThatIsNotAFieldNameIsACallerError(String name) {
        assertThrows(IllegalArgumentException.class, () -> sign("GET", URL, Map.of(), opts -> opts.withCovered(List.of(name))));
    }

    @Test
    void b15AnUnknownDerivedComponentKeepsItsOwnRefusal() {
        assertEquals(FikiException.Kind.UnsupportedComponent, kindOf(() ->
            sign("GET", URL, Map.of(), opts -> opts.withCovered(List.of("@target-uri")))));
    }

    @Test
    void b15AFieldNameIsStillLowercasedForALocalCaller() {
        Map<String, String> signed = sign("GET", URL, Map.of("X-A", "1"), opts -> opts.withCovered(List.of("X-A")));
        assertEquals(List.of("x-a"), Fiki.verifyRequest("GET", URL, signed, declined()).covered());
    }

    @Test
    void b15EveryPrintableAsciiCharacterIsASerializableString() {
        StringBuilder all = new StringBuilder();
        for (char ch = 0x20; ch <= 0x7e; ch++) {
            all.append(ch);
        }
        Map<String, String> signed = sign("GET", URL, Map.of(), opts -> opts.withNonce(all.toString()).withTag(all.toString()));
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, signed, declined()).aid());
    }

    /* ----------------------------------------------------------- B16 created and expires */

    @ParameterizedTest
    @ValueSource(longs = {-1L, -999_999_999_999_999L, 1_000_000_000_000_000L, Long.MIN_VALUE, Long.MAX_VALUE})
    void b16ATimestampOutsideTheIntegerRangeIsACallerError(long value) {
        assertThrows(IllegalArgumentException.class, () -> sign("GET", URL, Map.of(), opts -> opts.withCreated(value)));
        assertThrows(IllegalArgumentException.class, () -> sign("GET", URL, Map.of(), opts -> opts.withExpires(value)));
        assertThrows(IllegalArgumentException.class, () -> Fiki.signatureBase("GET", URL, Map.of(), List.of("@method"),
            new Fiki.Params(value, null, null, null, null, null)));
    }

    @Test
    void b16TheLargestAndSmallestTimestampsAreSigned() {
        Map<String, String> signed = sign("GET", URL, Map.of(),
            opts -> opts.withCreated(999_999_999_999_999L).withExpires(0));
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, signed, declined().withNow(0)).aid());
    }

    /* --------------------------------------------------------------- B17 freshness policy */

    @ParameterizedTest
    @ValueSource(longs = {0L, -1L, Long.MIN_VALUE})
    void b17AFreshnessWindowThatIsNotPositiveIsACallerError(long value) {
        assertThrows(IllegalArgumentException.class, () -> Fiki.VerifyOptions.maxAge(value));
        assertThrows(IllegalArgumentException.class, () -> declined().withSkew(value));
    }

    @Test
    void b17EnormousWindowsNeitherOverflowNorRefuse() {
        Map<String, String> signed = sign();
        Fiki.VerifyOptions huge = Fiki.VerifyOptions.maxAge(Long.MAX_VALUE).withSkew(Long.MAX_VALUE);
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, signed, huge.withNow(Long.MAX_VALUE)).aid());
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, signed, huge.withNow(Long.MIN_VALUE)).aid());
        assertEquals(KEY.aid(), Fiki.verifyRequest("GET", URL, signed, declined()).aid());
    }

    /* ---------------------------------------------------------------------- B18 Verdict */

    @Test
    void b18TheVerdictKeyidIsTheWireKeyidAndTheAidIsWhoVouched() {
        Map<String, String> signed = sign();
        Fiki.Verdict raw = Fiki.verifyRequest("GET", URL, signed, declined());
        assertEquals(KEY.keyid(), raw.keyid());
        assertEquals(KEY.aid(), raw.aid());
        Fiki.Verdict expected = Fiki.verifyRequest("GET", URL, signed, declined().withExpectedAid(KEY.aid()));
        assertEquals(KEY.keyid(), expected.keyid());
        assertEquals(KEY.aid(), expected.aid());
        // A signer that names no keyid at all, which only the base functions can produce.
        byte[] base = Fiki.signatureBase("GET", URL, Map.of(), List.of("@method"),
            new Fiki.Params(AT, null, null, null, null, null));
        String text = new String(base, StandardCharsets.UTF_8);
        Map<String, String> anonymous = Map.of(
            "Signature-Input", "sig=" + text.substring(text.lastIndexOf(": (") + 2),
            "Signature", "sig=:" + java.util.Base64.getEncoder().encodeToString(KEY.sign(base)) + ":");
        Fiki.Verdict none = Fiki.verifyRequest("GET", URL, anonymous, declined().withExpectedAid(KEY.aid()));
        assertNull(none.keyid());
        assertEquals(KEY.aid(), none.aid());
        String aid = "E" + "A".repeat(43);
        Map<String, String> resolved = sign("GET", URL, Map.of(), opts -> opts.withKeyid(aid));
        Fiki.Verdict vouched = Fiki.verifyRequest("GET", URL, resolved,
            declined().withResolver(k -> Key.verifyingKeyBytes(KEY.aid())));
        assertEquals(aid, vouched.keyid());
        assertEquals(aid, vouched.aid());
    }

    @Test
    void b18TheVerdictDocumentsBothFields() throws Exception {
        String source = Files.readString(new File("src/main/java/com/bakobo/fiki/Fiki.java").toPath(), StandardCharsets.UTF_8);
        int at = source.indexOf("public record Verdict(");
        String doc = source.substring(source.lastIndexOf("/**", at), at).replaceAll("\\s*\\n\\s*\\*", "");
        assertTrue(doc.contains("exactly as it appeared on the wire"), doc);
        assertTrue(doc.contains("or null when the signature had none"), doc);
        assertTrue(doc.contains("the identity that vouched for the key"), doc);
    }

    /* ------------------------------------------------------- B19 and E3: the constants */

    @Test
    void b19BothVectorsFormatsAreExported() {
        assertEquals(2, Fiki.VECTORS_FORMAT);
        assertEquals(4, Fiki.KERI_VECTORS_FORMAT);
    }

    @Test
    void e3TheBoundsAreExportedConstants() {
        assertEquals(8192, Fiki.MAX_FIELD_BYTES);
        assertEquals(16, Fiki.MAX_DICTIONARY_MEMBERS);
        assertEquals(64, Fiki.MAX_INNER_LIST_ITEMS);
        assertEquals(16, Fiki.MAX_PARAMETERS);
    }

    /* ------------------------------------------------- B20: bounds beyond what vectors pin */

    @Test
    void b20AFieldIsMeasuredInBytesOnItsRawValue() {
        // Trailing spaces a parser would accept: only the bound, taken before trimming, refuses it.
        Map<String, String> padded = sign();
        String input = padded.get("Signature-Input");
        padded.put("Signature-Input", input + " ".repeat(Fiki.MAX_FIELD_BYTES + 1 - input.length()));
        assertEquals(FikiException.Kind.MalformedSignatureInput, kindOf(() -> Fiki.verifyRequest("GET", URL, padded, declined())));
    }

    @Test
    void b20AParameterCountIsBoundedOnTheInnerListAndOnEachItem() {
        Map<String, String> signed = sign();
        String input = signed.get("Signature-Input");
        StringBuilder more = new StringBuilder();
        for (int i = 0; i < Fiki.MAX_PARAMETERS; i++) {
            more.append(";p").append(i);
        }
        signed.put("Signature-Input", input + more);
        assertEquals(FikiException.Kind.MalformedSignatureInput, kindOf(() -> Fiki.verifyRequest("GET", URL, signed, declined())));
        Map<String, String> item = sign();
        item.put("Signature-Input", item.get("Signature-Input").replace("\"@method\"", "\"@method\"" + more + ";q"));
        assertEquals(FikiException.Kind.MalformedSignatureInput, kindOf(() -> Fiki.verifyRequest("GET", URL, item, declined())));
        Map<String, String> member = sign();
        member.put("Signature", member.get("Signature") + more + ";q");
        assertEquals(FikiException.Kind.MalformedSignature, kindOf(() -> Fiki.verifyRequest("GET", URL, member, declined())));
    }
}
