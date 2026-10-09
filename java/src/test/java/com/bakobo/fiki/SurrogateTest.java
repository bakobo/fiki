package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * A lone UTF-16 surrogate in every untrusted string fiki measures or character-checks (tick 7us4).
 *
 * <p>A Java string can hold one, and no JSON vector carries one portably, so this is a native test.
 * Each input is refused as fiki-py refuses the same Python string, which can hold a lone surrogate
 * too; the comment on each case names the py path it takes, found by calling fiki-py with it. Every
 * size is counted as py's {@code len(value.encode("utf-8", "surrogatepass"))} counts it, where a
 * lone surrogate is three bytes, and not as {@code getBytes(UTF_8)}, which replaces one with a
 * single {@code ?}. Each refusal asserts a fragment of fiki's own message, so a refusal for some
 * other reason, or an exception the JDK raised, cannot pass.
 */
class SurrogateTest {

    private static final Key KEY = Key.fromSeed(new byte[32]);
    private static final String URL = "https://example.com/p";
    private static final long AT = 1_700_000_000L;

    private static Map<String, String> sign(String url, Map<String, String> given,
            Function<Fiki.SignOptions, Fiki.SignOptions> opts) {
        Map<String, String> headers = new LinkedHashMap<>(given);
        headers.putAll(Fiki.signRequest(KEY, "POST", url, given, opts.apply(Fiki.SignOptions.none().withCreated(AT))));
        return headers;
    }

    private static Map<String, String> signed(List<String> covered) {
        return sign(URL, Map.of(), opts -> opts.withCovered(covered));
    }

    private static Fiki.Verdict verify(String url, Map<String, String> headers) {
        return Fiki.verifyRequest("POST", url, headers, OptedOut.decliningFreshness());
    }

    private static void refused(FikiException.Kind kind, String fragment, Runnable body) {
        FikiException e = assertThrows(FikiException.class, body::run);
        assertEquals(kind, e.kind(), e.getMessage());
        assertTrue(e.getMessage().contains(fragment), e.getMessage());
    }

    private static void callerError(String fragment, Runnable body) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, body::run);
        assertTrue(e.getMessage().contains(fragment), e.getMessage());
    }

    private static Map<String, String> with(Map<String, String> headers, String name, String value) {
        Map<String, String> out = new LinkedHashMap<>(headers);
        out.put(name, value);
        return out;
    }

    private static final String NON_ASCII = "a non-ASCII character";
    private static final String NO_UTF8 = "has no UTF-8 encoding";
    private static final String OVER = "over 8192 bytes";

    /* ----------------------------------------------------------------- the target URL */

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInThePathIsABaseThatCannotBeBuilt(String lone) {
        // py: _check_raw on @path, after _split has passed it, on both sides.
        List<String> covered = List.of("@method", "@path");
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII,
            () -> sign(URL + lone, Map.of(), opts -> opts.withCovered(covered)));
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII, () -> verify(URL + lone, signed(covered)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInTheUrlsHostIsAnUnreadableTarget(String lone) {
        // py: _hostport's "its host is not ASCII", a ValueError when signing and a SignatureMismatch
        // when the URL was received.
        String url = "https://exa" + lone + "mple.com/p";
        callerError("its host is not ASCII", () -> sign(url, Map.of(), opts -> opts));
        refused(FikiException.Kind.SignatureMismatch, "its host is not ASCII",
            () -> verify(url, signed(List.of("@method", "@authority"))));
    }

    @Test
    void theUrlBoundCountsALoneSurrogateAsThreeBytes() {
        // py: _split measures with surrogatepass first, so 8193 bytes is unreadable for its size and
        // 8192 bytes passes on to the value check, which refuses the surrogate as non-ASCII.
        List<String> covered = List.of("@method", "@path");
        String atBound = "/a" + "\uD800".repeat(2730);
        String overBound = "/aa" + "\uD800".repeat(2730);
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII,
            () -> sign(atBound, Map.of(), opts -> opts.withCovered(covered)));
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII, () -> verify(atBound, signed(covered)));
        callerError(OVER, () -> sign(overBound, Map.of(), opts -> opts.withCovered(covered)));
        refused(FikiException.Kind.SignatureMismatch, OVER, () -> verify(overBound, signed(covered)));
    }

    /* ---------------------------------------------------------- Host and covered fields */

    private static Map<String, String> signedWithHost() {
        return sign("/p", Map.of("Host", "example.com"), opts -> opts.withCovered(List.of("@method", "@authority")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInHostIsABaseThatCannotBeBuilt(String lone) {
        // py: _check_raw on the Host value, before _hostport reads it, on both sides.
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII,
            () -> sign("/p", Map.of("Host", "example.com" + lone), opts -> opts));
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII,
            () -> verify("/p", with(signedWithHost(), "Host", "example.com" + lone)));
    }

    @Test
    void theHostBoundCountsALoneSurrogateAsThreeBytes() {
        // py: _check_raw measures first, so 2731 surrogates (8193 bytes) are refused for their size.
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII,
            () -> sign("/p", Map.of("Host", "\uD800".repeat(2730)), opts -> opts));
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII,
            () -> verify("/p", with(signedWithHost(), "Host", "\uD800".repeat(2730))));
        refused(FikiException.Kind.SignatureMismatch, OVER,
            () -> sign("/p", Map.of("Host", "\uD800".repeat(2731)), opts -> opts));
        refused(FikiException.Kind.SignatureMismatch, OVER,
            () -> verify("/p", with(signedWithHost(), "Host", "\uD800".repeat(2731))));
    }

    private static final List<String> FIELD = List.of("@method", "x-a");

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInACoveredFieldIsABaseThatCannotBeBuilt(String lone) {
        // py: _check_raw on the field value, on both sides.
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII,
            () -> sign(URL, Map.of("X-A", "v" + lone), opts -> opts.withCovered(FIELD)));
        Map<String, String> good = sign(URL, Map.of("X-A", "v"), opts -> opts.withCovered(FIELD));
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII, () -> verify(URL, with(good, "X-A", "v" + lone)));
    }

    @ParameterizedTest
    @ValueSource(ints = {2730, 2731})
    void theFieldBoundCountsALoneSurrogateAsThreeBytes(int count) {
        // py: _check_raw measures first: 2730 surrogates are 8190 bytes, refused as non-ASCII, and
        // 2731 are 8193, refused for their size.
        String value = "\uD800".repeat(count);
        String fragment = count * 3 > Fiki.MAX_FIELD_BYTES ? OVER : NON_ASCII;
        refused(FikiException.Kind.SignatureMismatch, fragment,
            () -> sign(URL, Map.of("X-A", value), opts -> opts.withCovered(FIELD)));
        Map<String, String> good = sign(URL, Map.of("X-A", "v"), opts -> opts.withCovered(FIELD));
        refused(FikiException.Kind.SignatureMismatch, fragment, () -> verify(URL, with(good, "X-A", value)));
    }

    /* ------------------------------------------------------- the three signature headers */

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInSignatureInputIsMalformed(String lone) {
        // py: _parse refuses a header with no UTF-8 spelling before it counts bytes, wherever the
        // surrogate sits: after the dictionary, inside a string, or as the keyid.
        Map<String, String> good = signed(List.of("@method", "@path"));
        String input = good.get("Signature-Input");
        for (String bad : List.of(input + lone, input.replace("\"@method\"", "\"@me" + lone + "thod\""),
                input.replaceFirst("keyid=\"[^\"]*\"", "keyid=\"k" + lone + "\""))) {
            refused(FikiException.Kind.MalformedSignatureInput, NO_UTF8,
                () -> verify(URL, with(good, "Signature-Input", bad)));
        }
        // Over the byte bound as well: the encoding is refused first, as in py.
        String big = input + " ".repeat(Fiki.MAX_FIELD_BYTES) + lone;
        refused(FikiException.Kind.MalformedSignatureInput, NO_UTF8, () -> verify(URL, with(good, "Signature-Input", big)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInSignatureIsMalformed(String lone) {
        // py: _parse, as for Signature-Input.
        Map<String, String> good = signed(List.of("@method", "@path"));
        refused(FikiException.Kind.MalformedSignature, NO_UTF8,
            () -> verify(URL, with(good, "Signature", good.get("Signature") + lone)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInAContentDigest(String lone) {
        // py, verifying: the covered value is checked when the base is built, before the digest is
        // parsed, so it is a base that cannot be built.
        byte[] body = "x".getBytes(StandardCharsets.UTF_8);
        Map<String, String> good = sign(URL, Map.of(), opts -> opts.withBody(body));
        refused(FikiException.Kind.SignatureMismatch, NON_ASCII, () -> Fiki.verifyRequest("POST", URL,
            with(good, "Content-Digest", good.get("Content-Digest") + lone), OptedOut.decliningFreshness().withBody(body)));
        // py, signing: a caller's own digest is parsed by _parse, whose refusal becomes the call's
        // mistake.
        callerError(NO_UTF8, () -> sign(URL, Map.of("Content-Digest", Fiki.contentDigest(body) + lone),
            opts -> opts.withBody(body)));
    }

    /* ------------------------------------------------------- what a caller names or says */

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInASignersStringParameterIsACallerError(String lone) {
        // py: check_signer_params, a ValueError.
        String fragment = "outside visible ASCII";
        callerError(fragment, () -> sign(URL, Map.of(), opts -> opts.withKeyid("k" + lone)));
        callerError(fragment, () -> sign(URL, Map.of(), opts -> opts.withNonce("k" + lone)));
        callerError(fragment, () -> sign(URL, Map.of(), opts -> opts.withTag("k" + lone)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInALabelIsACallerError(String lone) {
        // py: check_label, a ValueError.
        callerError("is not an RFC 8941 key", () -> sign(URL, Map.of(), opts -> opts.withLabel("sig" + lone)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInAComponentName(String lone) {
        // py: component(), a ValueError for a field name that is not a token, in a covered list and
        // in a verifier's minimum alike.
        callerError("is not an HTTP field name",
            () -> sign(URL, Map.of(), opts -> opts.withCovered(List.of("@method", "x-" + lone))));
        callerError("is not an HTTP field name", () -> Fiki.verifyRequest("POST", URL, signed(List.of("@method")),
            OptedOut.decliningFreshness().withMinimum(List.of("@method", "@path", "@query", "x-" + lone))));
        // py: _component_item, whose UTF-8 encode fails inside http_sfv's parse and is read as a
        // serialized spec that does not parse, UnsupportedComponent; in the name and in a parameter.
        String unreadable = "cannot read";
        refused(FikiException.Kind.UnsupportedComponent, unreadable,
            () -> sign(URL, Map.of(), opts -> opts.withCovered(List.of("@method", "\"x-" + lone + "\""))));
        refused(FikiException.Kind.UnsupportedComponent, unreadable,
            () -> sign(URL, Map.of(), opts -> opts.withCovered(List.of("@method", "\"x-a\";r" + lone))));
        // A derived name: py reads it as one fiki does not build, UnsupportedComponent; this port
        // refuses it sooner as a caller error, by @3e7wnyvg's decision that every component a caller
        // names is an RFC 8941 string.
        callerError("is not an RFC 8941 string",
            () -> sign(URL, Map.of(), opts -> opts.withCovered(List.of("@method", "@pa" + lone))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInTheMethodIsACallerError(String lone) {
        // py: check_method, a ValueError, on both sides.
        String fragment = "one or more token characters";
        callerError(fragment, () -> Fiki.signRequest(KEY, "PO" + lone, URL, Map.of(), Fiki.SignOptions.none()));
        callerError(fragment, () -> Fiki.verifyRequest("PO" + lone, URL, signed(List.of("@method")),
            OptedOut.decliningFreshness()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00"})
    void aSurrogateInAVerifiersOwnDecisionsIsComparedNotRead(String lone) {
        // py: an expected keyid and a served authority are compared exactly and never measured.
        Map<String, String> good = signed(List.of("@method", "@authority"));
        refused(FikiException.Kind.UnknownKey, "the one expected is", () -> Fiki.verifyRequest("POST", URL, good,
            OptedOut.decliningFreshness().withExpectedKeyid("k" + lone)));
        refused(FikiException.Kind.SignatureMismatch, "does not serve", () -> Fiki.verifyRequest("POST", URL, good,
            OptedOut.decliningFreshness().withAuthorities(Set.of("ex" + lone))));
    }
}
