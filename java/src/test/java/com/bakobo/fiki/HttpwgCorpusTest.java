package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * The httpwg structured-field-tests corpus against this port's RFC 8941 parser (this.i @7fexwu3s).
 *
 * <p>Dictionary cases run through {@link Fiki#parse}, the bounded entry point the verifier reads
 * Signature-Input with; item and list cases through {@link Fiki#parseItem} and {@link Fiki#parseList},
 * which apply the same four bounds. The only outcomes allowed are a value, compared exactly with the
 * corpus's, parameters and their order included, or fiki's malformed error. Every case matches the
 * corpus except three kinds, each a recorded fiki decision: a Date or Display String is refused
 * (@7vdhfv3q), an input over any of fiki's bounds is refused (@524c8qgv), and a byte sequence whose
 * padding is missing, partial or extra is refused while non-zero pad bits are accepted (@2g4xxev9,
 * @5zrf8gjk). The bounded dictionary entry point also refuses a dictionary of no members, which the
 * shared vector {@code signature-header-of-spaces} pins (review B7).
 */
class HttpwgCorpusTest {

    // Numbers keep their JSON literal's type: 1.0 is a decimal and 1 an integer.
    private static final ObjectMapper MAPPER =
        new ObjectMapper().enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
    private static final File CORPUS = new File("../vectors/third_party/structured-field-tests");
    private static final FikiException.Kind KIND = FikiException.Kind.MalformedSignatureInput;

    /*
     * The number of cases in each parsing file at the pinned commit, read from the files once when
     * this test was written. Every case runs and none is skipped, so a corpus refresh that shrinks a
     * file, or an emptied one, fails here rather than passing on less.
     */
    private static final Map<String, Integer> PARSE_CASES = Map.ofEntries(
        Map.entry("binary.json", 17),
        Map.entry("boolean.json", 12),
        Map.entry("date.json", 17),
        Map.entry("dictionary.json", 26),
        Map.entry("display-string.json", 22),
        Map.entry("examples.json", 21),
        Map.entry("item.json", 5),
        Map.entry("key-generated.json", 640),
        Map.entry("large-generated.json", 11),
        Map.entry("list.json", 11),
        Map.entry("listlist.json", 12),
        Map.entry("number-generated.json", 193),
        Map.entry("number.json", 37),
        Map.entry("param-dict.json", 14),
        Map.entry("param-list.json", 20),
        Map.entry("param-listlist.json", 3),
        Map.entry("string-generated.json", 256),
        Map.entry("string.json", 14),
        Map.entry("token-generated.json", 256),
        Map.entry("token.json", 6));

    /*
     * How many of those cases fiki accepts, and how many it refuses for each reason, so that a parser
     * change moving a case from one outcome to another shows up as a count rather than hiding in a
     * total that did not move.
     */
    private static final int ACCEPTED = 702;
    private static final int REFUSED_AS_THE_CORPUS_SAYS = 864;
    private static final int REFUSED_DATE_OR_DISPLAY_STRING = 17;
    private static final int REFUSED_OVER_A_BOUND = 6;
    private static final int REFUSED_PADDING = 3;
    private static final int REFUSED_EMPTY_DICTIONARY = 1;

    private static JsonNode load(String name) throws Exception {
        File file = new File(CORPUS, name);
        assertTrue(file.isFile(), "the httpwg corpus is not where every port reaches it: " + file);
        return MAPPER.readTree(file);
    }

    private static String raw(JsonNode c) {
        List<String> lines = new ArrayList<>();
        c.get("raw").forEach(line -> lines.add(line.asText()));
        return String.join(", ", lines);
    }

    /* ------------------------------------------------------------- what fiki must refuse */

    private enum Outcome { ACCEPT, CORPUS_REFUSES, DATE_OR_DISPLAY_STRING, OVER_A_BOUND, PADDING, EMPTY_DICTIONARY }

    private static boolean usesRfc9651(JsonNode node) {
        if (node.isObject() && node.has("__type")) {
            String type = node.get("__type").asText();
            return type.equals("date") || type.equals("displaystring");
        }
        for (JsonNode child : node) {
            if (usesRfc9651(child)) {
                return true;
            }
        }
        return false;
    }

    /** Whether the expected value, or the raw input, is over any bound fiki applies (@524c8qgv). */
    private static boolean overABound(JsonNode c) {
        if (Fiki.utf8Length(raw(c)) > Fiki.MAX_FIELD_BYTES) {
            return true;
        }
        JsonNode expected = c.get("expected");
        String type = c.get("header_type").asText();
        if (type.equals("item")) {
            return overItem(expected);
        }
        if (expected.size() > Fiki.MAX_DICTIONARY_MEMBERS) {
            return true;
        }
        for (JsonNode member : expected) {
            if (overItem(type.equals("dictionary") ? member.get(1) : member)) {
                return true;
            }
        }
        return false;
    }

    // [value, params], where an inner list's value is an array of [item, params].
    private static boolean overItem(JsonNode item) {
        if (item.get(1).size() > Fiki.MAX_PARAMETERS) {
            return true;
        }
        JsonNode value = item.get(0);
        if (value.isArray()) {
            if (value.size() > Fiki.MAX_INNER_LIST_ITEMS) {
                return true;
            }
            for (JsonNode inner : value) {
                if (inner.get(1).size() > Fiki.MAX_PARAMETERS) {
                    return true;
                }
            }
        }
        return false;
    }

    // @2g4xxev9's table of the corpus's can_fail byte sequences.
    private static final Set<String> PADDING_REFUSED = Set.of("unpadded", "partially padded", "extra padding");
    private static final Set<String> PADDING_ACCEPTED = Set.of("non-zero pad bits");

    private static Outcome expected(String file, JsonNode c) {
        String name = c.get("name").asText();
        if (file.equals("date.json") || file.equals("display-string.json")
                || (c.has("expected") && usesRfc9651(c.get("expected")))) {
            // Every case here must fail in fiki, whatever the corpus expects (@7vdhfv3q).
            return c.path("must_fail").asBoolean() ? Outcome.CORPUS_REFUSES : Outcome.DATE_OR_DISPLAY_STRING;
        }
        if (c.path("must_fail").asBoolean()) {
            return Outcome.CORPUS_REFUSES;
        }
        if (c.path("can_fail").asBoolean()) {
            if (file.equals("binary.json") && PADDING_REFUSED.contains(name)) {
                return Outcome.PADDING;
            }
            // "non-zero pad bits" by @2g4xxev9, and "two lines string" by py's outcome: the joined
            // raw value is the ordinary string "foo, bar", which every parser accepts.
            if (!(file.equals("binary.json") && PADDING_ACCEPTED.contains(name))
                    && !(file.equals("string.json") && name.equals("two lines string"))) {
                fail("a can_fail case this driver has no ruling for: " + file + " " + name);
            }
        }
        if (overABound(c)) {
            return Outcome.OVER_A_BOUND;
        }
        if (c.get("header_type").asText().equals("dictionary") && c.get("expected").isEmpty()) {
            return Outcome.EMPTY_DICTIONARY;
        }
        return Outcome.ACCEPT;
    }

    /* ------------------------------------------------------------------ running a case */

    private static Object parse(String type, String raw) {
        return switch (type) {
            case "dictionary" -> Fiki.parse(raw, "Signature-Input", KIND);
            case "list" -> Fiki.parseList(raw, "Signature-Input", KIND);
            case "item" -> Fiki.parseItem(raw, "Signature-Input", KIND);
            default -> throw new AssertionError("a header_type no port skips is unknown here: " + type);
        };
    }

    /** One case, returning the outcome it took, or failing with its name. */
    private static Outcome run(String file, JsonNode c) {
        String type = c.get("header_type").asText();
        String label = file + " / " + c.get("name").asText();
        Outcome outcome = expected(file, c);
        if (outcome != Outcome.ACCEPT) {
            // fiki's malformed error and nothing else: an exception of any other class escapes this
            // lambda and fails the case.
            FikiException e = assertThrows(FikiException.class, () -> parse(type, raw(c)), label);
            assertEquals(KIND, e.kind(), label);
            return outcome;
        }
        Object parsed;
        try {
            parsed = parse(type, raw(c));
        } catch (FikiException e) {
            throw new AssertionError(label + ": refused, and the corpus accepts it: " + e.getMessage(), e);
        }
        assertEquals(render(type, c.get("expected")), renderParsed(type, parsed), label);
        return outcome;
    }

    /*
     * Both sides rendered to one text form, so a mismatch prints both whole. Each bare item carries
     * its type, so an integer never equals a decimal; a decimal is compared at three fractional digits.
     */

    private static String render(String type, JsonNode expected) {
        StringBuilder out = new StringBuilder();
        switch (type) {
            case "item" -> renderItem(expected, out);
            case "list" -> {
                for (JsonNode member : expected) {
                    renderItem(member, out);
                    out.append(", ");
                }
            }
            default -> {
                for (JsonNode member : expected) {
                    out.append(member.get(0).asText()).append('=');
                    renderItem(member.get(1), out);
                    out.append(", ");
                }
            }
        }
        return out.toString();
    }

    private static void renderItem(JsonNode item, StringBuilder out) {
        JsonNode value = item.get(0);
        if (value.isArray()) {
            out.append('(');
            for (JsonNode inner : value) {
                renderItem(inner, out);
                out.append(' ');
            }
            out.append(')');
        } else {
            out.append(bare(value));
        }
        for (JsonNode param : item.get(1)) {
            out.append(';').append(param.get(0).asText()).append('=').append(bare(param.get(1)));
        }
    }

    private static String bare(JsonNode value) {
        if (value.isIntegralNumber()) {
            return "integer " + value.bigIntegerValue();
        }
        if (value.isNumber()) {
            return "decimal " + value.decimalValue().setScale(3, RoundingMode.HALF_EVEN).toPlainString();
        }
        if (value.isTextual()) {
            return "string " + quoted(value.asText());
        }
        if (value.isBoolean()) {
            return "boolean " + value.asBoolean();
        }
        String type = value.get("__type").asText();
        if (type.equals("token")) {
            return "token " + value.get("value").asText();
        }
        if (type.equals("binary")) {
            return "binary " + HexFormat.of().formatHex(base32(value.get("value").asText()));
        }
        throw new AssertionError("a type fiki refuses reached the comparison: " + type);
    }

    private static String renderParsed(String type, Object parsed) {
        StringBuilder out = new StringBuilder();
        switch (type) {
            case "item" -> renderParsedItem(parsed, out);
            case "list" -> {
                for (Object member : (List<?>) parsed) {
                    renderParsedItem(member, out);
                    out.append(", ");
                }
            }
            default -> {
                for (Object member : (List<?>) parsed) {
                    Sfv.Member m = (Sfv.Member) member;
                    out.append(m.key()).append('=');
                    renderParsedItem(m.value() instanceof Sfv.InnerList inner ? inner : new Sfv.Item(m.value(), m.params()), out);
                    out.append(", ");
                }
            }
        }
        return out.toString();
    }

    private static void renderParsedItem(Object member, StringBuilder out) {
        List<Map.Entry<String, Object>> params;
        if (member instanceof Sfv.InnerList inner) {
            out.append('(');
            for (Sfv.Item item : inner.items()) {
                renderParsedItem(item, out);
                out.append(' ');
            }
            out.append(')');
            params = inner.params();
        } else {
            Sfv.Item item = (Sfv.Item) member;
            out.append(parsedBare(item.value()));
            params = item.params();
        }
        for (Map.Entry<String, Object> param : params) {
            out.append(';').append(param.getKey()).append('=').append(parsedBare(param.getValue()));
        }
    }

    private static String parsedBare(Object value) {
        if (value instanceof Long n) {
            return "integer " + n;
        }
        if (value instanceof BigDecimal d) {
            return "decimal " + d.setScale(3, RoundingMode.HALF_EVEN).toPlainString();
        }
        if (value instanceof String s) {
            return "string " + quoted(s);
        }
        if (value instanceof Boolean b) {
            return "boolean " + b;
        }
        if (value instanceof Sfv.Token t) {
            return "token " + t.text();
        }
        if (value instanceof byte[] raw) {
            return "binary " + HexFormat.of().formatHex(raw);
        }
        throw new AssertionError("the parser returned a value of no RFC 8941 type: " + value);
    }

    private static String quoted(String text) {
        return '"' + text.replace("\\", "\\\\").replace("\"", "\\\"") + '"';
    }

    /** RFC 4648 section 6 base32, padded, which the corpus spells binary values in. */
    static byte[] base32(String text) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        String data = text.replace("=", "");
        byte[] out = new byte[data.length() * 5 / 8];
        int buffer = 0;
        int bits = 0;
        int at = 0;
        for (char ch : data.toCharArray()) {
            int index = alphabet.indexOf(ch);
            assertTrue(index >= 0, "not base32: " + text);
            buffer = (buffer << 5) | index;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out[at++] = (byte) (buffer >> bits);
            }
        }
        return out;
    }

    @Test
    void base32DecodesTheRfc4648Vectors() {
        assertEquals("", new String(base32(""), StandardCharsets.US_ASCII));
        assertEquals("f", new String(base32("MY======"), StandardCharsets.US_ASCII));
        assertEquals("fooba", new String(base32("MZXW6YTB"), StandardCharsets.US_ASCII));
        assertEquals("foobar", new String(base32("MZXW6YTBOI======"), StandardCharsets.US_ASCII));
    }

    /* ---------------------------------------------------------------------- the parsing cases */

    @TestFactory
    Stream<DynamicTest> everyParsingCase() {
        return PARSE_CASES.keySet().stream().sorted().map(file -> DynamicTest.dynamicTest(file, () -> {
            JsonNode cases = load(file);
            assertEquals(PARSE_CASES.get(file), cases.size(), file + " holds a different number of cases");
            int ran = 0;
            for (JsonNode c : cases) {
                run(file, c);
                ran++;
            }
            assertEquals(PARSE_CASES.get(file), ran, file + ": every case runs and none is skipped");
        }));
    }

    @Test
    void theOutcomesAreTheOnesCounted() throws Exception {
        Map<Outcome, Integer> counts = new LinkedHashMap<>();
        for (String file : PARSE_CASES.keySet()) {
            for (JsonNode c : load(file)) {
                counts.merge(run(file, c), 1, Integer::sum);
            }
        }
        assertEquals(ACCEPTED, counts.getOrDefault(Outcome.ACCEPT, 0), counts.toString());
        assertEquals(REFUSED_AS_THE_CORPUS_SAYS, counts.getOrDefault(Outcome.CORPUS_REFUSES, 0), counts.toString());
        assertEquals(REFUSED_DATE_OR_DISPLAY_STRING, counts.getOrDefault(Outcome.DATE_OR_DISPLAY_STRING, 0), counts.toString());
        assertEquals(REFUSED_OVER_A_BOUND, counts.getOrDefault(Outcome.OVER_A_BOUND, 0), counts.toString());
        assertEquals(REFUSED_PADDING, counts.getOrDefault(Outcome.PADDING, 0), counts.toString());
        assertEquals(REFUSED_EMPTY_DICTIONARY, counts.getOrDefault(Outcome.EMPTY_DICTIONARY, 0), counts.toString());
    }

    /* ---------------------------------------------------------------- the serialisation subset */

    private static final Key KEY = Key.fromSeed(new byte[32]);

    private static Map<String, String> sign(Fiki.SignOptions opts) {
        return Fiki.signRequest(KEY, "GET", "https://example.com/p", Map.of(), opts.withCreated(1));
    }

    private static void callerError(String fragment, Runnable body, String label) {
        Caller.refused(fragment, body::run, label);
    }

    // serialisation-tests/key-generated.json: 378 cases, all must_fail.
    private static final int SERIALISED_KEYS = 378;

    @Test
    void everyKeyTheCorpusCannotSerializeIsRefusedAsALabelAndAsAComponentParameter() throws Exception {
        JsonNode cases = load("serialisation-tests/key-generated.json");
        assertEquals(SERIALISED_KEYS, cases.size());
        int ran = 0;
        for (JsonNode c : cases) {
            String label = c.get("name").asText();
            assertTrue(c.path("must_fail").asBoolean(), label);
            JsonNode expected = c.get("expected");
            String key = c.get("header_type").asText().equals("dictionary")
                ? expected.get(0).get(0).asText()
                : expected.get(0).get(1).get(0).get(0).asText();
            callerError("is not an RFC 8941 key", () -> sign(Fiki.SignOptions.none().withLabel(key)), label);
            // As a covered component's parameter key the refusal is fiki's UnsupportedComponent, in
            // every port: a spec with a key that is not one does not parse, and one that parses names
            // a parameter other than "req", which fiki refuses (@3e7wnyvg, @5zrf8gjk).
            FikiException e = assertThrows(FikiException.class, () -> sign(Fiki.SignOptions.none()
                .withCovered(List.of("\"@method\";" + key))), label);
            assertEquals(FikiException.Kind.UnsupportedComponent, e.kind(), label);
            ran++;
        }
        assertEquals(SERIALISED_KEYS, ran);
    }

    // serialisation-tests/string-generated.json: 33 cases, all must_fail.
    private static final int SERIALISED_STRINGS = 33;

    @Test
    void everyStringTheCorpusCannotSerializeIsRefusedAsAKeyidNonceAndTag() throws Exception {
        JsonNode cases = load("serialisation-tests/string-generated.json");
        assertEquals(SERIALISED_STRINGS, cases.size());
        int ran = 0;
        for (JsonNode c : cases) {
            String label = c.get("name").asText();
            assertTrue(c.path("must_fail").asBoolean(), label);
            String text = c.get("expected").get(0).asText();
            String fragment = "outside visible ASCII";
            callerError(fragment, () -> sign(Fiki.SignOptions.none().withKeyid(text)), label);
            callerError(fragment, () -> sign(Fiki.SignOptions.none().withNonce(text)), label);
            callerError(fragment, () -> sign(Fiki.SignOptions.none().withTag(text)), label);
            ran++;
        }
        assertEquals(SERIALISED_STRINGS, ran);
    }

    // serialisation-tests/number.json: 9 cases. The two too-big integers run as created; the two
    // too-big decimals are skipped, since created is a long and no decimal reaches it, and the five
    // rounding cases are outside the subset this driver runs.
    private static final int SERIALISED_NUMBERS = 9;
    private static final int SERIALISED_NUMBERS_RUN = 2;

    @Test
    void everyTooBigIntegerIsRefusedAsCreated() throws Exception {
        JsonNode cases = load("serialisation-tests/number.json");
        assertEquals(SERIALISED_NUMBERS, cases.size());
        int ran = 0;
        int skipped = 0;
        for (JsonNode c : cases) {
            String label = c.get("name").asText();
            JsonNode number = c.get("expected").get(0);
            if (!label.startsWith("too big") || !number.isIntegralNumber()) {
                skipped++;
                continue;
            }
            assertTrue(c.path("must_fail").asBoolean(), label);
            long created = number.longValue();
            callerError("fiki signs a timestamp from 0",
                () -> Fiki.signRequest(KEY, "GET", "https://example.com/p", Map.of(),
                    Fiki.SignOptions.none().withCreated(created)), label);
            ran++;
        }
        assertEquals(SERIALISED_NUMBERS_RUN, ran);
        assertEquals(SERIALISED_NUMBERS - SERIALISED_NUMBERS_RUN, skipped);
    }

    // serialisation-tests/token-generated.json: 124 cases, none run: fiki serializes no token a
    // caller chooses, so this file is outside the subset.
    private static final int SERIALISED_TOKENS = 124;

    @Test
    void theTokenSerialisationFileIsSkippedWhole() throws Exception {
        assertEquals(SERIALISED_TOKENS, load("serialisation-tests/token-generated.json").size());
    }
}
