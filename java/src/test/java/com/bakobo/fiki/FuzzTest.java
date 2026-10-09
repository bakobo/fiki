package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * A deterministic, seeded mutation fuzz of the RFC 8941 parser and of verifyRequest (tick 7xbw).
 *
 * <p>Seeds are every raw value in the httpwg corpus's parsing files (@7fexwu3s) and every
 * Signature-Input and Signature value in vectors/accepts.json and vectors/refusals.json. Each mutant
 * is made by flipping, inserting, deleting, truncating or splicing UTF-16 code units, from an
 * alphabet that includes the structural characters, non-ASCII, the C1 controls U+0080 to U+009F,
 * U+2028, U+2029 and lone surrogates. The parser's only allowed outcomes are a value or fiki's
 * malformed error; verifyRequest's, given every decision explicitly, are a verdict or a
 * {@link FikiException}, since wire input never makes a caller error. Anything else fails with the
 * seed, the iteration and the input. No dependency: the generator is a hand-written xorshift64*.
 */
class FuzzTest {

    private static final long SEED = 0x5EED_F1C1_7B00_0001L;
    private static final int ITERATIONS = 24_000;
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final FikiException.Kind KIND = FikiException.Kind.MalformedSignatureInput;

    private static final List<String> SEEDS = new ArrayList<>();
    private static final List<JsonNode> REQUESTS = new ArrayList<>();

    @BeforeAll
    static void load() throws Exception {
        File corpus = new File("../vectors/third_party/structured-field-tests");
        File[] files = corpus.listFiles((dir, name) -> name.endsWith(".json"));
        assertTrue(files != null && files.length == 20, "the httpwg corpus's twenty parsing files");
        for (File file : files) {
            for (JsonNode c : MAPPER.readTree(file)) {
                List<String> lines = new ArrayList<>();
                c.get("raw").forEach(line -> lines.add(line.asText()));
                SEEDS.add(String.join(", ", lines));
            }
        }
        for (String name : List.of("accepts.json", "refusals.json")) {
            for (JsonNode c : MAPPER.readTree(new File("../vectors/" + name)).get("cases")) {
                REQUESTS.add(c);
                c.get("headers").fields().forEachRemaining(e -> {
                    String field = e.getKey().toLowerCase(java.util.Locale.ROOT);
                    if (field.equals("signature-input") || field.equals("signature")) {
                        SEEDS.add(e.getValue().asText());
                    }
                });
            }
        }
        assertEquals(1593 + 43 + 43 + 142 + 143 + 2, SEEDS.size(), "every seed loaded");
    }

    /* ------------------------------------------------------------------ the generator */

    private static final class Xorshift {
        private long state;

        Xorshift(long seed) {
            state = seed == 0 ? 1 : seed;
        }

        long next() {
            state ^= state >>> 12;
            state ^= state << 25;
            state ^= state >>> 27;
            return state * 0x2545F4914F6CDD1DL;
        }

        int below(int bound) {
            return (int) Long.remainderUnsigned(next(), bound);
        }
    }

    private static final String ALPHABET = buildAlphabet();

    private static String buildAlphabet() {
        StringBuilder out = new StringBuilder();
        // The grammar's structural characters, weighted by appearing in full.
        out.append("\"\\:;=,()?*-.@%/ \t0123456789aAzZ+_!#$&'^`|~<>[]{}");
        for (char ch = 0; ch < 0x20; ch++) {
            out.append(ch);
        }
        out.append('\u007f');
        for (char ch = 0x80; ch <= 0x9f; ch++) {
            out.append(ch);
        }
        out.append("\u00a0\u00e9\u0130\u212a\u2028\u2029\ufeff\uffff");
        // Lone surrogates, which only a UTF-16 string can hold.
        out.append("\ud800\udbff\udc00\udfff");
        return out.toString();
    }

    private static String mutate(Xorshift rng, String input) {
        String text = input;
        int rounds = 1 + rng.below(4);
        for (int r = 0; r < rounds; r++) {
            int length = text.length();
            int at = length == 0 ? 0 : rng.below(length);
            switch (rng.below(6)) {
                case 0 -> { // flip one code unit's bit, which reaches any character
                    if (length > 0) {
                        char flipped = (char) (text.charAt(at) ^ (1 << rng.below(16)));
                        text = text.substring(0, at) + flipped + text.substring(at + 1);
                    }
                }
                case 1 -> { // replace one code unit from the alphabet
                    if (length > 0) {
                        text = text.substring(0, at) + ALPHABET.charAt(rng.below(ALPHABET.length())) + text.substring(at + 1);
                    }
                }
                case 2 -> { // insert from the alphabet
                    int where = rng.below(length + 1);
                    text = text.substring(0, where) + ALPHABET.charAt(rng.below(ALPHABET.length())) + text.substring(where);
                }
                case 3 -> { // delete a run
                    if (length > 0) {
                        int end = Math.min(length, at + 1 + rng.below(8));
                        text = text.substring(0, at) + text.substring(end);
                    }
                }
                case 4 -> { // truncate
                    text = text.substring(0, rng.below(length + 1));
                }
                default -> { // splice with another seed
                    String other = SEEDS.get(rng.below(SEEDS.size()));
                    int cut = rng.below(other.length() + 1);
                    text = text.substring(0, rng.below(length + 1)) + other.substring(cut);
                }
            }
        }
        return text;
    }

    /* ---------------------------------------------------------------------- the targets */

    private static void parse(String mutant) {
        parseOne(() -> Fiki.parse(mutant, "Signature-Input", KIND));
        parseOne(() -> Fiki.parseList(mutant, "Signature-Input", KIND));
        parseOne(() -> Fiki.parseItem(mutant, "Signature-Input", KIND));
    }

    private static void parseOne(Supplier<Object> parser) {
        try {
            parser.get();
        } catch (FikiException e) {
            if (e.kind() != KIND) {
                throw new AssertionError("the parser refused as " + e.kind() + ", not " + KIND, e);
            }
        }
    }

    private static final Key KEY = Key.fromSeed(new byte[32]);

    // Every verifier policy is stated, as the brief asks, and each one is a different path.
    private static Fiki.VerifyOptions options(Xorshift rng, JsonNode c) {
        long now = c.path("now").isNumber() ? c.get("now").asLong() : 1_700_000_000L;
        byte[] body = c.path("body").isTextual() ? c.get("body").asText().getBytes(StandardCharsets.UTF_8) : null;
        Fiki.VerifyOptions declined = Fiki.VerifyOptions.decliningFreshness().withNow(now).withBody(body)
            .withoutKeyidCheck();
        return switch (rng.below(5)) {
            case 0 -> declined.withoutMinimum().withoutAuthorityCheck();
            case 1 -> Fiki.VerifyOptions.maxAge(300).withNow(now).withBody(body).withoutKeyidCheck()
                .withMinimum(Fiki.DEFAULT_MINIMUM).withAuthorities(Set.of("api.example.com", "example.com"));
            case 2 -> declined.withMinimum(Fiki.REQUEST_MINIMUM).withoutAuthorityCheck()
                .withResolver(keyid -> keyid.equals(KEY.keyid()) ? Key.verifyingKeyBytes(KEY.aid()) : null);
            case 3 -> declined.withoutMinimum().withoutAuthorityCheck().withExpectedAid(KEY.aid());
            default -> declined.withMinimum(Fiki.DEFAULT_MINIMUM).withoutAuthorityCheck()
                .withExpectedKeyid(KEY.keyid());
        };
    }

    private static void verify(Xorshift rng, String mutant) {
        JsonNode c = REQUESTS.get(rng.below(REQUESTS.size()));
        Map<String, String> headers = new LinkedHashMap<>();
        c.get("headers").fields().forEachRemaining(e -> headers.put(e.getKey(), e.getValue().asText()));
        String target = rng.below(2) == 0 ? "signature-input" : "signature";
        headers.keySet().removeIf(name -> name.equalsIgnoreCase(target));
        headers.put(target.equals("signature") ? "Signature" : "Signature-Input", mutant);
        Fiki.VerifyOptions opts = options(rng, c);
        try {
            Fiki.verifyRequest(c.get("method").asText(), c.get("url").asText(), headers, opts);
        } catch (FikiException e) {
            // A refusal in fiki's taxonomy is the other allowed outcome.
        }
    }

    private static String escaped(String text) {
        StringBuilder out = new StringBuilder();
        for (char ch : text.toCharArray()) {
            out.append(ch >= 0x20 && ch < 0x7f ? String.valueOf(ch) : String.format("\\u%04x", (int) ch));
        }
        return out.toString();
    }

    @Test
    void noMutantEscapesFikisTaxonomy() {
        Xorshift rng = new Xorshift(SEED);
        for (int i = 0; i < ITERATIONS; i++) {
            String mutant = mutate(rng, SEEDS.get(rng.below(SEEDS.size())));
            try {
                parse(mutant);
                verify(rng, mutant);
            } catch (Throwable t) {
                fail("seed " + Long.toHexString(SEED) + ", iteration " + i + ", input \"" + escaped(mutant) + "\": " + t, t);
            }
        }
    }
}
