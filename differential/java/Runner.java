// The Java port's answers to differential/cases.json, as a map from case id to outcome.
//
// Compiled against the port's classes and Jackson, which the port's own tests already use; see
// differential/README.md for the two ways to build it and for the outcome spelling all six runners
// share. Arguments: [cases.json] [out.json].

import com.bakobo.fiki.Fiki;
import com.bakobo.fiki.FikiException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class Runner {

    /** How much of a caller error's message an outcome carries; the same in every runner. */
    private static final int PREFIX = 40;

    private Runner() {}

    private static List<String> strings(JsonNode node) {
        List<String> out = new ArrayList<>();
        node.forEach(item -> out.add(item.asText()));
        return out;
    }

    /**
     * The case's stated policy in Java's spelling: a null max_age is decliningFreshness, null
     * authorities withoutAuthorityCheck, a null minimum withoutMinimum, "default" no call at all.
     */
    private static Fiki.VerifyOptions options(JsonNode c) {
        JsonNode maxAge = c.get("max_age");
        Fiki.VerifyOptions opts = maxAge.isNull()
            ? Fiki.VerifyOptions.decliningFreshness()
            : Fiki.VerifyOptions.maxAge(maxAge.asLong());
        opts = opts.withNow(c.get("now").asLong());
        JsonNode body = c.get("body");
        opts = opts.withBody(body.isNull() ? null : body.asText().getBytes(StandardCharsets.UTF_8));
        if (!c.get("expected_aid").isNull()) {
            opts = opts.withExpectedAid(c.get("expected_aid").asText());
        }
        JsonNode authorities = c.get("authorities");
        opts = authorities.isNull() ? opts.withoutAuthorityCheck() : opts.withAuthorities(strings(authorities));
        JsonNode minimum = c.get("minimum");
        if (minimum.isNull()) {
            opts = opts.withoutMinimum();
        } else if (minimum.isArray()) {
            opts = opts.withMinimum(strings(minimum));
        }
        return opts;
    }

    private static String outcome(JsonNode c) {
        try {
            Map<String, String> headers = new LinkedHashMap<>();
            c.get("headers").fields().forEachRemaining(e -> headers.put(e.getKey(), e.getValue().asText()));
            Fiki.Verdict verdict = Fiki.verifyRequest(c.get("method").asText(), c.get("url").asText(), headers, options(c));
            return "ok:" + verdict.aid();
        } catch (FikiException e) {
            return e.kind().name();
        } catch (Throwable e) {
            // A mistake in the call is an IllegalArgumentException and never a FikiException
            // (@5zrf8gjk). fiki throws exactly that class, so a subclass such as the JDK's
            // NumberFormatException is a bug, as Caller.java in the port's tests says.
            if (e.getClass() == IllegalArgumentException.class) {
                String message = String.valueOf(e.getMessage());
                int end = message.codePointCount(0, message.length()) > PREFIX
                    ? message.offsetByCodePoints(0, PREFIX) : message.length();
                return "caller:" + message.substring(0, end);
            }
            return "crash:" + e.getClass().getSimpleName();
        }
    }

    public static void main(String[] args) throws Exception {
        Path casesPath = Path.of(args.length > 0 ? args[0] : "../cases.json");
        Path outPath = Path.of(args.length > 1 ? args[1] : "../out/java.json");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode cases = mapper.readTree(casesPath.toFile()).get("cases");
        long start = System.nanoTime();
        Map<String, String> out = new TreeMap<>();
        for (JsonNode c : cases) {
            out.put(c.get("id").asText(), outcome(c));
        }
        File parent = outPath.toAbsolutePath().getParent().toFile();
        parent.mkdirs();
        Files.writeString(outPath, mapper.writeValueAsString(out) + "\n", StandardCharsets.UTF_8);
        System.out.printf("java: %d cases in %.1fs%n", out.size(), (System.nanoTime() - start) / 1e9);
    }
}
