// Release smoke test for com.bakobo:fiki, run against the artifact resolved from Maven Central,
// never the source. The same four checks as every port's smoke test (docs/releasing.md): a plain
// vector, a plain round trip, a KERI vector through a resolver, and a KERI round trip under a
// caller-chosen AID keyid. Usage: java -cp <classpath> Smoke.java <vectors-dir>
import com.bakobo.fiki.Fiki;
import com.bakobo.fiki.Key;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class Smoke {
    static final ObjectMapper JSON = new ObjectMapper();

    static void check(String name, String got, String want) {
        if (!want.equals(got)) {
            System.err.println("FAIL " + name + ": got " + got + ", want " + want);
            System.exit(1);
        }
        System.out.println("ok   " + name);
    }

    static JsonNode find(JsonNode file, String id) {
        for (JsonNode c : file.get("cases")) {
            if (c.get("id").asText().equals(id)) {
                return c;
            }
        }
        throw new IllegalStateException("vector case " + id + " is missing");
    }

    static Map<String, String> headers(JsonNode node) {
        Map<String, String> out = new LinkedHashMap<>();
        node.fields().forEachRemaining(e -> out.put(e.getKey(), e.getValue().asText()));
        return out;
    }

    public static void main(String[] args) throws Exception {
        Path vectors = Path.of(args[0]);

        JsonNode plain = find(JSON.readTree(vectors.resolve("accepts.json").toFile()), "default-covered-get");
        Fiki.Verdict verdict = Fiki.verifyRequest(plain.get("method").asText(), plain.get("url").asText(),
            headers(plain.get("headers")), Fiki.VerifyOptions.decliningFreshness().withNow(plain.get("now").asLong())
                .withoutAuthorityCheck());
        check("plain vector", verdict.aid(), plain.get("aid").asText());

        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) {
            seed[i] = (byte) i;
        }
        Key key = Key.fromSeed(seed);
        String url = "https://api.example.com/things?limit=1";
        byte[] body = "{\"hello\": \"world\"}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> signed = Fiki.signRequest(key, "POST", url, Map.of(), Fiki.SignOptions.none().withBody(body));
        verdict = Fiki.verifyRequest("POST", url, signed,
            Fiki.VerifyOptions.maxAge(300).withBody(body).withExpectedAid(key.aid())
                .withAuthorities(Set.of("api.example.com")));
        check("plain round trip", verdict.aid(), key.aid());

        JsonNode keri = JSON.readTree(vectors.resolve("keri").resolve("requests.json").toFile());
        Map<String, JsonNode> table = new HashMap<>();
        keri.get("keys").forEach(k -> table.put(k.get("keyid").asText(), k));
        Fiki.Resolver resolve = keyid -> {
            JsonNode entry = table.get(keyid);
            if (entry == null || entry.get("effective_key").isNull()) {
                return null;
            }
            return Base64.getUrlDecoder().decode(entry.get("effective_key").asText());
        };
        JsonNode kase = find(keri, "get-with-query");
        JsonNode request = kase.get("request");
        verdict = Fiki.verifyRequest(request.get("method").asText(), request.get("url").asText(),
            headers(request.get("headers")),
            Fiki.VerifyOptions.maxAge(keri.get("policy").get("max_age").asLong())
                .withSkew(keri.get("policy").get("skew").asLong())
                .withNow(kase.get("now").asLong())
                .withResolver(resolve)
                .withMinimum(Fiki.REQUEST_MINIMUM)
                .withoutAuthorityCheck());
        String keyid = kase.get("expected").get("keyid").asText();
        check("KERI vector", verdict.aid(), keyid);

        Key signer = Key.fromSeed(HexFormat.of().parseHex(table.get(keyid).get("seed_hex").asText()));
        url = "https://keria.example.com/identifiers?type=rot";
        signed = Fiki.signRequest(signer, "GET", url, Map.of(),
            Fiki.SignOptions.none().withKeyid(keyid).withMinimum(Fiki.REQUEST_MINIMUM));
        verdict = Fiki.verifyRequest("GET", url, signed,
            Fiki.VerifyOptions.maxAge(300).withResolver(resolve).withMinimum(Fiki.REQUEST_MINIMUM)
                .withoutAuthorityCheck());
        check("KERI round trip", verdict.aid(), keyid);
    }
}
