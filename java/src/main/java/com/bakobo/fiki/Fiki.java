package com.bakobo.fiki;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Signing and verifying whole HTTP requests (this.i @2hwvpm42, @7xrx5evg, @67shl6c5).
 *
 * <p>The keyid is always the signer's raw key and is not overridable, so "the request carries its
 * own verifying key" holds for every fiki-signed request. A body is always covered or the
 * signature is refused. And a verifier states a freshness policy or explicitly declines one.
 *
 * <p>The bound worth stating plainly: fiki cannot cover a body it was never given. The guarantee
 * is "hand fiki the body and it is covered, or fiki refuses" — a caller who omits it gets a valid
 * signature over a request whose body nothing protects, and no library can detect that.
 */
public final class Fiki {

    private Fiki() {}

    /**
     * The conformance contract this port satisfies (this.i @4fhrre0m).
     *
     * <p>Two artifacts interoperate when their declared vectors format matches, whatever their own
     * version numbers say — so this is the number to compare, not the release. Monotonic, because
     * a conformance contract has no meaningful minor: an implementation either satisfies the
     * vectors or it does not.
     */
    public static final int VECTORS_FORMAT = 1;

    /** The only signature algorithm fiki produces or accepts. */
    public static final String ALG = "ed25519";

    /**
     * Two hosts disagreeing by a second is ordinary; a verifier that treats it as an attack is
     * unusable.
     */
    public static final long DEFAULT_SKEW = 5;

    /** Derived components fiki builds. Anything else is refused rather than skipped. */
    public static final List<String> DERIVED = List.of("@method", "@authority", "@path", "@query");

    /**
     * {@code @method}, {@code @authority}, {@code @path}, {@code @query} — plus
     * {@code content-digest} whenever there is a body. This closes the query, host, and body gaps
     * that heti's KERI dialect leaves open and structurally cannot close.
     */
    public static final List<String> DEFAULT_COVERED =
        List.of("@method", "@authority", "@path", "@query");

    /** The covered component that binds a request body. */
    public static final String CONTENT_DIGEST = "content-digest";

    private static final Map<String, String> DEFAULT_PORTS =
        Map.of("http", "80", "https", "443", "ws", "80", "wss", "443");

    private static final Map<String, String> DIGEST_ALGORITHMS =
        Map.of("sha-256", "SHA-256", "sha-512", "SHA-512");

    /* ---------------------------------------------------------------- the signature base */

    /** The RFC 9421 signature parameters a signer sets. */
    public record Params(Long created, String keyid, String alg, Long expires, String nonce, String tag) {
        public static Params of(long created, String keyid) {
            return new Params(created, keyid, null, null, null, null);
        }
    }

    /** Build the RFC 9421 signature base for a request. */
    public static byte[] signatureBase(
            String method, String url, Map<String, String> headers, List<String> covered, Params params) {
        List<String> components = covered.stream().map(Fiki::lower).toList();
        List<String> lines = new ArrayList<>(componentLines(method, url, headers, components));

        // Order is the signer's choice — a verifier reserializes whatever it received — so fiki
        // fixes one order and keeps it, which makes its own output reproducible.
        List<Map.Entry<String, Object>> ordered = new ArrayList<>();
        if (params.created() != null) ordered.add(Map.entry("created", params.created()));
        if (params.expires() != null) ordered.add(Map.entry("expires", params.expires()));
        if (params.nonce() != null) ordered.add(Map.entry("nonce", params.nonce()));
        if (params.alg() != null) ordered.add(Map.entry("alg", params.alg()));
        if (params.keyid() != null) ordered.add(Map.entry("keyid", params.keyid()));
        if (params.tag() != null) ordered.add(Map.entry("tag", params.tag()));

        lines.add("\"@signature-params\": "
            + Sfv.serializeInnerList(new Sfv.InnerList(components, ordered)));
        return String.join("\n", lines).getBytes(StandardCharsets.UTF_8);
    }

    static List<String> componentLines(
            String method, String url, Map<String, String> headers, List<String> covered) {
        Target target = Target.split(url);
        Map<String, String> lowered = lowerHeaders(headers);
        List<String> lines = new ArrayList<>(covered.size());
        for (String raw : covered) {
            String component = lower(raw);
            lines.add("\"" + component + "\": " + componentValue(component, method, target, lowered));
        }
        return lines;
    }

    /**
     * A request target split without a URI parser doing the work: fiki needs the scheme, authority,
     * path and RAW query, and {@link URI} normalizes the query in ways RFC 9421 section 2.2.7 says
     * not to.
     */
    record Target(String scheme, String authority, String path, String query) {
        static Target split(String raw) {
            String scheme = null;
            String rest = raw;
            int at = raw.indexOf("://");
            if (at > 0 && raw.substring(0, at).chars().allMatch(c -> Character.isLetterOrDigit(c) || "+-.".indexOf(c) >= 0)) {
                scheme = raw.substring(0, at).toLowerCase(Locale.ROOT);
                rest = raw.substring(at + 3);
            }
            String authority = null;
            if (scheme != null) {
                int end = rest.length();
                for (int i = 0; i < rest.length(); i++) {
                    if ("/?#".indexOf(rest.charAt(i)) >= 0) {
                        end = i;
                        break;
                    }
                }
                authority = rest.substring(0, end);
                rest = rest.substring(end);
            }
            int hash = rest.indexOf('#');
            if (hash >= 0) {
                rest = rest.substring(0, hash);
            }
            int question = rest.indexOf('?');
            String path = question >= 0 ? rest.substring(0, question) : rest;
            String query = question >= 0 ? rest.substring(question + 1) : "";
            return new Target(scheme, authority, path.isEmpty() ? "/" : path, query);
        }
    }

    private static String componentValue(
            String component, String method, Target target, Map<String, String> headers) {
        switch (component) {
            case "@method":
                return method.toUpperCase(Locale.ROOT);
            case "@authority":
                return authority(target, headers);
            case "@path":
                return target.path();
            // Section 2.2.7: the whole query string including the leading "?", percent-encoding
            // preserved, and a bare "?" when the request carries no query at all.
            case "@query":
                return "?" + target.query();
            default:
                break;
        }
        if (component.startsWith("@")) {
            throw new FikiException(
                FikiException.Kind.UnsupportedComponent,
                "fiki does not build the derived component " + component + "; it builds "
                    + String.join(", ", DERIVED) + ".",
                component);
        }
        String value = headers.get(component);
        if (value == null) {
            throw new FikiException(
                FikiException.Kind.MissingComponent,
                "The signature covers " + component + ", but the request carries no value for it.",
                component);
        }
        return value;
    }

    private static String authority(Target target, Map<String, String> headers) {
        // RFC 9421 section 2.2.3: lowercase host, default port omitted. A relative URL falls back
        // to the Host header, which in HTTP/1.1 *is* the authority — the shape a server-side
        // verifier actually holds. Nothing is normalized away there, because without a scheme no
        // port is a default port.
        if (target.authority() != null) {
            String raw = target.authority().toLowerCase(Locale.ROOT);
            int colon = raw.lastIndexOf(':');
            String host = raw;
            String port = null;
            if (colon > 0 && raw.substring(colon + 1).chars().allMatch(Character::isDigit)
                && !raw.substring(colon + 1).isEmpty()) {
                host = raw.substring(0, colon);
                port = raw.substring(colon + 1);
            }
            String defaultPort = target.scheme() == null ? null : DEFAULT_PORTS.get(target.scheme());
            return port == null || port.equals(defaultPort) ? host : host + ":" + port;
        }
        String host = headers.get("host");
        if (host == null) {
            throw new FikiException(
                FikiException.Kind.MissingComponent,
                "The signature covers \"@authority\", but the URL carries no authority and the "
                    + "request has no Host header, so there is nothing to derive it from.",
                "@authority");
        }
        return host.toLowerCase(Locale.ROOT);
    }

    private static Map<String, String> lowerHeaders(Map<String, String> headers) {
        // Header field names are case-insensitive and appear lowercased in the base (section 2.1);
        // values are stripped of leading and trailing whitespace.
        Map<String, String> out = new TreeMap<>();
        if (headers != null) {
            headers.forEach((name, value) -> out.put(lower(name), value.trim()));
        }
        return out;
    }

    private static String lower(String text) {
        return text.toLowerCase(Locale.ROOT);
    }

    /* ------------------------------------------------------------------------- signing */

    /** Everything beyond the request itself. */
    public record SignOptions(
            byte[] body, List<String> covered, Long created, String label,
            Long expires, String nonce, String tag) {

        public static SignOptions none() {
            return new SignOptions(null, null, null, null, null, null, null);
        }

        public SignOptions withBody(byte[] body) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag);
        }

        public SignOptions withCreated(long created) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag);
        }

        public SignOptions withCovered(List<String> covered) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag);
        }

        public SignOptions withLabel(String label) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag);
        }

        public SignOptions withExpires(long expires) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag);
        }
    }

    /** The RFC 9530 {@code Content-Digest} header value for a body. */
    public static String contentDigest(byte[] body) {
        return "sha-256=:" + Key.STD.encodeToString(digest("SHA-256", body)) + ":";
    }

    private static byte[] digest(String algorithm, byte[] body) {
        try {
            return MessageDigest.getInstance(algorithm).digest(body);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("this JDK has no " + algorithm, e);
        }
    }

    /** Sign a request and return the headers to add to it. */
    public static Map<String, String> signRequest(
            Key key, String method, String url, Map<String, String> headers, SignOptions opts) {
        Map<String, String> supplied = headers == null ? Map.of() : headers;
        Map<String, String> sending = new LinkedHashMap<>(supplied);

        // Whether the caller CHOSE the covered set is the difference between fiki helping and fiki
        // overriding. On the default path a body simply gets covered; on an explicit path,
        // silently adding a component would cover something the caller did not ask for.
        boolean chosen = opts.covered() != null;
        List<String> components =
            new ArrayList<>((chosen ? opts.covered() : DEFAULT_COVERED).stream().map(Fiki::lower).toList());

        if (opts.body() != null) {
            if (!components.contains(CONTENT_DIGEST)) {
                if (chosen) {
                    throw new FikiException(
                        FikiException.Kind.UncoveredBody,
                        "This request carries a body, but the covered components do not include "
                            + "\"content-digest\", so the signature would not bind the body.");
                }
                components.add(CONTENT_DIGEST);
            }
            if (supplied.keySet().stream().noneMatch(name -> lower(name).equals(CONTENT_DIGEST))) {
                sending.put("Content-Digest", contentDigest(opts.body()));
            }
        }

        long created = opts.created() != null ? opts.created() : Instant.now().getEpochSecond();
        byte[] base = signatureBase(method, url, sending, components,
            new Params(created, key.keyid(), ALG, opts.expires(), opts.nonce(), opts.tag()));
        byte[] signature = key.sign(base);

        String text = new String(base, StandardCharsets.UTF_8);
        String marker = "\"@signature-params\": ";
        String rendered = text.substring(text.lastIndexOf(marker) + marker.length());
        String label = opts.label() == null ? "sig" : opts.label();

        Map<String, String> out = new LinkedHashMap<>();
        out.put("Signature-Input", label + "=" + rendered);
        out.put("Signature", label + "=:" + Key.STD.encodeToString(signature) + ":");
        String made = sending.get("Content-Digest");
        if (made != null && supplied.keySet().stream().noneMatch(name -> lower(name).equals(CONTENT_DIGEST))) {
            out.put("Content-Digest", made);
        }
        return out;
    }

    /* ----------------------------------------------------------------------- verifying */

    /** The outcome of a successful verification. */
    public record Verdict(String aid, List<String> covered) {}

    /**
     * The verifier's policy and the body it has in hand.
     *
     * <p>{@code maxAge} is a {@link Long} rather than a {@code long} because there is no default:
     * seconds of tolerance, or an explicit {@code null} to decline the check. Both defaults would
     * be wrong (this.i @67shl6c5).
     */
    public record VerifyOptions(Long maxAge, byte[] body, String expectedAid, Long skew, Long now) {

        /** Decline the freshness check, explicitly. */
        public static VerifyOptions decliningFreshness() {
            return new VerifyOptions(null, null, null, null, null);
        }

        public static VerifyOptions maxAge(long seconds) {
            return new VerifyOptions(seconds, null, null, null, null);
        }

        public VerifyOptions withBody(byte[] body) {
            return new VerifyOptions(maxAge, body, expectedAid, skew, now);
        }

        public VerifyOptions withExpectedAid(String aid) {
            return new VerifyOptions(maxAge, body, aid, skew, now);
        }

        public VerifyOptions withNow(long now) {
            return new VerifyOptions(maxAge, body, expectedAid, skew, now);
        }

        public VerifyOptions withSkew(long skew) {
            return new VerifyOptions(maxAge, body, expectedAid, skew, now);
        }
    }

    /** Verify a signed request. */
    public static Verdict verifyRequest(
            String method, String url, Map<String, String> headers, VerifyOptions opts) {
        Map<String, String> found = lowerHeaders(headers);
        Parsed parsed = read(found);
        Sfv.InnerList list = parsed.list();

        Object alg = list.param("alg");
        if (alg != null && !ALG.equals(alg)) {
            throw new FikiException(
                FikiException.Kind.UnsupportedAlgorithm,
                "This signature is made with \"" + alg + "\", and fiki verifies only " + ALG + ".",
                String.valueOf(alg));
        }

        String aid = resolve(opts.expectedAid(), list);
        List<String> lines = new ArrayList<>(componentLines(method, url, headers, list.items()));
        lines.add("\"@signature-params\": " + Sfv.serializeInnerList(list));
        byte[] base = String.join("\n", lines).getBytes(StandardCharsets.UTF_8);

        if (!verify(aid, parsed.signature(), base)) {
            throw new FikiException(
                FikiException.Kind.SignatureMismatch,
                "The signature does not match this request under the signer's key.");
        }

        // AFTER the signature check, deliberately. created and expires are covered by the
        // signature, so acting on them before verifying it would enforce a policy against values
        // an attacker could still have chosen — and would tell that attacker their forgery at
        // least parsed.
        checkFreshness(list, opts);

        if (list.items().contains(CONTENT_DIGEST)) {
            checkDigest(found.get(CONTENT_DIGEST), opts.body());
        }
        return new Verdict(aid, list.items());
    }

    private record Parsed(Sfv.InnerList list, byte[] signature) {}

    private static boolean verify(String aid, byte[] signature, byte[] base) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(Key.verifyingKey(aid));
            verifier.update(base);
            return verifier.verify(signature);
        } catch (java.security.SignatureException e) {
            // A structurally wrong signature is a mismatch, not a crash.
            return false;
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("verification failed", e);
        }
    }

    private static Parsed read(Map<String, String> found) {
        String rawInput = found.get("signature-input");
        String rawSignature = found.get("signature");
        if (rawInput == null || rawInput.isEmpty()) {
            throw new FikiException(
                FikiException.Kind.MissingSignatureInput,
                "This request has no Signature-Input header, so there is no way to know which "
                    + "components a signature would cover.");
        }
        if (rawSignature == null || rawSignature.isEmpty()) {
            throw new FikiException(
                FikiException.Kind.MissingSignature,
                "This request has no Signature header, so there is nothing to verify.");
        }

        List<Sfv.Member> inputs = parse(rawInput, "Signature-Input", FikiException.Kind.MalformedSignatureInput);
        List<Sfv.Member> signatures = parse(rawSignature, "Signature", FikiException.Kind.MalformedSignature);

        if (inputs.size() != 1) {
            throw new FikiException(
                FikiException.Kind.MalformedSignatureLabel,
                "fiki verifies a request carrying exactly one signature; this one declares "
                    + inputs.size() + ".");
        }
        Sfv.Member input = inputs.get(0);
        Sfv.Member match = signatures.size() == 1 && signatures.get(0).key().equals(input.key())
            ? signatures.get(0) : null;
        if (match == null) {
            throw new FikiException(
                FikiException.Kind.MissingSignatureLabel,
                "The Signature header carries no entry labelled " + input.key() + ".",
                input.key());
        }
        if (!(match.value() instanceof byte[] raw)) {
            throw new FikiException(
                FikiException.Kind.MalformedSignatureValue,
                "RFC 9421 carries the signature as an RFC 8941 byte sequence, wrapped in colons.");
        }
        return new Parsed(input.list(), raw);
    }

    private static List<Sfv.Member> parse(String raw, String name, FikiException.Kind kind) {
        try {
            return Sfv.parseDictionary(raw);
        } catch (Sfv.SyntaxException e) {
            throw new FikiException(kind, "I could not parse the " + name + " header.");
        }
    }

    private static String resolve(String expectedAid, Sfv.InnerList list) {
        if (expectedAid != null) {
            return expectedAid;
        }
        Object keyid = list.param("keyid");
        if (!(keyid instanceof String text) || text.isEmpty()) {
            throw new FikiException(
                FikiException.Kind.MissingKey,
                "This signature carries no keyid and no expectedAid was supplied, so there is no "
                    + "key to verify it against.");
        }
        byte[] raw;
        try {
            raw = Key.URL_DECODER.decode(text);
        } catch (IllegalArgumentException e) {
            raw = new byte[0];
        }
        if (raw.length != Key.RAW_LEN) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                "The keyid " + text + " is not a base64url-encoded 32-byte Ed25519 public key.",
                text);
        }
        return Key.toAid(raw);
    }

    private static void checkFreshness(Sfv.InnerList list, VerifyOptions opts) {
        Object expiresValue = list.param("expires");
        Long expires = expiresValue instanceof Long n ? n : null;
        if (expires == null && opts.maxAge() == null) {
            return;
        }
        long skew = opts.skew() == null ? DEFAULT_SKEW : opts.skew();
        long stamp = opts.now() == null ? Instant.now().getEpochSecond() : opts.now();

        if (expires != null && stamp > expires + skew) {
            throw new FikiException(
                FikiException.Kind.SignatureExpired,
                "This signature expired at " + expires + " and it is now " + stamp
                    + ", so the signer has already declared it should not be accepted.");
        }
        if (opts.maxAge() == null) {
            return;
        }
        long maxAge = opts.maxAge();

        Object createdValue = list.param("created");
        if (!(createdValue instanceof Long created)) {
            throw new FikiException(
                FikiException.Kind.SignatureTooOld,
                "This signature carries no created timestamp, so its age cannot be checked "
                    + "against the " + maxAge + "-second limit you asked for.");
        }
        if (stamp - created > maxAge + skew) {
            throw new FikiException(
                FikiException.Kind.SignatureTooOld,
                "This signature was created at " + created + ", which is more than " + maxAge
                    + " seconds before " + stamp + ", so it is too old to accept.");
        }
        if (created - stamp > skew) {
            throw new FikiException(
                FikiException.Kind.SignatureTooOld,
                "This signature claims to have been created at " + created + ", which is in the "
                    + "future relative to " + stamp + " by more than the " + skew
                    + "-second skew allowance.");
        }
    }

    private static void checkDigest(String header, byte[] body) {
        // The header is covered by the signature, so it cannot have been tampered with — but a
        // covered digest still only attests to a body nobody hashed until somebody hashes it.
        if (body == null) {
            throw new FikiException(
                FikiException.Kind.DigestMismatch,
                "The signature covers content-digest, but no body was supplied to check it against.");
        }
        List<Sfv.Member> parsed =
            parse(header == null ? "" : header, "Content-Digest", FikiException.Kind.MalformedDigest);
        for (Sfv.Member member : parsed) {
            String algorithm = DIGEST_ALGORITHMS.get(lower(member.key()));
            if (algorithm == null) {
                continue;
            }
            if (!(member.value() instanceof byte[] declared)) {
                throw new FikiException(
                    FikiException.Kind.MalformedDigest, "A Content-Digest value is a byte sequence.");
            }
            if (!MessageDigest.isEqual(digest(algorithm, body), declared)) {
                throw new FikiException(
                    FikiException.Kind.DigestMismatch,
                    "The request body does not match its " + member.key() + " Content-Digest, so "
                        + "the body is not the one that was signed.");
            }
            return;
        }
        throw new FikiException(
            FikiException.Kind.MalformedDigest,
            "The Content-Digest header names no algorithm fiki computes; it computes sha-256 and sha-512.");
    }
}
