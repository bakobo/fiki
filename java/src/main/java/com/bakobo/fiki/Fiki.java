package com.bakobo.fiki;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Signing and verifying whole HTTP requests and responses (this.i @2hwvpm42, @7xrx5evg, @67shl6c5,
 * and this.i @7f28p7xk, @24tvlxgd).
 *
 * <p>The keyid is the signer's raw key unless the caller names another (@7xrx5evg, @6g9zjsv9), so
 * "the request carries its own verifying key" holds for every fiki-signed request whose caller did
 * not deliberately choose otherwise — and a verifier handed a {@link Resolver} never falls back to
 * reading a key out of the keyid. A body is always covered or the signature is refused. And a
 * verifier states a freshness policy or explicitly declines one.
 *
 * <p>The bound worth stating plainly: fiki cannot cover a body it was never given. The guarantee
 * is "hand fiki the body and it is covered, or fiki refuses" — a caller who omits it gets a valid
 * signature over a request whose body nothing protects, and no library can detect that.
 *
 * <p>Verification raises in the KERI profile's section 9 order, so a message with one defect has
 * exactly one correct refusal. A mistake in the CALL rather than the message — a minimum smaller
 * than the profile's, an expected AID together with a resolver, an empty method — is an
 * {@link IllegalArgumentException}, never a {@link FikiException}.
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
    public static final int VECTORS_FORMAT = 2;

    /**
     * The KERI profile's vector set this port satisfies, vectors/keri/ (this.i @8vwrexxc). A
     * separate number from {@link #VECTORS_FORMAT}, because the two sets answer to different
     * authorities and move independently.
     */
    public static final int KERI_VECTORS_FORMAT = 4;

    /** The only signature algorithm fiki produces or accepts. */
    public static final String ALG = "ed25519";

    /**
     * Two hosts disagreeing by a second is ordinary; a verifier that treats it as an attack is
     * unusable.
     */
    public static final long DEFAULT_SKEW = 5;

    /** Derived components fiki builds in a request. Anything else is refused rather than skipped. */
    public static final List<String> DERIVED = List.of("@method", "@authority", "@path", "@query");

    /**
     * The one derived component a response has of its own (RFC 9421 section 2.2.9). Every request
     * component reaches a response only through {@link #req}.
     */
    public static final List<String> RESPONSE_DERIVED = List.of("@status");

    /**
     * {@code @method}, {@code @authority}, {@code @path}, {@code @query} — plus
     * {@code content-digest} whenever there is a body. This closes the query, host, and body gaps
     * that heti's KERI dialect leaves open and structurally cannot close.
     */
    public static final List<String> DEFAULT_COVERED =
        List.of("@method", "@authority", "@path", "@query");

    /** The covered component that binds a body. */
    public static final String CONTENT_DIGEST = "content-digest";

    // The only component parameter fiki supports, and only in a response (RFC 9421 section 2.4).
    private static final String REQ = "req";

    /**
     * The KERI profile's minimum covered set for a request (section 3). A body adds
     * {@code content-digest} on top.
     */
    public static final List<String> REQUEST_MINIMUM = List.of("@method", "@path", "@query");

    /**
     * The KERI profile's minimum covered set for a response (section 3). A body adds
     * {@code content-digest}, and a response to a request whose content was non-empty adds
     * {@code "content-digest";req}.
     */
    public static final List<String> RESPONSE_MINIMUM =
        List.of("@status", req("@method"), req("@path"), req("@query"));

    private static final Map<String, Integer> DEFAULT_PORTS =
        Map.of("http", 80, "https", 443, "ws", 80, "wss", 443);

    // RFC 9530. sha-256 on the way out; both are accepted on the way in, because fiki is not the
    // only thing that will ever have signed a message it is asked to verify. Every one a header
    // carries must match; any other algorithm is ignored (RFC 9530 section 2).
    private static final Map<String, String> DIGEST_ALGORITHMS =
        Map.of("sha-256", "SHA-256", "sha-512", "SHA-512");

    // RFC 9421 section 2.3's six signature parameters and the RFC 8941 type each must have.
    // Anything else is refused rather than carried: a parameter fiki does not understand could be
    // one whose meaning the signer relied on (@7f28p7xk).
    private static final Map<String, Class<?>> SIGNATURE_PARAMS = signatureParams();

    private static Map<String, Class<?>> signatureParams() {
        Map<String, Class<?>> out = new LinkedHashMap<>();
        out.put("created", Long.class);
        out.put("expires", Long.class);
        out.put("nonce", String.class);
        out.put("alg", String.class);
        out.put("keyid", String.class);
        out.put("tag", String.class);
        return out;
    }

    private static final int SIGNATURE_LENGTH = 64;

    // Input bounds (@5zrf8gjk, ticks 65q7 and 6mhg), far above anything an honest signer sends and
    // low enough that no parse is slow. Each applies to Signature-Input, Signature and
    // Content-Digest alike, and over any of them is that header's malformed class.

    /** The most bytes fiki reads in one Signature-Input, Signature or Content-Digest value. */
    public static final int MAX_FIELD_BYTES = 8192;

    /** The most members fiki reads in one of those dictionaries. */
    public static final int MAX_DICTIONARY_MEMBERS = 16;

    /** The most items fiki reads in one inner list, such as a covered-component list. */
    public static final int MAX_INNER_LIST_ITEMS = 64;

    /** The most parameters fiki reads on one item or inner list. */
    public static final int MAX_PARAMETERS = 16;

    // The RFC 8037 "x" form of a raw keyid (@7xrx5evg): 32 bytes, base64url, unpadded.
    private static final Pattern RAW_KEYID = Pattern.compile("[A-Za-z0-9_-]{43}");

    /* ------------------------------------------------------------------ the public shapes */

    /** The RFC 9421 signature parameters a signer sets. */
    public record Params(Long created, String keyid, String alg, Long expires, String nonce, String tag) {
        public static Params of(long created, String keyid) {
            return new Params(created, keyid, null, null, null, null);
        }
    }

    /**
     * The request a response answers, which a response's {@link #req} components are read from.
     *
     * <p>Its body is what decides whether the response must bind the request's digest: by content
     * alone, never by the request's headers, because both sides hold the whole request by the
     * time a response is signed or verified (@7p9s3g9k).
     */
    public record Request(String method, String url, Map<String, String> headers, byte[] body) {
        public Request {
            requireMethod(method);
            if (url == null) {
                throw new IllegalArgumentException("A request needs a URL.");
            }
            // An immutable copy, checked once, and a copy of the body: a caller mutating what it
            // passed in afterwards changes nothing fiki reads (@0ms4j0ef, @2r05k9g0).
            Map<String, String> given = headers == null ? Map.of() : headers;
            lowered(given);
            headers = Map.copyOf(given);
            body = body == null ? null : body.clone();
        }

        /** The headers, immutable. */
        @Override
        public Map<String, String> headers() {
            return Map.copyOf(headers);
        }

        /** A copy of the body, so a caller cannot change what fiki checks. */
        @Override
        public byte[] body() {
            return body == null ? null : body.clone();
        }
    }

    /**
     * The verifier's own key lookup (@6g9zjsv9): the keyid to the 32 raw bytes of the Ed25519 key
     * it names, or null when it names no key the caller knows, which is {@code UnknownKey}.
     *
     * <p>Authoritative: fiki never falls back to decoding the keyid, because a transferable prefix
     * that embeds a key embeds its INCEPTION key. A resolver may itself throw a
     * {@link FikiException} of kind {@code MalformedKey} for a keyid that is not a well-formed
     * identifier, or {@code UnsupportedSigner} for a key state with no single effective signer;
     * fiki carries either out unchanged.
     */
    @FunctionalInterface
    public interface Resolver {
        byte[] resolve(String keyid);
    }

    /** Everything a signer supplies beyond the message itself. */
    public record SignOptions(
            byte[] body, List<String> covered, Long created, String label,
            Long expires, String nonce, String tag, String keyid, List<String> minimum) {

        public static SignOptions none() {
            return new SignOptions(null, null, null, null, null, null, null, null, null);
        }

        public SignOptions withBody(byte[] body) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag, keyid, minimum);
        }

        public SignOptions withCovered(List<String> covered) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag, keyid, minimum);
        }

        public SignOptions withCreated(long created) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag, keyid, minimum);
        }

        public SignOptions withLabel(String label) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag, keyid, minimum);
        }

        public SignOptions withExpires(long expires) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag, keyid, minimum);
        }

        public SignOptions withNonce(String nonce) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag, keyid, minimum);
        }

        public SignOptions withTag(String tag) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag, keyid, minimum);
        }

        /**
         * The keyid to sign under, such as a KERI AID, when the verifier resolves it (@6g9zjsv9).
         * The default is the key itself, which any verifier can decode.
         */
        public SignOptions withKeyid(String keyid) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag, keyid, minimum);
        }

        /**
         * Refuse to sign a covered list the verifier would refuse: {@link #REQUEST_MINIMUM} or
         * {@link #RESPONSE_MINIMUM}, or a superset (@2f227n4r).
         */
        public SignOptions withMinimum(List<String> minimum) {
            return new SignOptions(body, covered, created, label, expires, nonce, tag, keyid, minimum);
        }
    }

    /**
     * The outcome of a successful verification. A throw means it did not verify.
     *
     * <p>{@code aid} is the non-transferable AID of the key that verified — or, when a resolver
     * supplied that key, the keyid the resolver vouched for (@6g9zjsv9). {@code covered} names each
     * component as a signer would: a plain name, or its serialized form when it carries a
     * parameter, such as {@code "@path";req}. {@code keyid} is the keyid as received.
     */
    public record Verdict(String aid, List<String> covered, String keyid) {}

    /**
     * A verifier's freshness decision: a maximum age in seconds, or {@link #DECLINED}. A value
     * rather than a nullable number, so that no constructor can leave the decision unstated
     * (this.i @67shl6c5, @3e7wnyvg).
     */
    public record Freshness(Long maxAge) {
        /** The freshness check, explicitly declined. An {@code expires} is enforced regardless. */
        public static final Freshness DECLINED = new Freshness(null);

        public Freshness {
            if (maxAge != null && maxAge <= 0) {
                throw new IllegalArgumentException(
                    "A maximum age is a positive number of seconds; to skip the age check, decline it.");
            }
        }
    }

    /**
     * The verifier's policy and the body it has in hand.
     *
     * <p>There is no default freshness: {@link #maxAge(long)} or {@link #decliningFreshness()},
     * and the canonical constructor refuses a null {@link Freshness}. Both defaults would be wrong
     * (this.i @67shl6c5).
     */
    public record VerifyOptions(
            Freshness freshness, byte[] body, String expectedAid, Long skew, Long now, Resolver resolver,
            List<String> minimum, String expectedKeyid, Set<String> authorities) {

        public VerifyOptions {
            if (freshness == null) {
                throw new IllegalArgumentException(
                    "State a freshness decision: a maximum age, or Freshness.DECLINED to decline the check.");
            }
            if (skew != null && skew <= 0) {
                throw new IllegalArgumentException("A clock skew allowance is a positive number of seconds.");
            }
        }

        /** Decline the freshness check, explicitly. */
        public static VerifyOptions decliningFreshness() {
            return new VerifyOptions(Freshness.DECLINED, null, null, null, null, null, null, null, null);
        }

        public static VerifyOptions maxAge(long seconds) {
            return new VerifyOptions(new Freshness(seconds), null, null, null, null, null, null, null, null);
        }

        /** The maximum age in seconds, or null when the check is declined. */
        public Long maxAge() {
            return freshness.maxAge();
        }

        public VerifyOptions withBody(byte[] body) {
            return new VerifyOptions(freshness, body, expectedAid, skew, now, resolver, minimum, expectedKeyid, authorities);
        }

        /** The key the verifier already knows this message should be signed by; authoritative. */
        public VerifyOptions withExpectedAid(String aid) {
            return new VerifyOptions(freshness, body, aid, skew, now, resolver, minimum, expectedKeyid, authorities);
        }

        public VerifyOptions withNow(long now) {
            return new VerifyOptions(freshness, body, expectedAid, skew, now, resolver, minimum, expectedKeyid, authorities);
        }

        public VerifyOptions withSkew(long skew) {
            return new VerifyOptions(freshness, body, expectedAid, skew, now, resolver, minimum, expectedKeyid, authorities);
        }

        /** Resolve the keyid through the caller's own key state (@6g9zjsv9). */
        public VerifyOptions withResolver(Resolver resolver) {
            return new VerifyOptions(freshness, body, expectedAid, skew, now, resolver, minimum, expectedKeyid, authorities);
        }

        /**
         * The verifier's covered-set policy, {@link #REQUEST_MINIMUM} or {@link #RESPONSE_MINIMUM}
         * or a superset, which also enforces the body rule and requires {@code created}. A
         * signature covering less is refused even though it verifies (@7f28p7xk).
         */
        public VerifyOptions withMinimum(List<String> minimum) {
            return new VerifyOptions(freshness, body, expectedAid, skew, now, resolver, minimum, expectedKeyid, authorities);
        }

        /** Refuse a signature by any other keyid, as {@code UnknownKey} (profile R1). */
        public VerifyOptions withExpectedKeyid(String keyid) {
            return new VerifyOptions(freshness, body, expectedAid, skew, now, resolver, minimum, keyid, authorities);
        }

        /**
         * The {@code @authority} values this verifier serves; a covered one outside the set is a
         * {@code SignatureMismatch}, and supplying them makes {@code @authority} required, so a
         * signature that does not cover it is {@code InsufficientCoverage} (@605z9tnw). Requests
         * only (@3cceqvg3).
         */
        public VerifyOptions withAuthorities(Set<String> authorities) {
            return new VerifyOptions(freshness, body, expectedAid, skew, now, resolver, minimum, expectedKeyid, authorities);
        }
    }

    /* ------------------------------------------------------------- component identifiers */

    /** The spelling of a request component named from a response: {@code req("@path")}. */
    public static String req(String name) {
        return Sfv.serializeBareItem(lower(name)) + ";" + REQ;
    }

    /**
     * A component identifier from a caller's spelling of it: a plain name ({@code "@method"},
     * {@code "Content-Digest"}) or its RFC 8941 serialization with parameters
     * ({@code "\"@method\";req"}). Names are lowercased as a convenience to a local caller; a name
     * parsed from the wire is never lowercased, and is refused instead when it is not already.
     */
    static Sfv.Item component(String spec) {
        if (spec.startsWith("\"")) {
            Sfv.Item item;
            try {
                item = Sfv.parseItem(spec);
            } catch (Sfv.SyntaxException e) {
                throw new FikiException(
                    FikiException.Kind.UnsupportedComponent,
                    "fiki cannot read " + spec + " as a component identifier; name a component "
                        + "plainly, as \"@path\", or in its serialized form, as '\"@path\";req'.",
                    spec);
            }
            return new Sfv.Item(named(lower((String) item.value()), spec), item.params());
        }
        return new Sfv.Item(named(lower(spec), spec), List.of());
    }

    private static final Pattern FIELD_NAME = Pattern.compile("[a-z0-9!#$%&'*+.^_`|~-]+");

    /**
     * A caller's component name, refused when it could not be serialized faithfully: every name
     * an RFC 8941 string, and a field name an HTTP field name, lowercase tchar (@3e7wnyvg).
     */
    private static String named(String name, String spec) {
        boolean derived = name.startsWith("@");
        boolean ok = derived ? name.chars().allMatch(c -> c >= 0x20 && c <= 0x7e) : FIELD_NAME.matcher(name).matches();
        if (!ok) {
            throw new IllegalArgumentException(
                "The component " + spec.replaceAll("[^\\x20-\\x7e]", "?") + " is not "
                    + (derived ? "an RFC 8941 string" : "an HTTP field name") + ", so it cannot be signed.");
        }
        return name;
    }

    private static List<Sfv.Item> components(List<String> specs) {
        List<Sfv.Item> out = new ArrayList<>(specs.size());
        for (String spec : specs) {
            out.add(component(spec));
        }
        return out;
    }

    private static String name(Sfv.Item item) {
        return (String) item.value();
    }

    /** The inverse of {@link #component}: a plain name when it has no parameters. */
    private static String specOf(Sfv.Item item) {
        return item.params().isEmpty() ? name(item) : Sfv.serializeItem(item);
    }

    /** What two identifiers must share to be the same component. Parameter order is not it. */
    private static String identity(Sfv.Item item) {
        List<Map.Entry<String, Object>> sorted = new ArrayList<>(item.params());
        sorted.sort(Map.Entry.comparingByKey(Comparator.naturalOrder()));
        return Sfv.serializeItem(new Sfv.Item(item.value(), sorted));
    }

    private static boolean isReq(Sfv.Item item) {
        return Boolean.TRUE.equals(item.param(REQ));
    }

    /**
     * Refuse a covered list fiki cannot build faithfully: duplicates first, then the unsupported.
     * That order is the KERI profile's section 9, so a list that is both has one correct refusal.
     */
    private static void checkCovered(List<Sfv.Item> items, boolean response) {
        Set<String> seen = new HashSet<>();
        for (Sfv.Item item : items) {
            if (!seen.add(identity(item))) {
                throw new FikiException(
                    FikiException.Kind.DuplicateComponent,
                    "The covered components name " + specOf(item) + " twice, so the signature base "
                        + "would not be what either copy says it is.",
                    specOf(item));
            }
        }
        for (Sfv.Item item : items) {
            boolean req = isReq(item);
            boolean otherParams = item.params().stream().anyMatch(entry -> !entry.getKey().equals(REQ));
            if (otherParams || (item.has(REQ) && !(req && response))) {
                throw new FikiException(
                    FikiException.Kind.UnsupportedComponent,
                    "fiki does not support the component " + specOf(item) + ": the only component "
                        + "parameter it supports is \"" + REQ + "\", and only in a response.",
                    specOf(item));
            }
            if (name(item).startsWith("@")) {
                List<String> supported = req || !response ? DERIVED : RESPONSE_DERIVED;
                if (!supported.contains(name(item))) {
                    throw new FikiException(
                        FikiException.Kind.UnsupportedComponent,
                        "fiki does not build the derived component " + specOf(item) + " in a "
                            + (response ? "response" : "request") + "; it builds "
                            + String.join(", ", supported) + ".",
                        specOf(item));
                }
            }
        }
    }

    /* ---------------------------------------------------------------- the signature base */

    /** A message as the base sees it: header names lowercased, values exactly as received. */
    /**
     * {@code received} is true on the verify side, where the message came from a peer: a target
     * that cannot be read there is a defect of the message, coded, rather than the caller's
     * mistake (@2r05k9g0).
     */
    private record Message(
            Map<String, String> headers, String method, Target target, Integer status, Message request,
            boolean received) {}

    private static Message requestMessage(String method, String url, Map<String, String> headers, boolean received) {
        requireMethod(method);
        if (url == null) {
            throw new IllegalArgumentException("A request needs a URL.");
        }
        return new Message(lowered(headers), method, Target.split(url), null, null, received);
    }

    private static Message responseMessage(int status, Map<String, String> headers, Request request, boolean received) {
        Message answered = request == null ? null
            : requestMessage(request.method(), request.url(), request.headers(), received);
        return new Message(lowered(headers), null, null, status, answered, received);
    }

    private static void requireMethod(String method) {
        if (method == null || method.isEmpty()) {
            // An @method of "" or "null" is a request nobody sent (@3cceqvg3).
            throw new IllegalArgumentException("A request needs a method, as it will be sent.");
        }
    }

    /** Build the RFC 9421 signature base for a request. */
    public static byte[] signatureBase(
            String method, String url, Map<String, String> headers, List<String> covered, Params params) {
        List<Sfv.Item> items = components(covered);
        checkCovered(items, false);
        return finish(linesFor(items, requestMessage(method, url, headers, false)), items, params);
    }

    /**
     * Build the RFC 9421 signature base for a response (sections 2.2.9 and 2.4). {@code request}
     * is the request being answered, which {@code req} components are read from; without one, a
     * {@code req} component is a {@code MissingComponent}.
     */
    public static byte[] responseSignatureBase(
            int status, Map<String, String> headers, List<String> covered, Params params, Request request) {
        List<Sfv.Item> items = components(covered);
        checkCovered(items, true);
        return finish(linesFor(items, responseMessage(status, headers, request, false)), items, params);
    }

    private static byte[] finish(List<String> lines, List<Sfv.Item> items, Params params) {
        // The signing side only: refuse a parameter the verifier would refuse, or that would
        // inject a line into Signature-Input, before anything is serialized (@2r05k9g0).
        sfInteger("created", params.created());
        sfInteger("expires", params.expires());
        sfString("nonce", params.nonce());
        sfString("alg", params.alg());
        sfString("keyid", params.keyid());
        sfString("tag", params.tag());
        // Order is the signer's choice — a verifier reserializes whatever it received — so fiki
        // fixes one order and keeps it, which makes its own output reproducible.
        List<Map.Entry<String, Object>> ordered = new ArrayList<>();
        if (params.created() != null) ordered.add(Map.entry("created", params.created()));
        if (params.expires() != null) ordered.add(Map.entry("expires", params.expires()));
        if (params.nonce() != null) ordered.add(Map.entry("nonce", params.nonce()));
        if (params.alg() != null) ordered.add(Map.entry("alg", params.alg()));
        if (params.keyid() != null) ordered.add(Map.entry("keyid", params.keyid()));
        if (params.tag() != null) ordered.add(Map.entry("tag", params.tag()));
        return finish(lines, new Sfv.InnerList(items, ordered));
    }

    private static final long SF_INTEGER_MAX = 999_999_999_999_999L;

    private static void sfInteger(String name, Long value) {
        if (value != null && (value > SF_INTEGER_MAX || value < -SF_INTEGER_MAX)) {
            throw new IllegalArgumentException(
                "The signature parameter " + name + " is " + value + ", and RFC 8941 integers have at most "
                    + "fifteen digits, so no verifier would read it.");
        }
    }

    private static void sfString(String name, String value) {
        if (value == null) {
            return;
        }
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch < 0x20 || ch > 0x7e) {
                throw new IllegalArgumentException(
                    "The signature parameter " + name + " contains a character outside visible ASCII and "
                        + "space, which an RFC 8941 string cannot carry.");
            }
        }
    }

    private static final Pattern SF_KEY = Pattern.compile("[a-z*][a-z0-9_\\-.*]*");

    private static byte[] finish(List<String> lines, Sfv.InnerList inner) {
        List<String> all = new ArrayList<>(lines);
        all.add("\"@signature-params\": " + Sfv.serializeInnerList(inner));
        return String.join("\n", all).getBytes(StandardCharsets.UTF_8);
    }

    private static List<String> linesFor(List<Sfv.Item> items, Message message) {
        List<String> lines = new ArrayList<>(items.size());
        for (Sfv.Item item : items) {
            lines.add(Sfv.serializeItem(item) + ": " + valueOf(item, message));
        }
        return lines;
    }

    /**
     * A component's value, refused when it has no single serialization both sides agree on. A
     * line break inside a value would forge a line of the base, and a byte outside visible ASCII is
     * encoded differently by different stacks, so such a base cannot be built and the refusal is a
     * signature mismatch (@2f227n4r).
     */
    private static String valueOf(Sfv.Item item, Message message) {
        return checked(componentValue(item, message), specOf(item));
    }

    private static String checked(String value, String spec) {
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!(ch == '\t' || (ch >= ' ' && ch <= '~'))) {
                throw new FikiException(
                    FikiException.Kind.SignatureMismatch,
                    "The value of " + spec + " contains a line break, a control character or a "
                        + "non-ASCII character, so there is no signature base both sides would build from it.");
            }
        }
        return value;
    }

    /**
     * A field value as the base carries it: checked on the RAW value, then stripped of leading and
     * trailing spaces and tabs only (RFC 9421 section 2.1). Checking after trimming would let a
     * value ending in CR LF verify as the value without it (@3cceqvg3).
     */
    private static String fieldValue(String raw, String spec) {
        checked(raw, spec);
        int start = 0;
        int end = raw.length();
        while (start < end && (raw.charAt(start) == ' ' || raw.charAt(start) == '\t')) {
            start++;
        }
        while (end > start && (raw.charAt(end - 1) == ' ' || raw.charAt(end - 1) == '\t')) {
            end--;
        }
        return raw.substring(start, end);
    }

    private static String componentValue(Sfv.Item item, Message message) {
        String name = name(item);
        if (isReq(item)) {
            if (message.request() == null) {
                throw new FikiException(
                    FikiException.Kind.MissingComponent,
                    "The signature covers " + specOf(item) + ", which is read from the request this "
                        + "response answers, and no request was supplied.",
                    specOf(item));
            }
            message = message.request();
        }
        switch (name) {
            case "@status":
                // Section 2.2.9: the three-digit status code. Anything else is not a status this
                // component can carry, so there is no value to sign or to check.
                // A request message has no status, and checkCovered has already refused @status
                // anywhere but a response's own components, so this is always a response's.
                int status = message.status();
                if (status < 100 || status > 999) {
                    throw new FikiException(
                        FikiException.Kind.MissingComponent,
                        "The signature covers @status, and " + status + " is not a "
                            + "three-digit HTTP status code, so there is no status line to build.",
                        "@status");
                }
                return Integer.toString(status);
            // Section 2.2.1: the method as sent, with no case transformation (@22g0xkr8).
            case "@method":
                return message.method();
            case "@authority":
                return authority(message.target(), message.headers(), message.received());
            // An empty path is the "/" the origin server would have received.
            case "@path":
                return message.target().path();
            // Section 2.2.7: the whole query string including the leading "?", percent-encoding
            // preserved, and a bare "?" when the request carries no query at all.
            case "@query":
                return "?" + message.target().query();
            default:
                break;
        }
        String value = message.headers().get(name);
        if (value == null) {
            throw new FikiException(
                FikiException.Kind.MissingComponent,
                "The signature covers " + specOf(item) + ", but the message carries no value for it, "
                    + "so the signature base cannot be built.",
                specOf(item));
        }
        return fieldValue(value, specOf(item));
    }

    /**
     * A request target split without a URI parser doing the work: fiki needs the scheme, authority,
     * path and RAW query, and {@link java.net.URI} normalizes in ways RFC 9421 sections 2.2.6 and
     * 2.2.7 say not to (@8yucn7nv).
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

    /**
     * The authority, normalized per RFC 9421 section 2.2.3: lowercase host, default port omitted.
     * Userinfo is dropped and the port compared as a number, as fiki-py's urlsplit does; an IPv6
     * literal keeps its brackets, as RFC 3986 section 3.2.2 writes it (@8yucn7nv).
     *
     * <p>A relative URL falls back to the Host header, which in HTTP/1.1 *is* the authority — the
     * shape a server-side verifier actually holds. Nothing is normalized away there, because
     * without a scheme no port is a default port.
     */
    private static String authority(Target target, Map<String, String> headers, boolean received) {
        if (target.authority() == null || target.authority().isEmpty()) {
            String host = headers.get("host");
            if (host == null) {
                throw new FikiException(
                    FikiException.Kind.MissingComponent,
                    "The signature covers \"@authority\", but the URL carries no authority and the "
                        + "request has no Host header, so there is nothing to derive it from.",
                    "@authority");
            }
            return lower(fieldValue(host, "@authority"));
        }
        String raw = target.authority();
        raw = raw.substring(raw.lastIndexOf('@') + 1).toLowerCase(Locale.ROOT);
        String host;
        String port;
        if (raw.startsWith("[")) {
            int close = raw.indexOf(']');
            if (close < 0) {
                throw unreadable("The URL's IPv6 literal " + raw + " has no closing bracket.", received);
            }
            host = raw.substring(0, close + 1);
            String after = raw.substring(close + 1);
            if (!after.isEmpty() && !after.startsWith(":")) {
                throw unreadable("The URL's authority " + raw + " has text after its IPv6 literal.", received);
            }
            port = after.isEmpty() ? "" : after.substring(1);
        } else {
            int colon = raw.lastIndexOf(':');
            host = colon < 0 ? raw : raw.substring(0, colon);
            port = colon < 0 ? "" : raw.substring(colon + 1);
        }
        if (port.isEmpty()) {
            return host;
        }
        // Any run of ASCII digits, its leading zeros stripped BEFORE the length check, so no
        // padding reaches parseInt and :000080 is port 80 (@3e7wnyvg).
        String digits = port.replaceFirst("^0+(?=.)", "");
        if (!port.matches("[0-9]+") || digits.length() > 5 || Integer.parseInt(digits) > 65535) {
            throw unreadable(
                "The URL's port " + port + " is not a number from 0 to 65535.", received);
        }
        int number = Integer.parseInt(digits);
        // Only a URL with a scheme has an authority of its own, so the scheme is never null here.
        Integer defaultPort = DEFAULT_PORTS.get(target.scheme());
        return defaultPort != null && number == defaultPort ? host : host + ":" + number;
    }

    /**
     * A target that cannot be read: the caller's mistake when the caller is signing, and a base
     * that cannot be built — a signature mismatch, as @2f227n4r makes every such base — when the
     * URL came from a peer (@2r05k9g0).
     */
    private static RuntimeException unreadable(String why, boolean received) {
        if (received) {
            return new FikiException(FikiException.Kind.SignatureMismatch,
                why + " There is no @authority to build the signature base from.");
        }
        return new IllegalArgumentException(why);
    }

    private static Map<String, String> lowered(Map<String, String> headers) {
        // Header field names are case-insensitive and appear lowercased in the base (section 2.1).
        // Values are kept as received; fieldValue checks and strips the ones that are covered. A
        // map naming one field under two spellings gives no way to know which value the other side
        // saw, so it is refused rather than resolved by iteration order (@0ms4j0ef).
        Map<String, String> out = new LinkedHashMap<>();
        if (headers != null) {
            headers.forEach((name, value) -> {
                if (name == null || value == null) {
                    throw new IllegalArgumentException(
                        "A header name or value is null; pass each field as a name and its value.");
                }
                // By key presence, not by put's previous value, which a null could not tell apart
                // from absence (@2r05k9g0).
                String key = lower(name);
                if (out.containsKey(key)) {
                    throw new IllegalArgumentException(
                        "The headers name " + key + " more than once, under different spellings; "
                            + "HTTP field names are case-insensitive, so pass each field once.");
                }
                out.put(key, value);
            });
        }
        return out;
    }

    private static String lower(String text) {
        return text.toLowerCase(Locale.ROOT);
    }

    /* ------------------------------------------------------------------------- signing */

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

    /**
     * A supplied minimum selects the KERI profile's policy, so it may only add to the profile's.
     * Anything smaller is the caller's mistake rather than a message's defect, so it is an
     * IllegalArgumentException, thrown before any message is read (bakobo/fiki#4).
     */
    private static void floored(List<String> minimum, List<String> floor) {
        if (minimum == null) {
            return;
        }
        Set<String> given = new HashSet<>();
        for (String spec : minimum) {
            given.add(identity(component(spec)));
        }
        List<String> missing = floor.stream().filter(spec -> !given.contains(identity(component(spec)))).toList();
        if (!missing.isEmpty()) {
            throw new IllegalArgumentException(
                "A minimum covered set must include the profile's own, " + String.join(", ", floor)
                    + "; this one leaves out " + String.join(", ", missing) + ". Pass null to apply no minimum at all.");
        }
    }

    private static boolean bindsRequestDigest(List<Sfv.Item> items) {
        String bound = identity(component(req(CONTENT_DIGEST)));
        return items.stream().anyMatch(item -> identity(item).equals(bound));
    }

    private static boolean coversBody(List<Sfv.Item> items) {
        return items.stream().anyMatch(item -> item.params().isEmpty() && name(item).equals(CONTENT_DIGEST));
    }

    private static boolean hasContent(byte[] body) {
        return body != null && body.length > 0;
    }

    /** Cover a body the caller handed over, or refuse to sign (@2hwvpm42). */
    private static void coverBody(List<Sfv.Item> items, Map<String, String> sending, byte[] body, boolean chosen) {
        if (body == null) {
            return;
        }
        // Whether the caller CHOSE the covered set is the difference between fiki helping and fiki
        // overriding. On the default path a body simply gets covered; on an explicit path,
        // silently adding a component would cover something the caller did not ask for.
        if (!coversBody(items)) {
            if (chosen) {
                throw new FikiException(
                    FikiException.Kind.UncoveredBody,
                    "This message carries a body, but the covered components do not include "
                        + "\"content-digest\", so the signature would not bind the body. Add it to the "
                        + "covered set, or omit the body if it is genuinely not part of what you are signing.");
            }
            items.add(component(CONTENT_DIGEST));
        }
        String given = lowered(sending).get(CONTENT_DIGEST);
        if (given == null) {
            sending.put("Content-Digest", contentDigest(body));
        } else {
            // A digest of the caller's own is signed as given, so it must hold for the body: fiki
            // does not sign what its own verifier would refuse (@0ms4j0ef).
            compareDigest(readDigest(given), body);
        }
    }

    private static Map<String, String> signed(
            Key key, byte[] base, String label, Map<String, String> sending, Map<String, String> given) {
        String chosen = label == null ? "sig" : label;
        if (!SF_KEY.matcher(chosen).matches()) {
            throw new IllegalArgumentException(
                "The label " + chosen + " is not an RFC 8941 key: a lowercase letter or *, then lowercase "
                    + "letters, digits, _, -, . or *.");
        }
        byte[] signature = key.sign(base);
        String text = new String(base, StandardCharsets.UTF_8);
        String marker = "\"@signature-params\": ";
        String rendered = text.substring(text.lastIndexOf(marker) + marker.length());

        Map<String, String> out = new LinkedHashMap<>();
        out.put("Signature-Input", chosen + "=" + rendered);
        out.put("Signature", chosen + "=:" + Key.STD.encodeToString(signature) + ":");
        String made = sending.get("Content-Digest");
        if (made != null && !lowered(given).containsKey(CONTENT_DIGEST)) {
            out.put("Content-Digest", made);
        }
        return out;
    }

    private static Params params(Key key, SignOptions opts) {
        long created = opts.created() != null ? opts.created() : Instant.now().getEpochSecond();
        return new Params(created, opts.keyid() == null ? key.keyid() : opts.keyid(), ALG,
            opts.expires(), opts.nonce(), opts.tag());
    }

    /**
     * Sign a request and return the headers to add to it.
     *
     * <p>With a body and no explicit covered set, fiki computes a {@code Content-Digest}, returns
     * it among the headers, and covers it; with an explicit covered set that omits it, fiki
     * refuses with {@code UncoveredBody}. The method is signed exactly as given (@22g0xkr8).
     */
    public static Map<String, String> signRequest(
            Key key, String method, String url, Map<String, String> headers, SignOptions opts) {
        requireMethod(method);
        floored(opts.minimum(), REQUEST_MINIMUM);
        Map<String, String> sending = new LinkedHashMap<>(headers == null ? Map.of() : headers);
        boolean chosen = opts.covered() != null;
        List<Sfv.Item> items = components(chosen ? opts.covered() : DEFAULT_COVERED);
        coverBody(items, sending, opts.body(), chosen);
        Message message = requestMessage(method, url, sending, false);
        if (opts.minimum() != null) {
            checkMinimum(items, opts.minimum(), requestHasBody(message.headers(), opts.body()), false);
        }
        checkCovered(items, false);
        byte[] base = finish(linesFor(items, message), items, params(key, opts));
        return signed(key, base, opts.label(), sending, headers);
    }

    /**
     * Sign a response to {@code request} (null when there is none to bind) and return the headers
     * to add to it (RFC 9421 section 2.4).
     *
     * <p>By default the signature covers {@code @status}, a {@code Content-Digest} of any body,
     * and — when the request is given — its method, path and query, plus its
     * {@code content-digest} when its content was non-empty, each marked {@code req}. A request
     * with content and no digest to bind is refused as {@code UncoveredBody} rather than signed
     * into a response every profile client refuses, and a digest the request body contradicts is
     * refused as the verifier would refuse it.
     */
    public static Map<String, String> signResponse(
            Key key, int status, Request request, Map<String, String> headers, SignOptions opts) {
        floored(opts.minimum(), RESPONSE_MINIMUM);
        Map<String, String> sending = new LinkedHashMap<>(headers == null ? Map.of() : headers);
        boolean chosen = opts.covered() != null;
        // By content alone: both sides hold the whole request by now (@7p9s3g9k).
        boolean hadBody = request != null && hasContent(request.body());
        List<String> covered = opts.covered();
        if (!chosen) {
            covered = new ArrayList<>(List.of("@status"));
            if (request != null) {
                covered.addAll(List.of(req("@method"), req("@path"), req("@query")));
            }
        }
        List<Sfv.Item> items = components(covered);
        coverBody(items, sending, opts.body(), chosen);
        Message message = responseMessage(status, sending, request, false);
        if (!chosen && hadBody) {
            if (!message.request().headers().containsKey(CONTENT_DIGEST)) {
                throw new FikiException(
                    FikiException.Kind.UncoveredBody,
                    "The request this response answers carried a body and no Content-Digest, so the "
                        + "response has nothing to bind that body with. Sign the request with a digest "
                        + "first, or name the covered components yourself.");
            }
            items.add(component(req(CONTENT_DIGEST)));
        }
        if (opts.minimum() != null) {
            checkMinimum(items, opts.minimum(), hasContent(opts.body()), hadBody);
        }
        // The check verifyResponse will make, made first: a signer does not vouch for a request
        // digest that the request body it was handed contradicts (bakobo/fiki#4).
        if (request != null && request.body() != null && bindsRequestDigest(items)) {
            // Through the base-value path, so an absent digest is MissingComponent (@3e7wnyvg).
            compareDigest(readDigest(valueOf(component(req(CONTENT_DIGEST)), message)), request.body());
        }
        checkCovered(items, true);
        byte[] base = finish(linesFor(items, message), items, params(key, opts));
        return signed(key, base, opts.label(), sending, headers);
    }

    /* ----------------------------------------------------------------------- verifying */

    /**
     * Verify a signed request, returning a {@link Verdict} or throwing.
     *
     * <p>An expected AID is authoritative when supplied — the preregistration case. A resolver is
     * the other way to be authoritative (@6g9zjsv9). Pass one or neither.
     */
    public static Verdict verifyRequest(
            String method, String url, Map<String, String> headers, VerifyOptions opts) {
        floored(opts.minimum(), REQUEST_MINIMUM);
        return verify(requestMessage(method, url, headers, true), false, null, opts);
    }

    /**
     * Verify a signed response to {@code request}, returning a {@link Verdict} or throwing.
     *
     * <p>An unsigned 401 is {@code Unauthenticated}, checked before anything else in the message,
     * because a server that refuses before it knows the agent cannot sign the refusal. A response
     * covering {@code "content-digest";req} verified against a request whose body is null is the
     * caller's mistake: that digest is recomputed over the request body, and fiki cannot check a
     * body it was not given.
     */
    public static Verdict verifyResponse(
            int status, Map<String, String> headers, Request request, VerifyOptions opts) {
        floored(opts.minimum(), RESPONSE_MINIMUM);
        if (opts.authorities() != null) {
            throw new IllegalArgumentException(
                "Served authorities are a request policy; a response has no @authority of its own to check.");
        }
        Message message = responseMessage(status, headers, request, true);
        // An empty Signature header signs nothing, so it takes the unsigned path too (@2r05k9g0).
        String signature = message.headers().get("signature");
        if (status == 401 && (signature == null || signature.isEmpty())) {
            throw new FikiException(
                FikiException.Kind.Unauthenticated,
                "The server answered 401 without signing the answer, so the request was not "
                    + "authenticated and the body of the refusal cannot be trusted.");
        }
        return verify(message, true, request, opts);
    }

    private record Parsed(Sfv.InnerList inner, byte[] signature) {}

    private record Resolved(byte[] raw, String aid) {}

    /**
     * The KERI profile's section 9 order, so a message has exactly one correct refusal. Every
     * header is read from the message's one canonical map (@0ms4j0ef).
     */
    private static Verdict verify(
            Message message, boolean response, Request request, VerifyOptions opts) {
        if (opts.expectedAid() != null && opts.resolver() != null) {
            throw new IllegalArgumentException("Pass an expected AID or a resolver, not both; each decides the key alone.");
        }
        Map<String, String> found = message.headers();
        // Under a minimum the profile applies, and it makes keyid REQUIRED whoever names the key
        // (@6hsuwdh8); otherwise only a verifier with no key of its own needs one.
        boolean profile = opts.minimum() != null;
        Parsed parsed = read(found, opts.expectedAid() == null || profile, profile);
        Sfv.InnerList inner = parsed.inner();
        List<Sfv.Item> items = inner.items();
        checkCovered(items, response);
        if (opts.minimum() != null) {
            checkMinimum(items, opts.minimum(),
                response ? hasContent(opts.body()) : requestHasBody(found, opts.body()),
                // By the request's content alone, as signResponse decides it (@7p9s3g9k).
                request != null && hasContent(request.body()));
        }
        // Served authorities bind the signature to a host only if it commits to one, so supplying
        // them makes @authority required (@605z9tnw): coverage, before the key, as section 9 orders.
        if (opts.authorities() != null) {
            checkMinimum(items, List.of("@authority"), false, false);
        }

        // Section 9's key steps in order (@5zrf8gjk): what the keyid alone shows, then the expected
        // keyid, and only then the resolver, which is never asked about a keyid already refused.
        String keyid = (String) inner.param("keyid");
        Resolved local = localKey(opts.expectedAid(), keyid, opts.resolver());
        if (opts.expectedKeyid() != null && !opts.expectedKeyid().equals(keyid)) {
            throw new FikiException(
                FikiException.Kind.UnknownKey,
                "This message is signed by \"" + keyid + "\", and the one expected is \"" + opts.expectedKeyid() + "\".",
                keyid);
        }
        Resolved resolved = local != null ? local : resolved(keyid, opts.resolver());
        Object alg = inner.param("alg");
        if (alg != null && !ALG.equals(alg)) {
            throw new FikiException(
                FikiException.Kind.UnsupportedAlgorithm,
                "This signature is made with \"" + alg + "\", and fiki verifies only " + ALG + " signatures.",
                (String) alg);
        }

        byte[] base = finish(linesFor(items, message), inner);
        if (!verifySignature(resolved.raw(), parsed.signature(), base)) {
            throw new FikiException(
                FikiException.Kind.SignatureMismatch,
                "The signature does not match this message under the signer's key, so the message "
                    + "cannot be treated as authentic.");
        }

        if (opts.authorities() != null) {
            for (Sfv.Item item : items) {
                if (name(item).equals("@authority") && !opts.authorities().contains(valueOf(item, message))) {
                    throw new FikiException(
                        FikiException.Kind.SignatureMismatch,
                        "The signature covers the authority \"" + valueOf(item, message) + "\", which this "
                            + "verifier does not serve, so it was signed for somebody else.");
                }
            }
        }

        // AFTER the signature check, deliberately. created and expires are covered by the
        // signature, so acting on them before verifying it would enforce a policy against values
        // an attacker could still have chosen — and would tell that attacker their forgery at
        // least parsed.
        checkFreshness(inner, opts);

        List<String> headersToRead = new ArrayList<>();
        List<byte[]> contents = new ArrayList<>();
        if (coversBody(items)) {
            headersToRead.add(found.get(CONTENT_DIGEST));
            contents.add(opts.body());
        }
        // A response binding the request's digest binds a request body only if somebody hashes it
        // (bakobo/fiki#4). A verifier handed no request body cannot, and a verdict that skipped the
        // check would look like one that made it, so that is the caller's mistake, not a pass.
        if (request != null && bindsRequestDigest(items)) {
            if (request.body() == null) {
                throw new IllegalArgumentException(
                    "The response covers \"content-digest\";req, so the request body it binds must be "
                        + "supplied in the Request to be checked; it was not.");
            }
            headersToRead.add(message.request().headers().get(CONTENT_DIGEST));
            contents.add(request.body());
        }
        // Every covered digest is parsed before any is compared, so a malformed one outranks a
        // mismatched one wherever each sits (profile section 9, bakobo/fiki#4).
        List<List<Digest>> recognized = new ArrayList<>();
        for (String header : headersToRead) {
            recognized.add(readDigest(header));
        }
        for (int i = 0; i < recognized.size(); i++) {
            compareDigest(recognized.get(i), contents.get(i));
        }

        return new Verdict(resolved.aid(), items.stream().map(Fiki::specOf).toList(), keyid);
    }

    private static boolean verifySignature(byte[] raw, byte[] signature, byte[] base) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(Key.decodePublic(raw));
            verifier.update(base);
            return verifier.verify(signature);
        } catch (java.security.SignatureException e) {
            // A signature the provider cannot even read is a mismatch, not a crash.
            return false;
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("verification failed", e);
        }
    }

    /**
     * The profile's request body test: a length above zero, any transfer coding, or content.
     * Requests only; a response's body is its content, since a HEAD or 304 response carries the
     * length of a representation it does not send (@2f227n4r).
     */
    private static boolean requestHasBody(Map<String, String> found, byte[] body) {
        if (hasContent(body)) {
            return true;
        }
        if (found.containsKey("transfer-encoding")) {
            return true;
        }
        String length = found.get("content-length");
        if (length == null) {
            return false;
        }
        // Fail closed: a length that is not a plain decimal, negative ones included, is not
        // evidence that there is no body.
        String trimmed = length.strip();
        return !trimmed.matches("[0-9]+") || !trimmed.matches("0+");
    }

    private static void checkMinimum(List<Sfv.Item> items, List<String> minimum, boolean hasBody, boolean requestHadBody) {
        Set<String> have = new HashSet<>();
        for (Sfv.Item item : items) {
            have.add(identity(item));
        }
        List<Sfv.Item> required = components(minimum);
        if (hasBody) {
            required.add(component(CONTENT_DIGEST));
        }
        if (requestHadBody) {
            required.add(component(req(CONTENT_DIGEST)));
        }
        for (Sfv.Item item : required) {
            if (!have.contains(identity(item))) {
                throw new FikiException(
                    FikiException.Kind.InsufficientCoverage,
                    "The signature does not cover " + specOf(item) + ", which this verifier requires, so "
                        + "it is refused even though it may be valid: a signature over too little is a "
                        + "signature over what an intermediary is free to change.",
                    specOf(item));
            }
        }
    }

    /**
     * Pull one signature and its input out of the headers, or say what is wrong with them. In the
     * KERI profile's section 9 order: absence before malformation, the Signature header before
     * Signature-Input, the members' shape before the label count.
     */
    private static Parsed read(Map<String, String> found, boolean requireKeyid, boolean requireCreated) {
        String rawSignature = found.get("signature");
        String rawInput = found.get("signature-input");
        if (rawSignature == null || rawSignature.isEmpty()) {
            throw new FikiException(
                FikiException.Kind.MissingSignature,
                "This message has no Signature header, so there is nothing to verify.");
        }
        if (rawInput == null || rawInput.isEmpty()) {
            throw new FikiException(
                FikiException.Kind.MissingSignatureInput,
                "This message has no Signature-Input header, so there is no way to know which "
                    + "components a signature would cover.");
        }

        List<Sfv.Member> signatures = parse(rawSignature, "Signature", FikiException.Kind.MalformedSignature);
        for (Sfv.Member member : signatures) {
            if (!(member.value() instanceof byte[])) {
                throw new FikiException(
                    FikiException.Kind.MalformedSignatureValue,
                    "RFC 9421 carries a signature as an RFC 8941 byte sequence, wrapped in colons; "
                        + "this Signature header carries something else.");
            }
        }
        List<Sfv.Member> inputs = parse(rawInput, "Signature-Input", FikiException.Kind.MalformedSignatureInput);
        for (Sfv.Member member : inputs) {
            checkInput(member, requireKeyid, requireCreated);
        }

        if (inputs.size() != 1 || signatures.size() != 1) {
            throw new FikiException(
                FikiException.Kind.MalformedSignatureLabel,
                "fiki verifies a message carrying exactly one signature; this one declares "
                    + inputs.size() + " in Signature-Input and " + signatures.size() + " in Signature.");
        }
        String label = inputs.get(0).key();
        if (!signatures.get(0).key().equals(label)) {
            throw new FikiException(
                FikiException.Kind.MissingSignatureLabel,
                "The Signature header carries no entry labelled \"" + label + "\", so the covered "
                    + "components describe a signature that is not here.",
                label);
        }
        byte[] value = (byte[]) signatures.get(0).value();
        if (value.length != SIGNATURE_LENGTH) {
            throw new FikiException(
                FikiException.Kind.MalformedSignatureValue,
                "RFC 9421 carries an Ed25519 signature as a 64-byte RFC 8941 byte sequence, wrapped "
                    + "in colons; this one is something else.");
        }
        return new Parsed((Sfv.InnerList) inputs.get(0).value(), value);
    }

    /** Refuse a Signature-Input member fiki would otherwise have to guess about. */
    private static void checkInput(Sfv.Member member, boolean requireKeyid, boolean requireCreated) {
        if (!(member.value() instanceof Sfv.InnerList inner)) {
            throw new FikiException(
                FikiException.Kind.MalformedSignatureInput,
                "A Signature-Input member is a parenthesized list of covered components; this one "
                    + "is a single value.");
        }
        for (Sfv.Item item : inner.items()) {
            if (!(item.value() instanceof String text)) {
                throw new FikiException(
                    FikiException.Kind.MalformedSignatureInput,
                    "Every covered component is named by a quoted string; " + Sfv.serializeItem(item) + " is not one.");
            }
            if (!text.startsWith("@") && !text.equals(lower(text))) {
                throw new FikiException(
                    FikiException.Kind.MalformedSignatureInput,
                    "The covered field " + Sfv.serializeItem(item) + " is not lowercase, and RFC 9421 "
                        + "section 2.1 requires field names in the covered list to be lowercased by the signer.");
            }
        }
        if (requireKeyid && !inner.has("keyid")) {
            // Here rather than when the key is resolved: keyid is REQUIRED, so its absence belongs
            // with the other defects of Signature-Input, ahead of the covered list (@2f227n4r).
            throw new FikiException(
                FikiException.Kind.MissingKey,
                "This signature carries no keyid, which the verifier's policy requires, so there is no "
                    + "key it names.");
        }
        if (requireCreated && !inner.has("created")) {
            // Only under a minimum, which is how a caller applies the KERI profile, where created
            // is REQUIRED. RFC 9421 makes it optional, and without a minimum it stays so (@7p9s3g9k).
            throw new FikiException(
                FikiException.Kind.MalformedSignatureInput,
                "This signature carries no created timestamp, which the verifier's policy requires.");
        }
        for (Map.Entry<String, Object> param : inner.params()) {
            Class<?> expected = SIGNATURE_PARAMS.get(param.getKey());
            if (expected == null) {
                throw new FikiException(
                    FikiException.Kind.MalformedSignatureInput,
                    "The signature parameter \"" + param.getKey() + "\" is not one fiki understands; it "
                        + "accepts " + String.join(", ", SIGNATURE_PARAMS.keySet()) + ".");
            }
            if (!expected.isInstance(param.getValue())) {
                throw new FikiException(
                    FikiException.Kind.MalformedSignatureInput,
                    "The signature parameter \"" + param.getKey() + "\" must be "
                        + (expected == Long.class ? "an integer" : "a quoted string") + ".");
            }
        }
    }

    /**
     * Parse one signature-related header, bounded before it is read (@5zrf8gjk): its size in bytes
     * first, on the raw value, then its shape, then the counts of what parsed. Over any bound is
     * the header's malformed class, never a crash or a slow parse.
     */
    private static List<Sfv.Member> parse(String raw, String name, FikiException.Kind kind) {
        // Never null: a covered digest header that is absent is already a MissingComponent.
        int bytes = raw.getBytes(StandardCharsets.UTF_8).length;
        if (bytes > MAX_FIELD_BYTES) {
            throw new FikiException(kind,
                "The " + name + " header is " + bytes + " bytes, and fiki reads one of at most "
                    + MAX_FIELD_BYTES + ".");
        }
        List<Sfv.Member> members;
        try {
            members = Sfv.parseDictionary(raw);
        } catch (Sfv.SyntaxException e) {
            throw new FikiException(kind,
                "I could not parse the " + name + " header; RFC 9421 spells it as an RFC 8941 dictionary.");
        }
        checkCounts(members, name, kind);
        return members;
    }

    private static void checkCounts(List<Sfv.Member> members, String name, FikiException.Kind kind) {
        if (members.size() > MAX_DICTIONARY_MEMBERS) {
            throw overLimit(name, kind, MAX_DICTIONARY_MEMBERS, "members");
        }
        for (Sfv.Member member : members) {
            if (member.params().size() > MAX_PARAMETERS) {
                throw overLimit(name, kind, MAX_PARAMETERS, "parameters on one item");
            }
            if (member.value() instanceof Sfv.InnerList inner) {
                if (inner.items().size() > MAX_INNER_LIST_ITEMS) {
                    throw overLimit(name, kind, MAX_INNER_LIST_ITEMS, "items in one inner list");
                }
                for (Sfv.Item item : inner.items()) {
                    if (item.params().size() > MAX_PARAMETERS) {
                        throw overLimit(name, kind, MAX_PARAMETERS, "parameters on one item");
                    }
                }
            }
        }
    }

    private static FikiException overLimit(String name, FikiException.Kind kind, int limit, String what) {
        return new FikiException(kind,
            "The " + name + " header has more than " + limit + " " + what + ", which is more than fiki "
                + "reads from any honest signer.");
    }

    /**
     * Every key check that needs nothing beyond the keyid itself (profile section 9): the key to
     * verify with and the identity to report, or null when the resolver decides. Either way a keyid
     * that is not well formed is refused here, before the expected keyid is compared and before any
     * resolver sees it (@5zrf8gjk).
     */
    private static Resolved localKey(String expectedAid, String keyid, Resolver resolver) {
        if (expectedAid != null) {
            byte[] raw = Key.trusted(Key.verifyingKeyBytes(expectedAid), expectedAid);
            return new Resolved(raw, Key.toAid(raw));
        }
        // Present and a string by now: checkInput refuses an absent keyid whenever no expected AID
        // was given, and a keyid of any other type. Empty is all that is left to refuse.
        if (keyid.isEmpty()) {
            throw new FikiException(
                FikiException.Kind.MissingKey,
                "This signature carries no keyid and no expected AID was supplied, so there is no "
                    + "key to verify it against.");
        }
        if (resolver != null) {
            if (Key.misspelledAid(keyid)) {
                throw new FikiException(
                    FikiException.Kind.MalformedKey,
                    "The keyid \"" + keyid + "\" is shaped like an AID and is not its canonical spelling, "
                        + "so it is not an AID at all.",
                    keyid);
            }
            return null;
        }
        // Strictly: a lenient decoder ignores trailing bits, so a keyid that is not the key's
        // encoding could verify as whatever key it happened to decode to. Only the one canonical
        // spelling is a key.
        if (!RAW_KEYID.matcher(keyid).matches()) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                "The keyid \"" + keyid + "\" is not a base64url-encoded 32-byte Ed25519 public key: that is "
                    + "exactly 43 characters from the base64url alphabet, unpadded.",
                keyid);
        }
        byte[] raw = Key.URL_DECODER.decode(keyid);
        if (!Key.URL.encodeToString(raw).equals(keyid)) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                "The keyid \"" + keyid + "\" is not the canonical base64url spelling of any key.",
                keyid);
        }
        return new Resolved(Key.trusted(raw, keyid), Key.toAid(raw));
    }

    /** The resolver's key for a keyid already found well formed, and the keyid it vouched for. */
    private static Resolved resolved(String keyid, Resolver resolver) {
        // The resolver is authoritative: fiki never falls back to decoding the keyid, because a
        // transferable prefix that embeds a key embeds its INCEPTION key (@6g9zjsv9).
        byte[] raw = resolver.resolve(keyid);
        if (raw == null) {
            throw new FikiException(
                FikiException.Kind.UnknownKey,
                "No key is known for the keyid \"" + keyid + "\", so the signature cannot be checked.",
                keyid);
        }
        if (raw.length != Key.RAW_LEN) {
            throw new FikiException(
                FikiException.Kind.MalformedKey,
                "The key resolved for \"" + keyid + "\" is not a 32-byte Ed25519 public key.",
                keyid);
        }
        return new Resolved(Key.trusted(raw.clone(), keyid), keyid);
    }

    /**
     * a + b and a - b, held at Long.MAX_VALUE or Long.MIN_VALUE instead of wrapping, so a limit
     * of Long.MAX_VALUE means no limit rather than a negative one, and a clock at either extreme
     * still compares the right way (@3e7wnyvg).
     */
    private static long sum(long a, long b) {
        try {
            return Math.addExact(a, b);
        } catch (ArithmeticException e) {
            // Only upward: b is always a skew, which is positive, so a sum overflows only past
            // Long.MAX_VALUE.
            return Long.MAX_VALUE;
        }
    }

    private static long difference(long a, long b) {
        try {
            return Math.subtractExact(a, b);
        } catch (ArithmeticException e) {
            return b < 0 ? Long.MAX_VALUE : Long.MIN_VALUE;
        }
    }

    /** Enforce the verifier's {@code maxAge}, then the signer's {@code expires} (section 9). */
    private static void checkFreshness(Sfv.InnerList inner, VerifyOptions opts) {
        Long expires = (Long) inner.param("expires");
        if (expires == null && opts.maxAge() == null) {
            return;
        }
        long skew = opts.skew() == null ? DEFAULT_SKEW : opts.skew();
        long stamp = opts.now() == null ? Instant.now().getEpochSecond() : opts.now();

        if (opts.maxAge() != null) {
            long maxAge = opts.maxAge();
            Long created = (Long) inner.param("created");
            if (created == null) {
                throw new FikiException(
                    FikiException.Kind.SignatureTooOld,
                    "This signature carries no created timestamp, so its age cannot be checked "
                        + "against the " + maxAge + "-second limit you asked for.");
            }
            if (difference(stamp, created) > sum(maxAge, skew)) {
                throw new FikiException(
                    FikiException.Kind.SignatureTooOld,
                    "This signature was created at " + created + ", which is more than " + maxAge
                        + " seconds before " + stamp + ", so it is too old to accept.");
            }
            if (difference(created, stamp) > skew) {
                throw new FikiException(
                    FikiException.Kind.SignatureTooOld,
                    "This signature claims to have been created at " + created + ", which is in the "
                        + "future relative to " + stamp + " by more than the " + skew + "-second skew allowance.");
            }
        }
        if (expires != null && stamp > sum(expires, skew)) {
            throw new FikiException(
                FikiException.Kind.SignatureExpired,
                "This signature expired at " + expires + " and it is now " + stamp
                    + ", so the signer has already declared it should not be accepted.");
        }
    }

    private record Digest(String name, String algorithm, byte[] expected) {}

    /**
     * Parse a Content-Digest into the members fiki computes, or refuse it as MalformedDigest.
     * Separate from the comparison so a verifier holding two covered digests parses both before
     * hashing either: section 9 puts malformed-digest first.
     */
    private static List<Digest> readDigest(String header) {
        List<Sfv.Member> parsed = parse(header, "Content-Digest", FikiException.Kind.MalformedDigest);
        List<Digest> recognized = new ArrayList<>();
        for (Sfv.Member member : parsed) {
            String algorithm = DIGEST_ALGORITHMS.get(member.key());
            if (algorithm == null) {
                continue;
            }
            if (!(member.value() instanceof byte[] expected)) {
                throw new FikiException(
                    FikiException.Kind.MalformedDigest,
                    "The " + member.key() + " Content-Digest is not an RFC 8941 byte sequence, so it "
                        + "cannot be compared with anything.");
            }
            recognized.add(new Digest(member.key(), algorithm, expected));
        }
        if (recognized.isEmpty()) {
            throw new FikiException(
                FikiException.Kind.MalformedDigest,
                "The Content-Digest header names no algorithm fiki computes; it computes sha-256 and sha-512.");
        }
        return recognized;
    }

    /**
     * Recompute the digest over the body actually received (@2hwvpm42). The header is covered by
     * the signature, so it cannot have been tampered with — but a covered digest still only
     * attests to a body nobody hashed until somebody hashes it.
     */
    private static void compareDigest(List<Digest> recognized, byte[] body) {
        if (body == null) {
            throw new FikiException(
                FikiException.Kind.DigestMismatch,
                "The signature covers content-digest, but no body was supplied to check it against, "
                    + "so the body is unverified.");
        }
        for (Digest digest : recognized) {
            if (!MessageDigest.isEqual(digest(digest.algorithm(), body), digest.expected())) {
                throw new FikiException(
                    FikiException.Kind.DigestMismatch,
                    "The body does not match its " + digest.name() + " Content-Digest, so the body is "
                        + "not the one that was signed.");
            }
        }
    }
}
