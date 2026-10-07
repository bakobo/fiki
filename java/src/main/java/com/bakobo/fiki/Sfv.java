package com.bakobo.fiki;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * The RFC 8941 subset RFC 9421 actually uses (this.i @2q9gv70t, @2tt6fmc0, @8yucn7nv).
 *
 * <p>Hand-rolled rather than depended upon, for the reason every port hand-rolls it: fiki's slice
 * of structured fields is small and CLOSED — dictionaries whose members are inner lists or bare
 * items with parameters — and the shared vectors pin its entire output surface byte for byte. The
 * usual argument against writing your own parser holds where the grammar is open-ended; this one's
 * every output is checked against committed bytes shared with four other implementations.
 *
 * <p>Every bare item type the grammar has is READ — integers, decimals, strings, tokens, byte
 * sequences, booleans — so that a header carrying the wrong type is refused for its type by the
 * caller, as fiki-py's http_sfv does, rather than failing to parse at all. Lists and items as
 * top-level fields are not here, because RFC 9421 puts neither in the headers fiki reads.
 */
final class Sfv {

    private Sfv() {}

    /**
     * This class's own failure, which never escapes the package: the parser cannot know WHICH
     * header it is reading, and the taxonomy distinguishes an unparsable Signature from an
     * unparsable Signature-Input, so callers translate it into the kind that names the header.
     */
    static final class SyntaxException extends RuntimeException {
        SyntaxException(String message) {
            super(message);
        }
    }

    /** An RFC 8941 token, kept distinct from a string because the two are different types. */
    record Token(String text) {}

    /** A bare item with its parameters, in the order they arrived. */
    record Item(Object value, List<Map.Entry<String, Object>> params) {
        Object param(String key) {
            return lookup(params, key);
        }

        boolean has(String key) {
            return params.stream().anyMatch(entry -> entry.getKey().equals(key));
        }
    }

    /** A parenthesized list of items with its parameters, in the order they arrived. */
    record InnerList(List<Item> items, List<Map.Entry<String, Object>> params) {
        Object param(String key) {
            return lookup(params, key);
        }

        boolean has(String key) {
            return params.stream().anyMatch(entry -> entry.getKey().equals(key));
        }
    }

    /** A dictionary member: an {@link InnerList}, or a bare value with its parameters. */
    record Member(String key, Object value, List<Map.Entry<String, Object>> params) {}

    private static Object lookup(List<Map.Entry<String, Object>> params, String key) {
        for (Map.Entry<String, Object> entry : params) {
            if (entry.getKey().equals(key)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static final class Cursor {
        private final String text;
        private int at;

        Cursor(String text) {
            this.text = text;
        }

        boolean done() {
            return at >= text.length();
        }

        char peek() {
            return done() ? '\0' : text.charAt(at);
        }

        void skipSpace() {
            while (!done() && peek() == ' ') {
                at++;
            }
        }

        void skipOws() {
            while (!done() && (peek() == ' ' || peek() == '\t')) {
                at++;
            }
        }

        void expect(char ch) {
            if (done() || peek() != ch) {
                throw new SyntaxException("expected " + ch + " at offset " + at);
            }
            at++;
        }

        String parseKey() {
            if (done() || !(isLower(peek()) || peek() == '*')) {
                throw new SyntaxException("a key starts with a lowercase letter or *");
            }
            int start = at;
            while (!done() && (isLower(peek()) || isDigit(peek()) || "_-.*".indexOf(peek()) >= 0)) {
                at++;
            }
            return text.substring(start, at);
        }

        String parseString() {
            at++; // the opening quote, which the caller already peeked
            StringBuilder out = new StringBuilder();
            while (!done()) {
                char ch = text.charAt(at++);
                if (ch == '\\') {
                    if (done()) {
                        throw new SyntaxException("a string ended mid-escape");
                    }
                    char escaped = text.charAt(at++);
                    if (escaped != '"' && escaped != '\\') {
                        throw new SyntaxException("only \\\" and \\\\ may be escaped");
                    }
                    out.append(escaped);
                } else if (ch == '"') {
                    return out.toString();
                } else if (ch < 0x20 || ch > 0x7e) {
                    // Section 3.3.3: a string is visible ASCII and space, nothing else.
                    throw new SyntaxException("a string carries a character outside visible ASCII");
                } else {
                    out.append(ch);
                }
            }
            throw new SyntaxException("a string ran to the end of the field");
        }

        Token parseToken() {
            int start = at;
            at++; // the first character, which the caller checked
            while (!done() && (isTchar(peek()) || peek() == ':' || peek() == '/')) {
                at++;
            }
            return new Token(text.substring(start, at));
        }

        byte[] parseByteSequence() {
            at++; // the opening colon
            int start = at;
            while (!done() && peek() != ':') {
                at++;
            }
            String encoded = text.substring(start, at);
            expect(':');
            try {
                return Base64.getDecoder().decode(encoded);
            } catch (IllegalArgumentException e) {
                throw new SyntaxException("a byte sequence must be base64 between colons");
            }
        }

        Object parseNumber() {
            // Section 3.3.1 and 3.3.2: at most fifteen digits for an integer, and at most twelve
            // before the point and three after it for a decimal. Java's long would take nineteen,
            // and a parser that accepted them would agree with no other implementation (@8yucn7nv).
            int start = at;
            if (peek() == '-') {
                at++;
            }
            int digitsStart = at;
            while (!done() && isDigit(peek())) {
                at++;
            }
            int whole = at - digitsStart;
            if (whole == 0) {
                throw new SyntaxException("expected a digit at offset " + at);
            }
            if (done() || peek() != '.') {
                if (whole > 15) {
                    throw new SyntaxException("an integer has at most fifteen digits");
                }
                return Long.parseLong(text.substring(start, at));
            }
            at++; // the point
            int fractionStart = at;
            while (!done() && isDigit(peek())) {
                at++;
            }
            int fraction = at - fractionStart;
            if (whole > 12 || fraction == 0 || fraction > 3) {
                throw new SyntaxException("a decimal has at most twelve digits, a point, and one to three more");
            }
            return new BigDecimal(text.substring(start, at));
        }

        Object parseBareItem() {
            char ch = peek();
            if (ch == '"') {
                return parseString();
            }
            if (ch == ':') {
                return parseByteSequence();
            }
            if (ch == '?') {
                at++;
                if (done()) {
                    throw new SyntaxException("a boolean is ?0 or ?1");
                }
                char flag = text.charAt(at++);
                if (flag != '0' && flag != '1') {
                    throw new SyntaxException("a boolean is ?0 or ?1");
                }
                return flag == '1';
            }
            if (ch == '-' || isDigit(ch)) {
                return parseNumber();
            }
            if (isAlpha(ch) || ch == '*') {
                return parseToken();
            }
            throw new SyntaxException("unsupported item at offset " + at);
        }

        List<Map.Entry<String, Object>> parseParameters() {
            List<Map.Entry<String, Object>> params = new ArrayList<>();
            while (!done() && peek() == ';') {
                at++;
                skipSpace();
                String key = parseKey();
                Object value = Boolean.TRUE;
                if (!done() && peek() == '=') {
                    at++;
                    value = parseBareItem();
                }
                // A repeated key overwrites the earlier value in its original place (section
                // 4.2.3.2), so a reader looking a parameter up gets the one a dictionary would.
                boolean replaced = false;
                for (int i = 0; i < params.size(); i++) {
                    if (params.get(i).getKey().equals(key)) {
                        params.set(i, Map.entry(key, value));
                        replaced = true;
                    }
                }
                if (!replaced) {
                    params.add(Map.entry(key, value));
                }
            }
            return params;
        }

        Item parseItem() {
            Object value = parseBareItem();
            return new Item(value, parseParameters());
        }

        InnerList parseInnerList() {
            at++; // the opening parenthesis
            List<Item> items = new ArrayList<>();
            while (true) {
                skipSpace();
                if (done()) {
                    throw new SyntaxException("an inner list ran to the end of the field");
                }
                if (peek() == ')') {
                    at++;
                    break;
                }
                items.add(parseItem());
                if (!done() && peek() != ' ' && peek() != ')') {
                    throw new SyntaxException("expected a space or ) at offset " + at);
                }
            }
            return new InnerList(items, parseParameters());
        }
    }

    private static boolean isLower(char ch) {
        return ch >= 'a' && ch <= 'z';
    }

    private static boolean isAlpha(char ch) {
        return isLower(ch) || (ch >= 'A' && ch <= 'Z');
    }

    private static boolean isDigit(char ch) {
        return ch >= '0' && ch <= '9';
    }

    private static boolean isTchar(char ch) {
        return isAlpha(ch) || isDigit(ch) || "!#$%&'*+-.^_`|~".indexOf(ch) >= 0;
    }

    /** Parse an RFC 8941 dictionary, preserving member order because the verify side needs it. */
    static List<Member> parseDictionary(String text) {
        Cursor cursor = new Cursor(text);
        List<Member> out = new ArrayList<>();
        cursor.skipSpace();
        while (!cursor.done()) {
            String key = cursor.parseKey();
            Member member;
            if (!cursor.done() && cursor.peek() == '=') {
                cursor.at++;
                if (cursor.peek() == '(') {
                    InnerList list = cursor.parseInnerList();
                    member = new Member(key, list, list.params());
                } else {
                    Item item = cursor.parseItem();
                    member = new Member(key, item.value(), item.params());
                }
            } else {
                member = new Member(key, Boolean.TRUE, cursor.parseParameters());
            }
            out.removeIf(existing -> existing.key().equals(key));
            out.add(member);
            cursor.skipOws();
            if (cursor.done()) {
                break;
            }
            cursor.expect(',');
            cursor.skipOws();
            if (cursor.done()) {
                throw new SyntaxException("a dictionary ended with a trailing comma");
            }
        }
        return out;
    }

    /** Parse one RFC 8941 item with its parameters, the whole of {@code text} and nothing else. */
    static Item parseItem(String text) {
        Cursor cursor = new Cursor(text);
        cursor.skipSpace();
        if (cursor.done()) {
            throw new SyntaxException("an item cannot be empty");
        }
        Item item = cursor.parseItem();
        cursor.skipSpace();
        if (!cursor.done()) {
            throw new SyntaxException("unexpected text after the item at offset " + cursor.at);
        }
        return item;
    }

    static String serializeBareItem(Object value) {
        if (value instanceof String text) {
            return '"' + text.replace("\\", "\\\\").replace("\"", "\\\"") + '"';
        }
        if (value instanceof Long n) {
            return n.toString();
        }
        if (value instanceof byte[] raw) {
            return ':' + Base64.getEncoder().encodeToString(raw) + ':';
        }
        if (value instanceof Token token) {
            return token.text();
        }
        if (value instanceof BigDecimal decimal) {
            String plain = decimal.toPlainString();
            return plain.contains(".") ? plain : plain + ".0";
        }
        return Boolean.TRUE.equals(value) ? "?1" : "?0";
    }

    static String serializeParameters(List<Map.Entry<String, Object>> params) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, Object> entry : params) {
            if (Boolean.TRUE.equals(entry.getValue())) {
                out.append(';').append(entry.getKey());
            } else {
                out.append(';').append(entry.getKey()).append('=').append(serializeBareItem(entry.getValue()));
            }
        }
        return out.toString();
    }

    static String serializeItem(Item item) {
        return serializeBareItem(item.value()) + serializeParameters(item.params());
    }

    /** Render a covered-component list with its signature parameters. */
    static String serializeInnerList(InnerList list) {
        StringBuilder out = new StringBuilder("(");
        for (int i = 0; i < list.items().size(); i++) {
            if (i > 0) {
                out.append(' ');
            }
            out.append(serializeItem(list.items().get(i)));
        }
        return out.append(')').append(serializeParameters(list.params())).toString();
    }
}
