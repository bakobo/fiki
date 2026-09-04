package com.bakobo.fiki;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * The RFC 8941 subset RFC 9421 actually uses (this.i @2q9gv70t, @2tt6fmc0).
 *
 * <p>Hand-rolled rather than depended upon, for the reason every port hand-rolls it: fiki's slice
 * of structured fields is small and CLOSED — a dictionary whose members are inner lists of strings
 * with parameters, plus byte sequences — and the shared vectors pin its entire output surface byte
 * for byte. The usual argument against writing your own parser holds where the grammar is
 * open-ended; this one's every output is checked against committed bytes shared with four other
 * implementations.
 *
 * <p>What is deliberately NOT here: decimals, tokens, inner-list items with their own parameters,
 * and every field type RFC 9421 never puts in these two headers.
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

    /** A covered-component list with its parameters, in the order they arrived. */
    record InnerList(List<String> items, List<Map.Entry<String, Object>> params) {
        Object param(String key) {
            for (Map.Entry<String, Object> entry : params) {
                if (entry.getKey().equals(key)) {
                    return entry.getValue();
                }
            }
            return null;
        }
    }

    /** A dictionary member: either an inner list, or a bare value with parameters. */
    record Member(String key, InnerList list, Object value) {}

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
                } else {
                    out.append(ch);
                }
            }
            throw new SyntaxException("a string ran to the end of the field");
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

        long parseInteger() {
            int start = at;
            if (peek() == '-') {
                at++;
            }
            while (!done() && isDigit(peek())) {
                at++;
            }
            try {
                return Long.parseLong(text.substring(start, at));
            } catch (NumberFormatException e) {
                throw new SyntaxException("expected an integer at offset " + start);
            }
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
                return parseInteger();
            }
            throw new SyntaxException("unsupported item at offset " + at);
        }

        List<Map.Entry<String, Object>> parseParameters() {
            List<Map.Entry<String, Object>> params = new ArrayList<>();
            while (!done() && peek() == ';') {
                at++;
                skipSpace();
                String key = parseKey();
                if (!done() && peek() == '=') {
                    at++;
                    params.add(Map.entry(key, parseBareItem()));
                } else {
                    params.add(Map.entry(key, Boolean.TRUE));
                }
            }
            return params;
        }

        InnerList parseInnerList() {
            at++; // the opening parenthesis
            List<String> items = new ArrayList<>();
            while (true) {
                skipSpace();
                if (done()) {
                    throw new SyntaxException("an inner list ran to the end of the field");
                }
                if (peek() == ')') {
                    at++;
                    break;
                }
                Object item = parseBareItem();
                if (!(item instanceof String text)) {
                    throw new SyntaxException("fiki's covered components are strings");
                }
                // RFC 9421 never puts parameters on the members of a covered-component list.
                if (!done() && peek() == ';') {
                    throw new SyntaxException("parameters on a covered component");
                }
                if (!done() && peek() != ' ' && peek() != ')') {
                    throw new SyntaxException("expected a space or ) at offset " + at);
                }
                items.add(text);
            }
            return new InnerList(items, parseParameters());
        }
    }

    private static boolean isLower(char ch) {
        return ch >= 'a' && ch <= 'z';
    }

    private static boolean isDigit(char ch) {
        return ch >= '0' && ch <= '9';
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
                    member = new Member(key, cursor.parseInnerList(), null);
                } else {
                    Object value = cursor.parseBareItem();
                    member = new Member(key, new InnerList(List.of(), cursor.parseParameters()), value);
                }
            } else {
                member = new Member(key, new InnerList(List.of(), cursor.parseParameters()), Boolean.TRUE);
            }
            out.removeIf(existing -> existing.key().equals(key));
            out.add(member);
            cursor.skipSpace();
            if (cursor.done()) {
                break;
            }
            cursor.expect(',');
            cursor.skipSpace();
            if (cursor.done()) {
                throw new SyntaxException("a dictionary ended with a trailing comma");
            }
        }
        return out;
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
        // Only FALSE reaches here: RFC 8941 renders a true-valued parameter as a bare key, which
        // serializeParameters does before calling this, and fiki never puts a boolean in an item
        // position.
        return "?0";
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

    /** Render a covered-component list with its signature parameters. */
    static String serializeInnerList(InnerList list) {
        StringBuilder out = new StringBuilder("(");
        for (int i = 0; i < list.items().size(); i++) {
            if (i > 0) {
                out.append(' ');
            }
            out.append(serializeBareItem(list.items().get(i)));
        }
        return out.append(')').append(serializeParameters(list.params())).toString();
    }
}
