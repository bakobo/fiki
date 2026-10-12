package com.bakobo.fiki;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Other spellings of an Ed25519 public key, read at the edge of the API (this.i @0mvgkwnl).
 *
 * <p>{@link Key#aidFrom} turns a public key spelled as an AID, as raw base64url (the wire keyid of
 * @7xrx5evg, also a JWK's "x"), as a base58btc did:key, as a did:peer with numalgo 0, or as an
 * OpenSSH public line into the canonical AID. The OpenSSH private-key reader is {@link OpenSsh}.
 *
 * <p>Nothing here touches a request. A verifier calls {@code aidFrom} when it loads its
 * registrations, so a bad one fails at configuration time rather than on a live request, and the
 * expected AID stays a single spelling. Every spelling has exactly one accepted form: each decoder
 * below re-encodes what it decoded and refuses a mismatch, so no key has two spellings that both
 * pass. Every decoded key then goes through {@link Key#trusted}, so no spelling is a way around the
 * small-order refusal (@37wdchu5).
 */
final class Formats {

    private Formats() {}

    // Checked before anything is decoded, so nothing below ever sees more than this (input-handling
    // standard: size, then shape, then meaning). An OpenSSH public line's comment is the only part
    // of any spelling that varies much, and 1024 characters leaves it ample room.
    static final int MAX_PUBLIC_CHARS = 1024;

    private static final int RAW_B64URL_LEN = 43;
    // multicodec ed25519-pub, 0xed as an unsigned varint
    private static final byte[] ED25519_PUB = {(byte) 0xed, 0x01};
    // A base58btc value over 34 bytes is at most 47 characters after the "z"; anything longer
    // cannot be an Ed25519 did:key, and refusing it first keeps base58's big-integer arithmetic to
    // a fixed size.
    private static final int MAX_MULTIBASE = 48;

    private static final String B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger FIFTY_EIGHT = BigInteger.valueOf(58);
    private static final Pattern B64URL = Pattern.compile("[A-Za-z0-9_-]*");
    // "ssh-ed25519", one space, the blob, and optionally one space and a printable-ASCII comment
    // that neither begins nor ends with a space, so that no whitespace around any field is ever
    // ignored.
    private static final Pattern SSH_LINE =
        Pattern.compile("ssh-ed25519 ([A-Za-z0-9+/=]+)(?: ([\\x21-\\x7e](?:[\\x20-\\x7e]*[\\x21-\\x7e])?))?");

    /** Unpadded base64url, or null unless {@code text} is the one canonical spelling of its bytes. */
    static byte[] b64url(String text) {
        if (!B64URL.matcher(text).matches() || text.length() % 4 == 1) {
            return null;
        }
        byte[] data = Key.URL_DECODER.decode(text);
        return Key.URL.encodeToString(data).equals(text) ? data : null;
    }

    /** base58btc, or null. Leading "1"s are zero bytes, so every string has exactly one meaning. */
    static byte[] b58(String text) {
        if (text.isEmpty()) {
            return null;
        }
        BigInteger number = BigInteger.ZERO;
        int zeros = 0;
        boolean leading = true;
        for (int i = 0; i < text.length(); i++) {
            int digit = B58.indexOf(text.charAt(i));
            if (digit < 0) {
                return null;
            }
            if (leading && digit == 0) {
                zeros++;
            } else {
                leading = false;
            }
            number = number.multiply(FIFTY_EIGHT).add(BigInteger.valueOf(digit));
        }
        byte[] magnitude = number.signum() == 0 ? new byte[0] : unsigned(number.toByteArray());
        byte[] out = new byte[zeros + magnitude.length];
        System.arraycopy(magnitude, 0, out, zeros, magnitude.length);
        return out;
    }

    /** A positive BigInteger's two's-complement bytes without the sign byte it may carry. */
    private static byte[] unsigned(byte[] signed) {
        return signed[0] == 0 ? Arrays.copyOfRange(signed, 1, signed.length) : signed;
    }

    /**
     * The raw key under a did:key multibase value, which is base58btc ("z") only.
     *
     * <p>The did:key ABNF also admits base64url ("u"), but the spec's resolution algorithm requires
     * the value to "begin with the letter z" or raise invalidDid, and the peer DID ABNF has
     * transform = "z". Reading "u" too would give every key two DIDs.
     */
    private static byte[] multibaseEd25519(String value) {
        if (value.length() > MAX_MULTIBASE || !value.startsWith("z")) {
            return null;
        }
        byte[] decoded = b58(value.substring(1));
        if (decoded == null || decoded.length != ED25519_PUB.length + Key.RAW_LEN) {
            return null;
        }
        return decoded[0] == ED25519_PUB[0] && decoded[1] == ED25519_PUB[1]
            ? Arrays.copyOfRange(decoded, 2, decoded.length)
            : null;
    }

    /**
     * The 32 bytes under a 44-character B, D or E AID, or null unless it is spelled canonically.
     *
     * <p>An AID is base64url over a zero pad byte and the bytes, with the pad's character replaced
     * by the code; only the spelling toAid produces, code aside, is an AID (bakobo/fiki#4). Every
     * caller has already read the first character as B, D or E.
     */
    private static byte[] aidBody(String text) {
        if (text.length() != Key.QB64_LEN) {
            return null;
        }
        byte[] decoded = b64url("A" + text.substring(1));
        if (decoded == null) {
            return null;
        }
        byte[] raw = Arrays.copyOfRange(decoded, 1, decoded.length);
        return Key.toAid(raw).substring(1).equals(text.substring(1)) ? raw : null;
    }

    /** The raw key {@code text} spells, by its shape, or null for a shape fiki does not read. */
    private static byte[] rawOf(String text) {
        if (text.length() == Key.QB64_LEN && text.charAt(0) == Key.CODE) {
            return aidBody(text);
        }
        if (text.length() == RAW_B64URL_LEN) {
            return b64url(text);
        }
        if (text.startsWith("did:key:")) {
            return multibaseEd25519(text.substring("did:key:".length()));
        }
        if (text.startsWith("did:peer:0")) {
            return multibaseEd25519(text.substring("did:peer:0".length()));
        }
        Matcher line = SSH_LINE.matcher(text);
        if (line.matches()) {
            byte[] blob = OpenSsh.b64std(line.group(1));
            return blob == null ? null : OpenSsh.sshPublicBlob(blob);
        }
        return null;
    }

    /** See {@link Key#aidFrom}. */
    static String aidFrom(String text) {
        if (text == null) {
            // A caller's mistake, reported in Java's idiom so that catching fiki's refusals cannot
            // swallow it (docs/user-guide.md, "Handling errors").
            throw new IllegalArgumentException("A public key is text (a String), not null.");
        }
        // Counted in code points, as every other port counts characters, and only when the UTF-16
        // length could be over: a code point is never more than two chars.
        if (text.length() > MAX_PUBLIC_CHARS) {
            int length = text.codePointCount(0, text.length());
            if (length > MAX_PUBLIC_CHARS) {
                throw refused("A public key is at most " + MAX_PUBLIC_CHARS
                    + " characters in any spelling fiki reads; this one is " + length + ".");
            }
        }
        // Shape before meaning: only a canonically spelled D or E AID is told what it is.
        if (!text.isEmpty() && "DE".indexOf(text.charAt(0)) >= 0 && aidBody(text) != null) {
            throw refused("The text is a transferable or digest AID, whose current key is not recoverable "
                + "from the identifier; resolve it to a key first.");
        }
        byte[] raw = rawOf(text);
        if (raw == null) {
            throw refused("The text, " + text.codePointCount(0, text.length()) + " characters, is not an "
                + "Ed25519 public key in any spelling fiki reads: an AID, raw base64url, a base58btc "
                + "did:key, a did:peer:0, or an ssh-ed25519 line.");
        }
        Key.trusted(raw, "");
        return Key.toAid(raw);
    }

    // The detail is empty and the message never quotes the input: what a caller hands aidFrom by
    // mistake can be a private key.
    private static FikiException refused(String message) {
        return new FikiException(FikiException.Kind.MalformedKey, message, "");
    }
}
