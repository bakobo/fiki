package com.bakobo.fiki;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Unencrypted OpenSSH Ed25519 private keys, for {@link Key#fromOpenssh} (this.i @0mvgkwnl).
 *
 * <p>The seed it returns derives its own public key, and a seed always derives a point of prime
 * order, so the small-order refusal of @37wdchu5 cannot fire here once the stored public key is
 * checked against the derived one.
 */
final class OpenSsh {

    private OpenSsh() {}

    // Checked before anything is decoded (input-handling standard: size, then shape, then meaning).
    static final int MAX_PRIVATE_CHARS = 4096;

    private static final byte[] SSH_TYPE = "ssh-ed25519".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] NONE = "none".getBytes(StandardCharsets.US_ASCII);
    private static final Pattern B64STD = Pattern.compile("[A-Za-z0-9+/]*={0,2}");
    private static final String BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private static final String END = "-----END OPENSSH PRIVATE KEY-----";
    private static final byte[] MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);

    /** Padded standard base64, or null unless {@code text} is the one canonical spelling. */
    static byte[] b64std(String text) {
        if (!B64STD.matcher(text).matches() || text.length() % 4 != 0) {
            return null;
        }
        byte[] data = Key.STD_DECODER.decode(text);
        return Key.STD.encodeToString(data).equals(text) ? data : null;
    }

    /** RFC 4251 section 5 wire fields, refusing any length that overruns what is there. */
    private static final class Reader {
        private final byte[] data;
        private int pos;

        Reader(byte[] data, int pos) {
            this.data = data;
            this.pos = pos;
        }

        /** The next uint32, or -1 when fewer than four bytes are left. */
        long uint32() {
            if (data.length - pos < 4) {
                return -1;
            }
            long value = 0;
            for (int i = 0; i < 4; i++) {
                value = (value << 8) | (data[pos++] & 0xff);
            }
            return value;
        }

        byte[] string() {
            long length = uint32();
            if (length < 0 || length > data.length - pos) {
                return null;
            }
            byte[] value = Arrays.copyOfRange(data, pos, pos + (int) length);
            pos += (int) length;
            return value;
        }

        byte[] rest() {
            return Arrays.copyOfRange(data, pos, data.length);
        }
    }

    /** The 32 raw bytes of an ssh-ed25519 public blob with nothing after them, or null. */
    static byte[] sshPublicBlob(byte[] blob) {
        Reader reader = new Reader(blob, 0);
        if (!Arrays.equals(reader.string(), SSH_TYPE)) {
            return null;
        }
        byte[] raw = reader.string();
        return raw != null && raw.length == Key.RAW_LEN && reader.rest().length == 0 ? raw : null;
    }

    // The detail is empty and the reason never quotes the input: a private key must not reach a log.
    private static FikiException refused(String reason) {
        return new FikiException(
            FikiException.Kind.MalformedKey, "The OpenSSH private key was refused: " + reason, "");
    }

    /** See {@link Key#fromOpenssh}. */
    static Key read(String text) {
        if (text == null) {
            // A caller's mistake, reported in Java's idiom so that catching fiki's refusals cannot
            // swallow it (docs/user-guide.md, "Handling errors").
            throw new IllegalArgumentException("An OpenSSH private key is text (a String), not null.");
        }
        if (text.length() > MAX_PRIVATE_CHARS && text.codePointCount(0, text.length()) > MAX_PRIVATE_CHARS) {
            throw refused("it is over " + MAX_PRIVATE_CHARS + " characters.");
        }
        String trimmed = text.endsWith("\n") ? text.substring(0, text.length() - 1) : text;
        // -1 keeps trailing empty strings, as Python's split does.
        String[] lines = trimmed.split("\n", -1);
        if (lines.length < 3 || !lines[0].equals(BEGIN) || !lines[lines.length - 1].equals(END)) {
            throw refused("it is not one \"" + BEGIN + "\" block with LF line endings and nothing around it.");
        }
        StringBuilder joined = new StringBuilder();
        for (int i = 1; i < lines.length - 1; i++) {
            if (lines[i].isEmpty() || !B64STD.matcher(lines[i]).matches()) {
                throw refused("its body is not lines of standard base64.");
            }
            joined.append(lines[i]);
        }
        byte[] blob = b64std(joined.toString());
        if (blob == null) {
            throw refused("its body is not canonical standard base64.");
        }
        if (blob.length < MAGIC.length || !Arrays.equals(Arrays.copyOf(blob, MAGIC.length), MAGIC)) {
            throw refused("it is not in the openssh-key-v1 format.");
        }
        Reader reader = new Reader(blob, MAGIC.length);
        byte[] cipher = reader.string();
        byte[] kdf = reader.string();
        byte[] kdfoptions = reader.string();
        if (cipher != null && !Arrays.equals(cipher, NONE)) {
            throw refused("it is encrypted under a passphrase, and fiki reads only unencrypted keys. Keep a "
                + "dedicated key for fiki rather than removing the passphrase from one used elsewhere.");
        }
        if (cipher == null || !Arrays.equals(kdf, NONE) || kdfoptions == null || kdfoptions.length != 0
                || reader.uint32() != 1) {
            throw refused("its header is not that of exactly one unencrypted key.");
        }
        byte[] publicBlob = reader.string();
        byte[] raw = publicBlob == null ? null : sshPublicBlob(publicBlob);
        byte[] privateSection = reader.string();
        if (raw == null || privateSection == null || reader.rest().length != 0) {
            throw refused("it is not exactly one ssh-ed25519 key with nothing after it.");
        }
        return privateSection(privateSection, raw);
    }

    /** The key from the private section, after every consistency check it carries. */
    private static Key privateSection(byte[] section, byte[] raw) {
        Reader reader = new Reader(section, 0);
        long check = reader.uint32();
        if (section.length % 8 != 0 || check < 0 || check != reader.uint32()) {
            throw refused("its private section is misaligned or its check integers differ.");
        }
        byte[] type = reader.string();
        byte[] inner = reader.string();
        byte[] secret = reader.string();
        byte[] comment = reader.string();
        if (!Arrays.equals(type, SSH_TYPE) || !Arrays.equals(inner, raw) || secret == null
                || secret.length != 2 * Key.RAW_LEN) {
            throw refused("its private section does not hold the key its public section names.");
        }
        Key key = Key.fromSeed(Arrays.copyOf(secret, Key.RAW_LEN));
        if (!Arrays.equals(Arrays.copyOfRange(secret, Key.RAW_LEN, secret.length), raw)
                || !Arrays.equals(key.publicRaw(), raw)) {
            throw refused("its seed does not derive the public key it is stored with.");
        }
        byte[] padding = reader.rest();
        if (comment == null || !printable(comment)) {
            throw refused("its comment is not printable ASCII.");
        }
        if (padding.length >= 8 || !ascending(padding)) {
            throw refused("its padding is not 1, 2, 3, ... to the next eight-byte boundary.");
        }
        return key;
    }

    private static boolean printable(byte[] bytes) {
        for (byte b : bytes) {
            if (b < 0x20 || b > 0x7e) {
                return false;
            }
        }
        return true;
    }

    private static boolean ascending(byte[] padding) {
        for (int i = 0; i < padding.length; i++) {
            if (padding[i] != i + 1) {
                return false;
            }
        }
        return true;
    }
}
