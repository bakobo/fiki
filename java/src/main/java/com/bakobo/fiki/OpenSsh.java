package com.bakobo.fiki;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * The OpenSSH encodings in an ssh-ed25519 public line, for {@link Key#aidFrom} (this.i @0mvgkwnl).
 */
final class OpenSsh {

    private OpenSsh() {}

    private static final byte[] SSH_TYPE = "ssh-ed25519".getBytes(StandardCharsets.US_ASCII);
    private static final Pattern B64STD = Pattern.compile("[A-Za-z0-9+/]*={0,2}");

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
}
