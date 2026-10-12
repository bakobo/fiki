package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * What the key vectors cannot reach in this port's readers (this.i @0mvgkwnl): base58 and base64
 * edges, a length bound counted in code points where a Java string counts UTF-16 units, and the
 * openssh-key-v1 fields that each run out early, built here field by field.
 */
class KeyFormatsTest {

    private static final Key KEY = Key.fromSeed(new byte[32]);

    private static String refused(Runnable body) {
        FikiException e = assertThrows(FikiException.class, body::run);
        assertEquals(FikiException.Kind.MalformedKey, e.kind(), e.getMessage());
        assertEquals("", e.detail());
        return e.getMessage();
    }

    @Test
    void base58ReadsLeadingOnesAsZeroBytesAndNothingElse() {
        assertNull(Formats.b58(""));
        assertNull(Formats.b58("0"));
        assertArrayEquals(new byte[] {0}, Formats.b58("1"));
        assertArrayEquals(new byte[] {0, 0, 1}, Formats.b58("112"));
        assertArrayEquals(new byte[] {57}, Formats.b58("z"));
        // 58 * 3 = 174 = 0xae: a top bit set, so BigInteger's sign byte must be dropped.
        assertArrayEquals(new byte[] {(byte) 0xae}, Formats.b58("41"));
    }

    @Test
    void base64urlRefusesALengthNoBytesHave() {
        assertNull(Formats.b64url("AAAAA"));
        assertArrayEquals(new byte[3], Formats.b64url("AAAA"));
    }

    @Test
    void aShortTextStartingWithDIsNotCalledAnAid() {
        String message = refused(() -> Key.aidFrom("D"));
        assertTrue(message.startsWith("The text, 1 characters, is not an Ed25519 public key"), message);
    }

    @Test
    void thePublicBoundCountsCodePointsNotChars() {
        // 600 astral characters are 1200 chars and 600 code points: under the bound, so refused by
        // shape, as every other port counts them.
        String astral = "😀".repeat(600);
        String message = refused(() -> Key.aidFrom(astral));
        assertTrue(message.startsWith("The text, 600 characters, is not"), message);
        message = refused(() -> Key.aidFrom("😀".repeat(1025)));
        assertTrue(message.endsWith("this one is 1025."), message);
    }

    @Test
    void thePrivateBoundCountsCodePointsNotChars() {
        String message = refused(() -> Key.fromOpenssh("😀".repeat(3000)));
        assertTrue(message.contains("is not one \"-----BEGIN OPENSSH PRIVATE KEY-----\" block"), message);
        message = refused(() -> Key.fromOpenssh("😀".repeat(4097)));
        assertTrue(message.contains("it is over 4096 characters"), message);
    }

    /* ------------------------------------------------- openssh-key-v1, one field at a time */

    private static final byte[] MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);

    private static final class Wire {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Wire raw(byte[] bytes) {
            out.writeBytes(bytes);
            return this;
        }

        Wire uint32(int value) {
            return raw(new byte[] {(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value});
        }

        Wire string(byte[] bytes) {
            return uint32(bytes.length).raw(bytes);
        }

        Wire string(String text) {
            return string(text.getBytes(StandardCharsets.US_ASCII));
        }

        /** Padding 1, 2, 3, ... to the next eight-byte boundary. */
        Wire padded() {
            for (int i = 1; out.size() % 8 != 0; i++) {
                out.write(i);
            }
            return this;
        }

        byte[] bytes() {
            return out.toByteArray();
        }
    }

    private static byte[] publicBlob() {
        return new Wire().string("ssh-ed25519").string(KEY.publicRaw()).bytes();
    }

    private static Wire header() {
        return new Wire().raw(MAGIC).string("none").string("none").string("").uint32(1).string(publicBlob());
    }

    private static String armored(byte[] blob) {
        String body = Base64.getEncoder().encodeToString(blob);
        StringBuilder text = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (int i = 0; i < body.length(); i += 70) {
            text.append(body, i, Math.min(body.length(), i + 70)).append('\n');
        }
        return text.append("-----END OPENSSH PRIVATE KEY-----\n").toString();
    }

    private static byte[] secret(int length) {
        byte[] out = Arrays.copyOf(KEY.seed(), 64);
        System.arraycopy(KEY.publicRaw(), 0, out, 32, 32);
        return Arrays.copyOf(out, length);
    }

    private static String withPrivate(Wire section) {
        return armored(header().string(section.padded().bytes()).bytes());
    }

    private static Wire checks() {
        return new Wire().uint32(7).uint32(7).string("ssh-ed25519").string(KEY.publicRaw());
    }

    @Test
    void theBuilderMakesAKeyThatLoads() {
        assertEquals(KEY.aid(), Key.fromOpenssh(withPrivate(checks().string(secret(64)).string("c"))).aid());
    }

    @Test
    void aBlobShorterThanTheMagicIsNotOpensshKeyV1() {
        String message = refused(() -> Key.fromOpenssh(armored(new byte[3])));
        assertTrue(message.contains("not in the openssh-key-v1 format"), message);
    }

    @Test
    void aHeaderThatEndsEarlyIsNotOneUnencryptedKey() {
        String fragment = "its header is not that of exactly one unencrypted key";
        String message = refused(() -> Key.fromOpenssh(armored(MAGIC)));
        assertTrue(message.contains(fragment), message);
        message = refused(() -> Key.fromOpenssh(armored(new Wire().raw(MAGIC).string("none").string("none").bytes())));
        assertTrue(message.contains(fragment), message);
    }

    @Test
    void aFileThatEndsAfterThePublicKeyHoldsNoKey() {
        String message = refused(() -> Key.fromOpenssh(armored(header().bytes())));
        assertTrue(message.contains("not exactly one ssh-ed25519 key"), message);
    }

    @Test
    void aPrivateSectionWithoutAWholeSecretDoesNotHoldTheKey() {
        String fragment = "does not hold the key its public section names";
        String message = refused(() -> Key.fromOpenssh(withPrivate(checks())));
        assertTrue(message.contains(fragment), message);
        message = refused(() -> Key.fromOpenssh(withPrivate(checks().string(secret(63)).string("c"))));
        assertTrue(message.contains(fragment), message);
    }

    @Test
    void aPrivateSectionOfAnotherTypeDoesNotHoldTheKey() {
        // The public section is ssh-ed25519, so only the private section's own type is wrong.
        Wire section = new Wire().uint32(7).uint32(7).string("ssh-ed25518").string(KEY.publicRaw())
            .string(secret(64)).string("c");
        String message = refused(() -> Key.fromOpenssh(withPrivate(section)));
        assertTrue(message.contains("does not hold the key its public section names"), message);
    }

    @Test
    void aPrivateSectionWithoutACommentIsRefused() {
        String message = refused(() -> Key.fromOpenssh(withPrivate(checks().string(secret(64)))));
        assertTrue(message.contains("its comment is not printable ASCII"), message);
    }
}
