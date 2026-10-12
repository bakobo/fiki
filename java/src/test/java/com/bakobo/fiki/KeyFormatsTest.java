package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * What the key vectors cannot reach in this port's readers (this.i @0mvgkwnl): base58 and base64
 * edges, and a length bound counted in code points where a Java string counts UTF-16 units.
 */
class KeyFormatsTest {

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
}
