package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.function.Executable;

/**
 * A caller error that only fiki's own refusal satisfies (tick 7xbw, T3).
 *
 * <p>{@code assertThrows(IllegalArgumentException.class, ...)} alone passes on any
 * IllegalArgumentException, including one the JDK raises from a bug in fiki, such as a
 * NumberFormatException, which is a subclass. Each check therefore names a fragment of the message
 * fiki writes for that mistake.
 */
final class Caller {

    private Caller() {}

    static IllegalArgumentException refused(String fragment, Executable body) {
        return refused(fragment, body, "");
    }

    static IllegalArgumentException refused(String fragment, Executable body, String label) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, body, label);
        assertTrue(e.getMessage() != null && e.getMessage().contains(fragment),
            () -> label + " expected fiki's message containing \"" + fragment + "\", got: " + e.getMessage());
        return e;
    }

    /*
     * fiki's own wording for each way a target it is signing cannot be read, for the parameterized
     * tests whose inputs each fail one of them. Every phrase is fiki's, so a JDK exception matches
     * none.
     */
    private static final List<String> UNREADABLE_TARGET = List.of(
        "is not a number from 0 to 65535",
        "has no closing bracket",
        "has text after its IPv6 literal",
        "is not an IPv6 address or IPvFuture",
        "has a bracket outside an IP-literal",
        "is not a single host and optional port",
        "its host is not ASCII");

    static IllegalArgumentException unreadableTarget(Executable body) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, body);
        assertTrue(e.getMessage() != null && UNREADABLE_TARGET.stream().anyMatch(e.getMessage()::contains),
            () -> "expected fiki's refusal of an unreadable target, got: " + e.getMessage());
        return e;
    }
}
