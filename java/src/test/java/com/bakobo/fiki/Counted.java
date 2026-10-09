package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.function.ThrowingConsumer;

/** A vector file's cases as dynamic tests, holding the file to its pinned count (tick 7xbw, T8). */
final class Counted {

    private Counted() {}

    /**
     * One dynamic test per case, after checking that the file holds exactly {@code pinned} cases,
     * and a last test that checks every one of them ran. {@code pinned} is read from the file once,
     * when the driver is written, never at test time, so a vector file that loses cases fails here.
     */
    static Stream<DynamicTest> each(String file, JsonNode cases, int pinned, ThrowingConsumer<JsonNode> body) {
        assertEquals(pinned, cases.size(), file + " holds a different number of cases than this driver pins");
        AtomicInteger ran = new AtomicInteger();
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode c : cases) {
            tests.add(DynamicTest.dynamicTest(c.get("id").asText(), () -> {
                ran.incrementAndGet();
                body.accept(c);
            }));
        }
        tests.add(DynamicTest.dynamicTest("all " + pinned + " cases of " + file + " ran",
            () -> assertEquals(pinned, ran.get(), file + ": not every case ran")));
        return tests.stream();
    }
}
