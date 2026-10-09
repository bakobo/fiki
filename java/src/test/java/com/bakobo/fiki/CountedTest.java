package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

/**
 * The drivers count what they run (tick 7xbw, T8): an emptied or shrunken cases array once passed
 * every driver, since a loop over nothing asserts nothing.
 */
class CountedTest {

    private static JsonNode cases(int count) throws Exception {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < count; i++) {
            json.append(i == 0 ? "" : ",").append("{\"id\":\"c").append(i).append("\"}");
        }
        return new ObjectMapper().readTree(json.append(']').toString());
    }

    @Test
    void aFileHoldingFewerCasesThanPinnedFails() throws Exception {
        assertThrows(AssertionFailedError.class, () -> Counted.each("f.json", cases(0), 3, c -> { }));
        assertThrows(AssertionFailedError.class, () -> Counted.each("f.json", cases(2), 3, c -> { }));
        assertThrows(AssertionFailedError.class, () -> Counted.each("f.json", cases(4), 3, c -> { }));
    }

    @Test
    void theLastTestChecksThatEveryCaseRan() throws Throwable {
        List<DynamicTest> tests = Counted.each("f.json", cases(3), 3, c -> { }).toList();
        assertEquals(4, tests.size());
        // Run only the last: no case ran, so it fails.
        assertThrows(AssertionFailedError.class, () -> tests.get(3).getExecutable().execute());
        for (DynamicTest test : tests) {
            test.getExecutable().execute();
        }
    }
}
