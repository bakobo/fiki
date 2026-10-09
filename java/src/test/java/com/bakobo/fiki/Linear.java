package com.bakobo.fiki;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.function.Consumer;
import java.util.function.IntFunction;

/**
 * Linear time, checked without a wall-clock limit (tick 7xbw).
 *
 * <p>The old tests asserted that a large input parsed within five seconds, which says nothing about
 * growth and fails on a loaded machine. This times the same total work two ways: the input at n
 * parsed four times, and the input at 4n parsed once. Linear work takes about as long either way;
 * quadratic work takes four times as long the second way. Each is timed in this thread's CPU time,
 * which a loaded runner's other processes do not add to, in alternating rounds of equal length, and
 * the fastest of each is kept, so a cache or allocation hiccup in one round does not count.
 */
final class Linear {

    private Linear() {}

    // Linear work gives a ratio of about 1; quadratic about 4.
    static final double LIMIT = 2.5;
    private static final int ROUNDS = 15;

    static <T> void assertLinear(String what, int n, IntFunction<T> input, Consumer<T> work) {
        T small = input.apply(n);
        T large = input.apply(4 * n);
        Runnable fourSmall = () -> {
            for (int i = 0; i < 4; i++) {
                work.accept(small);
            }
        };
        Runnable oneLarge = () -> work.accept(large);
        // Warm the JIT on both before anything is timed.
        for (int i = 0; i < 2; i++) {
            fourSmall.run();
            oneLarge.run();
        }
        long fastestSmall = Long.MAX_VALUE;
        long fastestLarge = Long.MAX_VALUE;
        for (int i = 0; i < ROUNDS; i++) {
            fastestSmall = Math.min(fastestSmall, time(fourSmall));
            fastestLarge = Math.min(fastestLarge, time(oneLarge));
            if (i >= 2 && fastestLarge < LIMIT * fastestSmall) {
                break;
            }
        }
        double ratio = (double) fastestLarge / Math.max(1, fastestSmall);
        assertTrue(ratio < LIMIT, what + ": " + fastestSmall / 1000 + " us for four parses at n=" + n + " and "
            + fastestLarge / 1000 + " us for one at 4n, a ratio of " + String.format("%.2f", ratio)
            + "; linear work gives about 1 and quadratic about 4");
    }

    // The CPU time of this thread alone, so time the scheduler gives other processes, and the
    // collector's own threads, never count against the parse.
    private static final ThreadMXBean THREADS = ManagementFactory.getThreadMXBean();

    private static long time(Runnable work) {
        long start = THREADS.getCurrentThreadCpuTime();
        work.run();
        return THREADS.getCurrentThreadCpuTime() - start;
    }
}
