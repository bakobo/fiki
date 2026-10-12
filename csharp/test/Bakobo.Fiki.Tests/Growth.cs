using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// How work grows with input, measured so that a slow or loaded runner cannot fail a test and a
    /// complexity regression still does (tick 7xbw). A wall-clock bound such as "under a second"
    /// failed on a loaded machine on 2026-10-09 while proving nothing about complexity; a ratio of
    /// two timings taken on the same machine moments apart cancels the machine's speed.
    /// </summary>
    internal static class Growth
    {
        /// <summary>The size factor between the two inputs.</summary>
        internal const int Factor = 4;

        /// <summary>
        /// Linear work grows by <see cref="Factor"/>, 4; quadratic by its square, 16. Measured
        /// here, fiki's linear paths grow by 4.2 to 7, the excess being caches and the garbage
        /// collector on the larger input; ten leaves room above that and stays well below 16.
        /// </summary>
        internal const double LinearCeiling = 10;

        /// <summary>
        /// Work that stops at a bound grows by nothing, 1; linear work by 4. 2.5 leaves room for
        /// noise and is still well short of linear.
        /// </summary>
        internal const double BoundedCeiling = 2.5;

        /// <summary>
        /// The ratio of the best time at <c>n * Factor</c> to the best time at <c>n</c>.
        /// <paramref name="prepare"/> builds the input for a size outside the clock and returns the
        /// work. The two sizes alternate, so a burst of load on the runner lands on both, and the
        /// best of several rounds is kept, since load only ever adds time. Each sample repeats the
        /// work <paramref name="repeat"/> times, so a fast operation still takes long enough to time.
        /// </summary>
        internal static double Ratio(Func<int, Action> prepare, int n, int rounds = 9, int repeat = 1)
        {
            var small = prepare(n);
            var large = prepare(n * Factor);
            small();
            large();
            var bestSmall = double.MaxValue;
            var bestLarge = double.MaxValue;
            for (var round = 0; round < rounds; round++)
            {
                bestSmall = Math.Min(bestSmall, Seconds(small, repeat));
                bestLarge = Math.Min(bestLarge, Seconds(large, repeat));
            }
            return bestLarge / bestSmall;
        }

        private static double Seconds(Action work, int repeat)
        {
            // The previous sample's garbage is collected off the clock, not charged to this one.
            GC.Collect();
            GC.WaitForPendingFinalizers();
            var start = ThreadSeconds();
            var clock = Stopwatch.StartNew();
            for (var i = 0; i < repeat; i++)
            {
                work();
            }
            var wall = clock.Elapsed.TotalSeconds;
            return start == null ? wall : ThreadSeconds()!.Value - start.Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TimeSpec
        {
            public long Seconds;
            public long Nanoseconds;
        }

        [DllImport("libc", EntryPoint = "clock_gettime")]
        private static extern int ClockGetTime(int clock, out TimeSpec time);

        private static bool _noThreadClock;

        /// <summary>
        /// This thread's CPU time where POSIX offers it (CLOCK_THREAD_CPUTIME_ID), which a busy
        /// machine cannot inflate by preempting the thread; null elsewhere, and the wall clock is
        /// used instead.
        /// </summary>
        private static double? ThreadSeconds()
        {
            if (_noThreadClock || RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return null;
            }
            try
            {
                var id = RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? 16 : 3;
                if (ClockGetTime(id, out var time) == 0)
                {
                    return time.Seconds + time.Nanoseconds / 1e9;
                }
            }
            catch (Exception ex) when (ex is DllNotFoundException || ex is EntryPointNotFoundException)
            {
            }
            _noThreadClock = true;
            return null;
        }
    }
}
