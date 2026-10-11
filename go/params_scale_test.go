package fiki

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// scalesLinearly fails unless doing work once over 4n inputs takes about as long as doing it four
// times over n, which is what linear work does; quadratic work takes four times as long. It
// compares the two rather than holding either to a wall-clock limit, so a slow or loaded runner
// slows both alike and cannot fail it (tick 7xbw: C#'s absolute-time test failed on a loaded
// machine on 2026-10-09). The two are timed over the same span of wall time, so the scheduler
// preempts both alike, and alternately, nine rounds each keeping its fastest, so a stall lands
// on both or on neither. The limit of 2.5 leaves linear work room for cache effects and noise, and
// still refuses quadratic work's 4.
func scalesLinearly(t *testing.T, n int, prepare func(n int) func()) {
	t.Helper()
	small, large := prepare(n), prepare(4*n)
	runs := [2]func(){func() { small(); small(); small(); small() }, large}
	fastest := [2]time.Duration{1<<63 - 1, 1<<63 - 1}
	for range 9 {
		for i, run := range runs {
			runtime.GC()
			started := time.Now()
			run()
			fastest[i] = min(fastest[i], time.Since(started))
		}
	}
	if ratio := float64(fastest[1]) / float64(max(fastest[0], time.Microsecond)); ratio > 2.5 {
		t.Errorf("work over %d inputs, done four times, took %v, and over %d inputs once took %v, "+
			"%.1f times as long; linear work takes about as long", n, fastest[0], 4*n, fastest[1], ratio)
	}
}

// Hostile review of 365f522 on bakobo/fiki#6, item 2: setParam rescanned every earlier
// parameter, so a long Signature-Input cost quadratic time before it was refused. Since 0.8.0 an
// item carries at most MaxParameters distinct ones (this.i @5zrf8gjk), so the run repeats them,
// which is the path that once rescanned.
func TestManyParametersParseInLinearTime(t *testing.T) {
	scalesLinearly(t, 80000, func(n int) func() {
		var b strings.Builder
		b.WriteString(`sig=("@method")`)
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, ";p%d=1", i%MaxParameters)
		}
		field := b.String()
		return func() {
			if _, _, err := parseDictionary(field); err != nil {
				t.Fatal(err)
			}
		}
	})
}
