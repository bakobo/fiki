package com.bakobo.fiki;

/**
 * Verify options that state fiki 0.8's policy explicitly: no minimum, no authority check, and no
 * expected keyid.
 *
 * <p>Format 3 made both a stated decision, with the default minimum applied when none is stated and
 * authorities required (this.i @524c8qgv), and part two made a response's minimum default to the
 * profile's and its expected keyid required. The tests that use these have their subjects elsewhere
 * — a digest, a key, a clock — and were written against the 0.8 defaults, so they state that policy
 * rather than inherit the new one and start testing something else. A later
 * {@code withMinimum}, {@code withAuthorities} or {@code withExpectedKeyid} still replaces each.
 */
final class OptedOut {

    private OptedOut() {}

    static Fiki.VerifyOptions decliningFreshness() {
        return Fiki.VerifyOptions.decliningFreshness().withoutMinimum().withoutAuthorityCheck().withoutKeyidCheck();
    }

    static Fiki.VerifyOptions maxAge(long seconds) {
        return Fiki.VerifyOptions.maxAge(seconds).withoutMinimum().withoutAuthorityCheck().withoutKeyidCheck();
    }
}
