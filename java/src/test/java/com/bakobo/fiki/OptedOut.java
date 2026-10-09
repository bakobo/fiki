package com.bakobo.fiki;

/**
 * Request-verify options that state fiki 0.8's policy explicitly: no minimum and no authority check.
 *
 * <p>Format 3 made both a stated decision, with the default minimum applied when none is stated and
 * authorities required (this.i @524c8qgv). The tests that use these have their subjects elsewhere
 * — a digest, a key, a clock — and were written against the 0.8 defaults, so they state that policy
 * rather than inherit the new one and start testing something else. A later
 * {@code withMinimum} or {@code withAuthorities} still replaces either.
 */
final class OptedOut {

    private OptedOut() {}

    static Fiki.VerifyOptions decliningFreshness() {
        return Fiki.VerifyOptions.decliningFreshness().withoutMinimum().withoutAuthorityCheck();
    }

    static Fiki.VerifyOptions maxAge(long seconds) {
        return Fiki.VerifyOptions.maxAge(seconds).withoutMinimum().withoutAuthorityCheck();
    }
}
