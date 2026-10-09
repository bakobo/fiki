namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// Verify options under fiki 0.8's request policy, now stated rather than defaulted: no minimum
    /// covered set and no served-authority check. Format 3 makes the first default to
    /// <see cref="HttpSignatures.DefaultMinimum"/> and the second a required decision (this.i
    /// @524c8qgv), and a test whose subject is something else states the policy it relies on here,
    /// as fiki-py's tests pass <c>minimum=None, authorities=None</c>. A test may still add a
    /// minimum or authorities of its own, which replace these.
    /// </summary>
    internal static class Verifying
    {
        internal static VerifyOptions MaxAge(long seconds) =>
            VerifyOptions.MaxAge(seconds).WithoutMinimum().DecliningAuthorityCheck();

        internal static VerifyOptions DecliningFreshness() =>
            VerifyOptions.DecliningFreshness().WithoutMinimum().DecliningAuthorityCheck();
    }
}
