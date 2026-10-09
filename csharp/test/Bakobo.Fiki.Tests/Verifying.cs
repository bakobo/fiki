namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// Verify options under fiki 0.8's policy, now stated rather than defaulted: no minimum covered
    /// set, no served-authority check, and no expected keyid. Format 3 makes the first default to
    /// <see cref="HttpSignatures.DefaultMinimum"/> for a request and
    /// <see cref="HttpSignatures.ResponseMinimum"/> for a response, and the other two required
    /// decisions (this.i @524c8qgv), and a test whose subject is something else states the policy it
    /// relies on here, as fiki-py's tests pass <c>minimum=None, authorities=None</c> and
    /// <c>expected_keyid=None</c>. A test may still add a minimum, authorities or an expected keyid
    /// of its own, which replace these.
    /// </summary>
    internal static class Verifying
    {
        internal static VerifyOptions MaxAge(long seconds) =>
            VerifyOptions.MaxAge(seconds).WithoutMinimum().DecliningAuthorityCheck().DecliningKeyidCheck();

        internal static VerifyOptions DecliningFreshness() =>
            VerifyOptions.DecliningFreshness().WithoutMinimum().DecliningAuthorityCheck().DecliningKeyidCheck();
    }
}
