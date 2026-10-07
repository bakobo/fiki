using System;
using System.IO;
using System.Text.Json;

namespace Bakobo.Fiki.Tests
{
    /// <summary>Where the repository's shared files are, found from the test assembly.</summary>
    internal static class Repo
    {
        /// <summary>
        /// The repository root: the nearest ancestor of the test assembly holding both
        /// <c>vectors/</c> and <c>this.i</c>. Never found by matching a directory NAME, which breaks
        /// in a worktree or a clone under another name (tick 32mh).
        /// </summary>
        internal static readonly string Root = FindRoot(AppContext.BaseDirectory);

        internal static string FindRoot(string start)
        {
            for (var dir = new DirectoryInfo(start); dir != null; dir = dir.Parent)
            {
                if (Directory.Exists(Path.Combine(dir.FullName, "vectors"))
                    && File.Exists(Path.Combine(dir.FullName, "this.i")))
                {
                    return dir.FullName;
                }
            }
            throw new DirectoryNotFoundException($"No ancestor of {start} holds both vectors/ and this.i.");
        }

        internal static string PathTo(params string[] parts) => Path.Combine(Root, Path.Combine(parts));

        internal static JsonElement Json(params string[] parts)
        {
            using var document = JsonDocument.Parse(File.ReadAllText(PathTo(parts)));
            return document.RootElement.Clone();
        }
    }
}
