// The C# port's answers to differential/cases.json, as a map from case id to outcome.
//
// `dotnet run -c Release -- [cases.json] [out.json]` from differential/csharp. The outcome spelling
// is shared by all six runners and described in differential/README.md.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Bakobo.Fiki;

// How much of a caller error's message an outcome carries; the same in every runner.
const int Prefix = 40;

var casesPath = args.Length > 0 ? args[0] : Path.Combine("..", "cases.json");
var outPath = args.Length > 1 ? args[1] : Path.Combine("..", "out", "csharp.json");
using var document = JsonDocument.Parse(File.ReadAllText(casesPath, Encoding.UTF8));
var stopwatch = Stopwatch.StartNew();
var outcomes = new SortedDictionary<string, string>(StringComparer.Ordinal);
var count = 0;
foreach (var c in document.RootElement.GetProperty("cases").EnumerateArray())
{
    outcomes[c.GetProperty("id").GetString()!] = Outcome(c);
    count++;
}
Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outPath))!);
File.WriteAllText(outPath, JsonSerializer.Serialize(outcomes) + "\n", new UTF8Encoding(false));
Console.WriteLine($"csharp: {count} cases in {stopwatch.Elapsed.TotalSeconds:F1}s");

// The case's stated policy in C#'s spelling: a null max_age is DecliningFreshness, null
// authorities DecliningAuthorityCheck, a null minimum WithoutMinimum, "default" no call at all.
static VerifyOptions Options(JsonElement c)
{
    var maxAge = c.GetProperty("max_age");
    var options = maxAge.ValueKind == JsonValueKind.Null ? VerifyOptions.DecliningFreshness() : VerifyOptions.MaxAge(maxAge.GetInt64());
    options = options.WithNow(c.GetProperty("now").GetInt64());
    var body = c.GetProperty("body");
    options = options.WithBody(body.ValueKind == JsonValueKind.Null ? null : Encoding.UTF8.GetBytes(body.GetString()!));
    var aid = c.GetProperty("expected_aid");
    if (aid.ValueKind != JsonValueKind.Null)
    {
        options = options.WithExpectedAid(aid.GetString()!);
    }
    var authorities = c.GetProperty("authorities");
    options = authorities.ValueKind == JsonValueKind.Null
        ? options.DecliningAuthorityCheck()
        : options.WithAuthorities(authorities.EnumerateArray().Select(x => x.GetString()!).ToList());
    var minimum = c.GetProperty("minimum");
    if (minimum.ValueKind == JsonValueKind.Null)
    {
        options = options.WithoutMinimum();
    }
    else if (minimum.ValueKind == JsonValueKind.Array)
    {
        options = options.WithMinimum(minimum.EnumerateArray().Select(x => x.GetString()!).ToList());
    }
    return options;
}

static string Outcome(JsonElement c)
{
    try
    {
        var headers = c.GetProperty("headers").EnumerateObject()
            .Select(p => new KeyValuePair<string, string>(p.Name, p.Value.GetString()!)).ToList();
        var verdict = HttpSignatures.VerifyRequest(c.GetProperty("method").GetString()!, c.GetProperty("url").GetString()!, headers, Options(c));
        return "ok:" + verdict.Aid;
    }
    catch (FikiException e)
    {
        return e.Kind.ToString();
    }
    catch (ArgumentException e) when (e.GetType() == typeof(ArgumentException) || e.GetType() == typeof(ArgumentNullException) || e.GetType() == typeof(ArgumentOutOfRangeException))
    {
        // A mistake in the call is an ArgumentException and never a FikiException (@5zrf8gjk).
        // fiki throws these three exactly, so another subclass, such as a DecoderFallbackException
        // from the runtime, is a bug.
        return "caller:" + Truncate(e.Message, Prefix);
    }
#pragma warning disable CA1031 // Recording any other exception is the point.
    catch (Exception e)
#pragma warning restore CA1031
    {
        return "crash:" + e.GetType().Name;
    }
}

// Cut to n code points, not UTF-16 units, as the other runners do.
static string Truncate(string s, int n)
{
    var text = new StringBuilder();
    var taken = 0;
    for (var i = 0; i < s.Length && taken < n; i++, taken++)
    {
        text.Append(s[i]);
        if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
        {
            text.Append(s[++i]);
        }
    }
    return text.ToString();
}
