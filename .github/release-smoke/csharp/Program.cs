// Release smoke test for Bakobo.Fiki, run against the package restored from nuget.org, never the
// source. The same four checks as every port's smoke test (docs/releasing.md): a plain vector, a
// plain round trip, a KERI vector through a resolver, and a KERI round trip under a caller-chosen
// AID keyid. Usage: dotnet run -p:FikiVersion=X.Y.Z -- <vectors-dir>
using System.Text;
using System.Text.Json;
using Bakobo.Fiki;

var vectors = args[0];

JsonElement Load(params string[] parts) =>
    JsonDocument.Parse(File.ReadAllText(Path.Combine(new[] { vectors }.Concat(parts).ToArray()))).RootElement;

JsonElement Find(JsonElement file, string id) =>
    file.GetProperty("cases").EnumerateArray().Single(c => c.GetProperty("id").GetString() == id);

Dictionary<string, string> Headers(JsonElement node) =>
    node.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);

byte[] B64Url(string text) =>
    Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/').PadRight((text.Length + 3) / 4 * 4, '='));

void Check(string name, string? got, string want)
{
    if (got != want)
    {
        Console.Error.WriteLine($"FAIL {name}: got {got}, want {want}");
        Environment.Exit(1);
    }
    Console.WriteLine($"ok   {name}");
}

var plain = Find(Load("accepts.json"), "default-covered-get");
var verdict = HttpSignatures.VerifyRequest(plain.GetProperty("method").GetString()!, plain.GetProperty("url").GetString()!,
    Headers(plain.GetProperty("headers")), VerifyOptions.DecliningFreshness().WithNow(plain.GetProperty("now").GetInt64()).DecliningAuthorityCheck());
Check("plain vector", verdict.Aid, plain.GetProperty("aid").GetString()!);

var key = Key.FromSeed(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray());
var url = "https://api.example.com/things?limit=1";
var body = Encoding.UTF8.GetBytes("{\"hello\": \"world\"}");
var signed = HttpSignatures.SignRequest(key, "POST", url, body: body);
verdict = HttpSignatures.VerifyRequest("POST", url, signed, VerifyOptions.MaxAge(300).WithBody(body).WithExpectedAid(key.Aid)
    .WithAuthorities(new[] { "api.example.com" }));
Check("plain round trip", verdict.Aid, key.Aid);

var keri = Load("keri", "requests.json");
var table = keri.GetProperty("keys").EnumerateArray().ToDictionary(k => k.GetProperty("keyid").GetString()!);
Func<string, byte[]?> resolve = keyid =>
    table.TryGetValue(keyid, out var entry) && entry.GetProperty("effective_key").ValueKind == JsonValueKind.String
        ? B64Url(entry.GetProperty("effective_key").GetString()!)
        : null;
var kase = Find(keri, "get-with-query");
var request = kase.GetProperty("request");
var policy = keri.GetProperty("policy");
verdict = HttpSignatures.VerifyRequest(request.GetProperty("method").GetString()!, request.GetProperty("url").GetString()!,
    Headers(request.GetProperty("headers")),
    VerifyOptions.MaxAge(policy.GetProperty("max_age").GetInt64())
        .WithSkew(policy.GetProperty("skew").GetInt64())
        .WithNow(kase.GetProperty("now").GetInt64())
        .WithResolver(resolve)
        .WithMinimum(HttpSignatures.RequestMinimum)
        .DecliningAuthorityCheck());
var keyid = kase.GetProperty("expected").GetProperty("keyid").GetString()!;
Check("KERI vector", verdict.Aid, keyid);

var signer = Key.FromSeed(Convert.FromHexString(table[keyid].GetProperty("seed_hex").GetString()!));
url = "https://keria.example.com/identifiers?type=rot";
signed = HttpSignatures.SignRequest(signer, "GET", url, keyId: keyid, minimum: HttpSignatures.RequestMinimum);
verdict = HttpSignatures.VerifyRequest("GET", url, signed,
    VerifyOptions.MaxAge(300).WithResolver(resolve).WithMinimum(HttpSignatures.RequestMinimum).DecliningAuthorityCheck());
Check("KERI round trip", verdict.Aid, keyid);
