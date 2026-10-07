# The C# test project uses xUnit v2 (2.9.3), which NuGet marks deprecated in favour of xunit.v3. The port's worker reported that xunit.v3 4.x needs Microsoft.Testing.Platform, which the .NET 10 SDK's default dotnet test and coverlet.msbuild do not drive; that claim is unverified. Test-scope only, so no consumer inherits it. Migrate to xunit.v3 with a runner coverlet supports (or coverlet.MTP), keeping the 100% branch gate, and confirm the net481 leg still runs.
kind: todo
created: 2026-10-07T18:48Z

