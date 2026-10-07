# Releasing fiki

Each of the six ports versions and releases on its own (`this.i` @4fhrre0m), so a release is always a release of one port. Pushing a tag of the form `<port>/vX.Y.Z` starts that port's release workflow, `.github/workflows/release-<port>.yml`, and nothing else.

| Port | Tag | Workflow | Registry | Package |
|---|---|---|---|---|
| Python | `py/vX.Y.Z` | `release-py.yml` | PyPI | `fiki` |
| JavaScript | `js/vX.Y.Z` | `release-js.yml` | npm | `@bakobo/fiki` |
| Rust | `rust/vX.Y.Z` | `release-rust.yml` | crates.io | `fiki` |
| Java | `java/vX.Y.Z` | `release-java.yml` | Maven Central | `com.bakobo:fiki` |
| C# | `csharp/vX.Y.Z` | `release-csharp.yml` | nuget.org | `Bakobo.Fiki` |
| Go | `go/vX.Y.Z` | `release-go.yml` | the Go module proxy | `github.com/bakobo/fiki/go` |

Five of the six publish with no long-lived credential: PyPI, npm, crates.io and nuget.org all accept a short-lived token that the registry mints in exchange for the workflow run's GitHub OIDC token, and Go needs no credential because the tag is the release. Maven Central is the exception, because as of 2026-10 it offers no trusted publishing; see its section below.

## Cutting a release of one port

1. Bump the version in the port's manifest in a pull request: `py/pyproject.toml` (and `py/uv.lock`, by running `uv lock` in `py/`), `js/package.json`, `rust/Cargo.toml` (and `rust/Cargo.lock`, by running `cargo update -p fiki` in `rust/`), `java/pom.xml`, or `csharp/src/Bakobo.Fiki/Bakobo.Fiki.csproj`. Go has no manifest version, since its version is its tag.
2. If the change alters what the vectors require, it is also a vectors-format bump (`this.i` @4fhrre0m), and the port's exported constant must move with the vector files.
3. Merge the pull request.
4. Tag the merge commit on `main` and push the tag:

   ```sh
   git switch main && git pull
   git tag py/v0.6.0
   git push origin py/v0.6.0
   ```

5. Approve the `release` environment's deployment when GitHub asks. Every workflow except Go's pauses for that approval before its publish job, and the approval is what lets that job mint an OIDC token or read a secret.
6. Watch the `verify` job. The release is done when it is green, not when the publish job is.

A version cannot be published twice on any of these registries. If a release fails after its publish job succeeded, fix forward with the next patch version rather than trying to replace what was published.

## What each workflow does

Every workflow has the same five stages, and every job other than the publish job runs with `contents: read` and nothing more.

1. `version` refuses to continue unless the tag has the form `<port>/vX.Y.Z`, the manifest declares exactly that version, and the tagged commit is on `main`. The environment's tag rule controls which refs may deploy; this check controls which commits, since anyone with push access can tag any commit.
2. `test` calls the port's own CI workflow, `ci-<port>.yml`, through `workflow_call`, so a release runs exactly the suite CI runs, shared `vectors/` and `vectors/keri/` included, and not a copy of it that drifts.
3. `build` produces the artifact once (`uv build`, `npm pack`, `cargo publish --dry-run`, `mvn -P release -Dgpg.skip verify`, `dotnet pack`) and, where the registry takes a file, uploads it for the publish job, so what was built and inspected is what ships.
4. `publish` runs in the GitHub environment `release`, and is the only job with `id-token: write`. It waits for a required reviewer to approve, then:
   - PyPI: `pypa/gh-action-pypi-publish` with trusted publishing and attestations.
   - npm: `npm publish <tarball> --provenance --access public` with npm 11.16.0, which authenticates through trusted publishing; npm requires 11.5.1 or later for this.
   - crates.io: `rust-lang/crates-io-auth-action` trades the OIDC token for a crates.io token that expires after 30 minutes and is revoked when the job ends, then `cargo publish`.
   - nuget.org: `NuGet/login` trades the OIDC token for an API key valid for one hour, then `dotnet nuget push`. Its `user` input is the nuget.org profile name, read from the environment variable `NUGET_USER`.
   - Maven Central: `mvn -P release deploy`, signing with the PGP key and authenticating with the Portal user token, both read from `release` environment secrets. This job asks for no OIDC token, since Central does not accept one.
   - Go: there is no publish job. The tag is already public, and the module proxy fetches it on first request.
5. `verify` waits, with a bounded retry, until the registry serves the new version, installs it into a clean environment (a fresh venv, an empty npm project, a fresh Cargo project, an empty local Maven repository, an empty NuGet package cache, a fresh Go module), and runs the port's smoke test against it. For npm it also runs `npm audit signatures`, which checks the registry signature and provenance attestation. For Go it then asks pkg.go.dev to index the version, which pkg.go.dev would otherwise discover on its own from index.golang.org within minutes (https://pkg.go.dev/about).

### The smoke tests

Each port has one, under `.github/release-smoke/<port>/`, kept outside the port's directory so no package build can sweep it into an artifact. All six make the same four checks against the installed package:

1. Plain, from a vector: `vectors/accepts.json` case `default-covered-get` verifies under its pinned clock and yields the AID the vector names.
2. Plain, round trip: a key from a fixed seed signs a POST with a body, and the result verifies with a freshness limit and the key's AID preregistered.
3. KERI, from a vector: `vectors/keri/requests.json` case `get-with-query`, signed under a transferable `E…` AID, verifies through a resolver built from the file's keys table, under the profile's request minimum.
4. KERI, round trip: the controller's key signs under that caller-chosen AID keyid with the profile's minimum, and the result verifies through the same resolver.

To run one locally against a locally built artifact, build the package, install it into a scratch environment the way the `verify` job does, and pass the repository's `vectors/` directory as the argument.

## One-time registry setup (Daniel)

Everything in this section is done once, in a browser or a terminal logged in as the account that owns the package. None of it creates a token that has to be stored or rotated, except for Maven Central.

### GitHub: the `release` environment

Source: https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments

1. In `bakobo/fiki`, go to Settings → Environments → New environment, enter `release`, and click Configure environment.
2. Select Required reviewers, add Daniel, and click Save protection rules. Leave Prevent self-review unselected, because the person pushing the tag is usually the person approving it, and with it selected nobody could approve.
3. In the Deployment branches and tags dropdown choose the option that restricts deployment to selected branches and tags, click Add deployment branch or tag rule, set Ref type to Tag, enter the pattern `*/v*`, and click Add rule. Add no branch rule: a release deploys only from a tag.
4. Under Environment variables, click Add Variable, name it `NUGET_USER`, and set its value to the nuget.org profile name (not the email address) of the account that owns the NuGet trusted publishing policy below.
5. For Maven Central only, add the four environment secrets described in its section below.

### PyPI: project `fiki`

Source: https://docs.pypi.org/trusted-publishers/adding-a-publisher/

1. Go to https://pypi.org/manage/projects/ and click Manage on `fiki`.
2. Select Publishing in the sidebar.
3. Under GitHub, fill in: Repository owner's name `bakobo`, Repository name `fiki`, GitHub Actions workflow filename `release-py.yml`, GitHub Actions environment `release`.
4. Click Add.

### npm: package `@bakobo/fiki`

Sources: https://docs.npmjs.com/trusted-publishers and https://docs.npmjs.com/cli/v11/commands/npm-trust

Either of these two ways works.

From a terminal, with npm 11.15.0 or later and two-factor authentication enabled on the npm account (both are requirements of `npm trust`):

```sh
npm trust github @bakobo/fiki --repo bakobo/fiki --file release-js.yml --env release --allow-publish
```

Or on npmjs.com: open the package's Settings, find Trusted Publisher, click GitHub Actions, and fill in Organization or user `bakobo`, Repository `fiki`, Workflow filename `release-js.yml`, Environment name `release`. The fields are case-sensitive and the filename takes no path.

Then, as npm's documentation recommends, go to the package's Settings → Publishing access and select "Require two-factor authentication and disallow tokens", so that no long-lived token can publish the package at all.

### crates.io: crate `fiki`

Source: https://crates.io/docs/trusted-publishing

Trusted publishing requires the crate to exist already, and the 0.0.1 placeholder satisfies that.

1. Go to https://crates.io/crates/fiki/settings and open Trusted Publishing.
2. Click Add and choose GitHub.
3. Fill in Repository owner `bakobo`, Repository name `fiki`, Workflow filename `release-rust.yml`, Environment `release`, and save.

### nuget.org: package `Bakobo.Fiki`

Source: https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing

1. Log in to nuget.org, click the username, and choose Trusted Publishing.
2. Add a policy. Choose as its owner the user or organization that owns `Bakobo.Fiki`, since a policy applies to the packages of its owner. Fill in Repository Owner `bakobo`, Repository `fiki`, Workflow File `release-csharp.yml` (the file name only), Environment `release`.
3. Put the owning account's profile name in the GitHub environment variable `NUGET_USER`, as described above.

A new policy can start out "temporarily active" for seven days, until a first successful publish lets nuget.org lock it to the repository's GitHub IDs. If seven days pass without a release, restart the window from the same page.

### Maven Central: `com.bakobo:fiki`

Sources: https://central.sonatype.org/register/namespace/, https://central.sonatype.org/publish/generate-portal-token/, https://central.sonatype.org/publish/requirements/gpg/, https://central.sonatype.org/publish/publish-portal-maven/

Maven Central is the one registry here that still needs long-lived credentials. As of 2026-10 the Central Publisher Portal has no OIDC trusted publishing: it authenticates a deployment with a user token, and it refuses any file that lacks a PGP signature. Sigstore signatures are now validated too, but Sonatype states that PGP signatures remain required. So this section is a decision for Daniel, not only a setup step: whether to accept these four secrets in the `release` environment, or to defer the Java release until Central offers trusted publishing.

1. Register the namespace. In the Central Publisher Portal, go to View Namespaces → Add Namespace and enter `com.bakobo`. Copy the verification key it shows, add it as a DNS TXT record on `bakobo.com`, and refresh until the namespace shows Verified. Add the record before asking for verification, since a cached NXDOMAIN delays it.
2. Generate a user token at https://central.sonatype.com/usertoken with Generate User Token, giving it a display name and an expiration. The token cannot be retrieved after the dialog closes, and when it expires a new one has to be generated and the two secrets below replaced.
3. Create a PGP key for signing releases (`gpg --gen-key`; it defaults to two years of validity), and publish its public half: `gpg --keyserver keyserver.ubuntu.com --send-keys <KEY-ID>`. Central also accepts keys.openpgp.org and pgp.mit.edu.
4. In the GitHub `release` environment, add four environment secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` from the user token, `GPG_PRIVATE_KEY` as the ASCII-armored private key (`gpg --armor --export-secret-keys <KEY-ID>`), and `GPG_PASSPHRASE`.

The release profile in `java/pom.xml` attaches the sources and javadoc jars Central requires, signs every file with the BouncyCastle signer (which reads `MAVEN_GPG_KEY` and `MAVEN_GPG_PASSPHRASE`, so no keyring is created on the runner), and publishes through `central-publishing-maven-plugin` with `autoPublish` and `waitUntil=published`.

### Go: nothing to register

Source: https://pkg.go.dev/about

The module proxy fetches `github.com/bakobo/fiki/go` from the public repository the first time anyone requests a version, and `release-go.yml` makes that request. The `release` environment is not involved, because nothing is published. To ask pkg.go.dev to index a version by hand, request https://proxy.golang.org/github.com/bakobo/fiki/go/@v/vX.Y.Z.info, or open https://pkg.go.dev/github.com/bakobo/fiki/go and click Request.
