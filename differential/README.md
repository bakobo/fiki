# The cross-port differential

`docs/user-guide.md` and `this.i` @5zrf8gjk promise that every port of fiki gives the same answer to the same input. The shared vectors under `vectors/` pin about two hundred chosen answers. This directory asks the same question of 3,000 inputs nobody chose, and `.github/workflows/ci-differential.yml` fails whenever two ports answer one of them differently (tick 7xbw).

## What is here

- `generate.py` writes `cases.json`. It takes the requests in `vectors/accepts.json` and `vectors/refusals.json` and mutates the Signature-Input, Signature and Content-Digest fields, the URL, and the Host header. It is deterministic (seed 9421, stdlib only), and CI regenerates the file and fails if the result differs from the committed one.
- One runner per port: `run_py.py`, `run_js.mjs`, `go/`, `rust/`, `java/Runner.java` and `csharp/`. Each one reads `cases.json`, calls that port's `verify_request` with exactly the decisions the case states, and writes a JSON map from case id to outcome. Each runner builds against the port in this repository from outside the port's tree, and uses nothing the port's own tests do not already use.
- `compare.py` reads the six maps and exits non-zero if any case has more than one outcome, if any outcome is a crash, or if a map is missing or incomplete.

## Cases

Every case states every verifier decision in the vectors' format-3 spelling, so no runner picks a default.

- `max_age` is a number of seconds, or null to decline the check.
- `now` is always a number. A vector whose `now` is null means the real clock, and a case cannot depend on the day, so the generator pins it.
- `authorities` is a list of hosts, or null to decline the check.
- `minimum` is `"default"` for the port's own default, null for the explicit opt-out, or a list.
- `expected_aid` is an AID, or null.

Each decision is kept from the base vector or replaced by another stated one, independently: the window (`max_age` with `now`) and `authorities` in about 30% of cases each, `minimum` in 20%, and `expected_aid` in 5%.

## Outcomes

Every runner spells its outcome the same way:

- `ok:<aid>` when the request verifies.
- The error's kind as the shared vectors spell it, such as `SignatureMismatch`, when fiki refuses the request.
- `caller:<the first 40 characters of the message>` for a mistake in the call: Python's TypeError or ValueError, JavaScript's TypeError, Go's `ErrInvalidOptions`, Rust's `InvalidArgument`, Java's IllegalArgumentException, and C#'s ArgumentException, ArgumentNullException or ArgumentOutOfRangeException. Each runner matches those classes exactly, because each port raises exactly those, so a subclass such as Java's NumberFormatException is a bug rather than a refusal.
- `crash:<type>` for anything else, including a Go or Rust panic. A crash fails the run even when every port crashes alike.

`compare.py` compares a caller error by its class and not its wording, because the vectors deliberately leave each port to word its own (`py/tests/test_vectors.py`, `CALLER_MESSAGES`). Every other outcome is compared exactly. A port that calls an input a caller error where another refuses or accepts it still disagrees, and the full wording is printed when it does.

## When it is red

There is no allowlist. A disagreement is a broken promise, so the fix belongs in the port that is wrong, or in the vectors if the promise needs stating more precisely. Do not add an exception here. `compare.py` prints each disagreeing case once with every port's outcome; the case itself is in `cases.json` under the same id, and minimizing it to the smallest input that still disagrees usually names the rule two ports read differently. A case worth keeping becomes a vector in `vectors/generate.py`.

## Running it locally

Each runner takes `[cases.json] [out.json]` and defaults to `differential/cases.json` and `differential/out/<port>.json`. From the repository root:

```sh
python3 differential/generate.py                     # then: git diff --exit-code differential/cases.json
(cd py && uv run python ../differential/run_py.py)
node differential/run_js.mjs
(cd differential/go && go run .)
(cd differential/rust && cargo run --locked)
(cd differential/csharp && dotnet run -c Release)
python3 differential/compare.py
```

Java needs the port's classes and Jackson on the classpath. With Maven, as CI does it:

```sh
(cd java && mvn -B -q compile dependency:build-classpath -Dmdep.includeScope=test -Dmdep.outputFile=target/differential.classpath)
cd differential/java
cp="../../java/target/classes:$(cat ../../java/target/differential.classpath)"
javac --release 17 -encoding UTF-8 -d classes/runner -cp "$cp" Runner.java && java -cp "classes/runner:$cp" Runner
```

Without Maven, compile `java/src/main/java` with `javac --release 17 -d classes/main` and put the jackson-databind, jackson-core and jackson-annotations 2.18.2 jars on the classpath in place of the Maven-resolved one.

Each runner takes a few seconds for the 3,000 cases. In CI the jobs run in parallel and the whole workflow is bounded by the slowest toolchain setup.
