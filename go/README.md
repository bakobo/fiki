# fiki (Go)

[![Go](https://github.com/bakobo/fiki/actions/workflows/ci-go.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-go.yml)

The Go implementation of [fiki](../README.md). Requires Go 1.22 or newer, and has **no dependencies** — the standard library carries `crypto/ed25519` and `crypto/sha256`, and the RFC 8941 subset RFC 9421 needs is hand-rolled in `sfv.go` for the reason every port hand-rolls it.

```sh
cd go
go test ./...
```

## Signing a request

```go
key, _ := fiki.FromSeed(seed)     // or fiki.Generate()
fmt.Println(key.AID())            // register this once with whoever you call

body := []byte(`{"hello": "world"}`)
headers, err := fiki.SignRequest(key, "POST",
    "https://api.example.com/things?limit=1", nil,
    fiki.SignOptions{Body: body})
```

By default the signature binds the method, the host, the path, the query string, and a digest of the body. Pass the body wherever you pass the URL: fiki covers a body it is given, or refuses to sign — but it cannot cover one it never sees.

## Verifying a request

```go
maxAge := int64(300)
verdict, err := fiki.VerifyRequest(r.Method, r.URL.String(), headers,
    fiki.VerifyOptions{Body: body, MaxAge: &maxAge, Authorities: []string{"api.example.com"}})
```

`Authorities` is a decision you must state, as `MaxAge` is: the hosts this verifier serves, compared exactly with the `@authority` the request derives, or `AnyAuthority: true` to check none. Go cannot make a field mandatory at compile time, so stating neither, both, or an empty list is `ErrInvalidOptions` when `VerifyRequest` runs. With no `Minimum` given, `VerifyRequest` requires `DefaultMinimum` (`@method @authority @path @query`, plus `content-digest` when there is a body), which is what fiki signs by default; `NoMinimum: true` opts out explicitly.

`MaxAge` is a `*int64` rather than an `int64` because there is no default: a positive number of seconds of tolerance, or an explicit `nil` to decline the check. Zero or less, for `MaxAge` or `Skew`, is `ErrInvalidOptions`. Both defaults would be wrong — a number guesses at somebody else's clock skew and replay window, and skipping the check silently is the thing the field exists to prevent. An `expires` the signer declared is enforced either way.

Signature, Signature-Input and Content-Digest are bounded before they are parsed: at most `MaxFieldBytes` (8192) each, `MaxDictionaryMembers` (16) members, `MaxInnerListItems` (64) covered components and `MaxParameters` (16) parameters on an item. A header over any of them is refused as malformed.

## What its coverage gate does and does not say

The suite holds **100% statement coverage**, not 100% branch coverage. That is weaker than the gate the Python and JavaScript ports hold, and the difference is Go's, not a choice: `go test -cover` measures statements only, and there is no branch mode. Getting branch coverage would mean a third-party tool, which is a dependency this port does not have and would rather not acquire for a measurement. The shared vectors carry most of the weight either way — they are the same bytes all five implementations answer to.
