# fiki (Rust)

[![Rust](https://github.com/bakobo/fiki/actions/workflows/ci-rust.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-rust.yml)

The Rust implementation of [fiki](../README.md). Requires Rust 1.75 or newer.

```sh
cd rust
cargo test
```

## Dependencies, and why this port has some

The Go and JavaScript ports have none. This one cannot: Rust's standard library has no cryptography at all, so Ed25519 and SHA-2 have to come from somewhere. It takes `ed25519-dalek`, `sha2`, and `rand_core`, and nothing else — the RFC 8941 subset is still hand-rolled in `src/sfv.rs`, and base64 is thirty lines in `src/keys.rs` rather than a fourth crate.

That asymmetry is recorded in `this.i` @2tt6fmc0 rather than left for a reader who expected fiki's zero-dependency claim to be universal.

## Signing a request

```rust
let key = Key::from_seed(&seed)?;   // or Key::generate()
println!("{}", key.aid());          // register this once with whoever you call

let headers = sign_request(&key, "POST",
    "https://api.example.com/things?limit=1", &BTreeMap::new(),
    &SignOptions { body: Some(body.to_vec()), ..Default::default() })?;
```

By default the signature binds the method, the host, the path, the query string, and a digest of the body. Pass the body wherever you pass the URL: fiki covers a body it is given, or refuses to sign — but it cannot cover one it never sees.

## Verifying a request

```rust
let verdict = verify_request(method, url, &headers, &VerifyOptions {
    max_age: Some(300),             // or None to decline the check
    body: Some(body.to_vec()),
    ..Default::default()
})?;
```

`max_age` is an `Option<i64>` the caller fills in one way or the other: seconds of tolerance, or an explicit `None`. Both defaults would be wrong — a number guesses at somebody else's clock skew and replay window, and skipping the check silently is the thing the field exists to prevent. An `expires` the signer declared is enforced either way.

## Two things measured rather than assumed

`Key`'s `Debug` prints the AID and nothing else, so a seed cannot reach a log line by way of a derived impl.

A public key is refused as `MalformedKey` before any signature is checked unless it is the canonical encoding of an on-curve point of large order — whether it arrives as an AID, a keyid, or from a resolver (`this.i` @2t8xctts, @34qlc8r3). That is measured rather than inherited from `ed25519-dalek` 2.x, whose `VerifyingKey::from_bytes` reduces a y at or above the field prime and so accepts a second spelling of some keys, and accepts small-order points under which a signature proves nothing about who made it; `tests/profile.rs` pins every class on every path.
