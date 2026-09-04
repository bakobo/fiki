//! Compiles and runs the samples in docs/user-guide.md, so a reader's copy-paste works.

use std::collections::BTreeMap;

use fiki::{sign_request, verify_request, Key, SignOptions, VerifyOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed: Vec<u8> = (0u8..32).collect();
    let key = Key::from_seed(&seed)?;
    println!("{}", key.aid());

    let url = "https://api.example.com/things?limit=1";
    let body = br#"{"hello": "world"}"#;
    let headers = sign_request(
        &key,
        "POST",
        url,
        &BTreeMap::new(),
        &SignOptions {
            body: Some(body.to_vec()),
            ..Default::default()
        },
    )?;

    let verdict = verify_request(
        "POST",
        url,
        &headers,
        &VerifyOptions {
            max_age: Some(300),
            body: Some(body.to_vec()),
            ..Default::default()
        },
    )?;
    assert_eq!(verdict.aid, key.aid());
    println!("rust guide samples: OK");
    Ok(())
}
