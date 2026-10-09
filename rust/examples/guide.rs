//! Compiles and runs the samples in the user guide, so a reader's copy-paste works.
//!
//! Each sample sits between `// guide:` markers so the text a guide quotes is the text CI runs.

use std::collections::BTreeMap;
use std::sync::Arc;

use fiki::{
    sign_request, sign_response, verify_request, verify_response, Authorities, Error,
    ExpectedKeyid, Key, Kind, Minimum, Request, Resolver, SignOptions, VerifyOptions,
    REQUEST_MINIMUM, RESPONSE_MINIMUM,
};

type Outcome = Result<(), Box<dyn std::error::Error>>;

const URL: &str = "https://keria.example.com/identifiers";
const BODY: &[u8] = br#"{"name": "alice"}"#;
// The controller and agent of vectors/keri/: synthetic but well-formed E-code AIDs, signed by the
// keys from seeds 2..34 and 3..35.
const CONTROLLER: &str = "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx";
const AGENT: &str = "EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6";

fn seeded(first: u8) -> Key {
    Key::from_seed(&(first..first + 32).collect::<Vec<_>>()).unwrap()
}

fn current_key(key: &Key) -> [u8; 32] {
    *fiki::verifying_key(&key.aid()).unwrap().as_bytes()
}

fn main() -> Outcome {
    plain()?;
    let controller = seeded(2);
    let agent = seeded(3);
    // In a KERI stack these come from each AID's key event log. Here they are a table.
    let table = BTreeMap::from([
        (CONTROLLER.to_string(), current_key(&controller)),
        (AGENT.to_string(), current_key(&agent)),
    ]);
    let headers = keri_request(&controller)?;
    keri_verify(&headers, &table)?;
    let request = Request {
        method: "POST".into(),
        url: URL.into(),
        headers: headers.clone(),
        body: Some(BODY.to_vec()),
    };
    let response = keri_response(&agent, &request)?;
    keri_verify_response(&response, &request, &table)?;
    refusals(&controller, &headers, &table)?;
    println!("rust guide samples: OK");
    Ok(())
}

fn plain() -> Outcome {
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
            // Required, like max_age: the hosts this verifier serves, or Authorities::Unchecked.
            authorities: Authorities::served(["api.example.com"]),
            ..Default::default()
        },
    )?;
    assert_eq!(verdict.aid, key.aid());
    Ok(())
}

fn keri_request(controller: &Key) -> Result<BTreeMap<String, String>, Error> {
    let key = controller;
    // guide:begin sign-request-with-aid
    // The keyid is the signer's KERI AID rather than its key; only a verifier that can resolve the
    // AID to its current key can check the signature.
    let headers = sign_request(
        key,
        "POST",
        "https://keria.example.com/identifiers",
        &BTreeMap::new(),
        &SignOptions {
            body: Some(br#"{"name": "alice"}"#.to_vec()),
            keyid: Some("ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx".into()),
            // Refuse to sign anything a KERI-profile verifier would refuse.
            minimum: Some(REQUEST_MINIMUM.map(String::from).to_vec()),
            ..Default::default()
        },
    )?;
    // guide:end
    Ok(headers)
}

fn keri_verify(headers: &BTreeMap<String, String>, table: &BTreeMap<String, [u8; 32]>) -> Outcome {
    let key_state = table.clone();
    let body = BODY;
    // guide:begin verify-with-resolver
    // The resolver maps a keyid to the 32 raw bytes of its CURRENT key, from the verifier's own
    // key state. It is authoritative: fiki never decodes the keyid as a key instead. None means
    // "no key known", which fiki reports as Kind::UnknownKey.
    let resolve: Resolver = Arc::new(move |keyid: &str| Ok(key_state.get(keyid).copied()));

    let verdict = verify_request(
        "POST",
        "https://keria.example.com/identifiers",
        headers,
        &VerifyOptions {
            max_age: Some(300),
            body: Some(body.to_vec()),
            resolve: Some(resolve),
            minimum: Minimum::Of(REQUEST_MINIMUM.map(String::from).to_vec()),
            authorities: Authorities::served(["keria.example.com"]),
            ..Default::default()
        },
    )?;
    assert_eq!(verdict.aid, "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx");
    // guide:end
    Ok(())
}

fn keri_response(agent: &Key, request: &Request) -> Result<BTreeMap<String, String>, Error> {
    let request = request.clone();
    // guide:begin sign-response
    // `request` is the request being answered, with the body that arrived. By default the
    // response covers @status, its own body's digest, and the request's method, path, query and
    // digest, each marked `req` -- which binds the answer to the question.
    let response_headers = sign_response(
        agent,
        200,
        Some(&request),
        &BTreeMap::new(),
        &SignOptions {
            body: Some(br#"{"done": true}"#.to_vec()),
            keyid: Some("EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6".into()),
            minimum: Some(RESPONSE_MINIMUM.map(String::from).to_vec()),
            ..Default::default()
        },
    )?;
    // guide:end
    Ok(response_headers)
}

fn keri_verify_response(
    response_headers: &BTreeMap<String, String>,
    request: &Request,
    table: &BTreeMap<String, [u8; 32]>,
) -> Outcome {
    let key_state = table.clone();
    let resolve: Resolver = Arc::new(move |keyid: &str| Ok(key_state.get(keyid).copied()));
    // guide:begin verify-response
    // A client names the AID it is talking to, so a response signed by anyone else is refused.
    let verdict = verify_response(
        200,
        response_headers,
        Some(request),
        &VerifyOptions {
            max_age: Some(300),
            body: Some(br#"{"done": true}"#.to_vec()),
            resolve: Some(resolve),
            expected_keyid: ExpectedKeyid::is("EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6"),
            minimum: Minimum::Of(RESPONSE_MINIMUM.map(String::from).to_vec()),
            ..Default::default()
        },
    )?;
    assert_eq!(
        verdict.keyid.as_deref(),
        Some("EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6")
    );
    // guide:end
    Ok(())
}

fn refusals(
    controller: &Key,
    headers: &BTreeMap<String, String>,
    table: &BTreeMap<String, [u8; 32]>,
) -> Outcome {
    let key_state = table.clone();
    let opts = |resolve: Resolver| VerifyOptions {
        max_age: Some(300),
        body: Some(BODY.to_vec()),
        resolve: Some(resolve),
        minimum: Minimum::Of(REQUEST_MINIMUM.map(String::from).to_vec()),
        authorities: Authorities::served(["keria.example.com"]),
        ..Default::default()
    };
    let verify = |headers: &BTreeMap<String, String>, opts: &VerifyOptions| {
        verify_request("POST", URL, headers, opts)
    };
    let known: Resolver = Arc::new(move |keyid: &str| Ok(key_state.get(keyid).copied()));
    let nobody: Resolver = Arc::new(|_: &str| Ok(None));
    // guide:begin resolver-refuses
    // A resolver may refuse a keyid itself, in fiki's vocabulary: MalformedKey for one that is not
    // a well-formed identifier, UnsupportedSigner for a key state no single key can sign for.
    let group: Resolver = Arc::new(|keyid: &str| {
        Err(Error::detailed(
            Kind::UnsupportedSigner,
            "This AID's key state has no single key that satisfies its threshold.",
            keyid,
        ))
    });
    // guide:end
    let narrow = sign_request(
        controller,
        "POST",
        URL,
        &BTreeMap::new(),
        &SignOptions {
            body: Some(BODY.to_vec()),
            covered: Some(vec![
                "@method".into(),
                "@path".into(),
                "content-digest".into(),
            ]),
            keyid: Some(CONTROLLER.into()),
            ..Default::default()
        },
    )?;
    let mut doubled = headers.clone();
    let input = doubled["Signature-Input"].replacen("\"@path\"", "\"@path\" \"@path\"", 1);
    doubled.insert("Signature-Input".into(), input);
    let below = VerifyOptions {
        minimum: Minimum::Of(vec!["@method".into()]),
        ..opts(known.clone())
    };

    // A response verifier states its keyid decision; this one declines it.
    let any_signer = VerifyOptions {
        expected_keyid: ExpectedKeyid::Unchecked,
        ..Default::default()
    };
    let results = [
        verify(headers, &opts(nobody)), // the resolver knows no such keyid
        verify(headers, &opts(group)),  // the resolver refuses the key state
        verify(&narrow, &opts(known.clone())), // signed over less than the minimum
        verify(&doubled, &opts(known.clone())), // a component listed twice
        verify_response(401, &BTreeMap::new(), None, &any_signer), // unsigned 401
        verify(headers, &below),        // a minimum below the profile's own
    ];
    let mut seen = Vec::new();
    for result in results {
        // guide:begin error-kinds
        // Every refusal is an Err(fiki::Error) whose `kind` names the condition and whose
        // `detail` carries the offending value, such as the keyid or the missing component.
        // The KERI profile added these kinds:
        let err = result.unwrap_err();
        match err.kind {
            Kind::UnknownKey => {}           // no key is known for the keyid
            Kind::UnsupportedSigner => {}    // the AID's key state has no single signing key
            Kind::InsufficientCoverage => {} // valid, but covers less than the verifier requires
            Kind::DuplicateComponent => {}   // the covered list names a component twice
            Kind::Unauthenticated => {}      // a 401 the server did not sign
            Kind::InvalidArgument => {}      // the call is wrong, not the message
            _ => {}                          // the kinds that predate the profile
        }
        // guide:end
        seen.push(err.kind);
    }
    assert_eq!(
        seen,
        [
            Kind::UnknownKey,
            Kind::UnsupportedSigner,
            Kind::InsufficientCoverage,
            Kind::DuplicateComponent,
            Kind::Unauthenticated,
            Kind::InvalidArgument,
        ]
    );
    Ok(())
}
