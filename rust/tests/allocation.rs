//! A request body is borrowed, never copied, on the response paths (bakobo/fiki#8).
//!
//! Observed through a counting global allocator, which is why this is its own test binary: the
//! allocator is process-wide, and the one test here is the only thing running in it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use fiki::{
    content_digest, sign_response, verify_response, Authorities, Key, Minimum, Request,
    SignOptions, VerifyOptions,
};

/// The policy fiki 0.8 applied when a caller stated none: no minimum and no authority check.
/// Format 3 makes a minimum the default and authorities a required decision (`this.i` @524c8qgv),
/// so a test whose subject is something else states that policy rather than relying on it.
fn opted_out() -> VerifyOptions {
    VerifyOptions {
        minimum: Minimum::Off,
        authorities: Authorities::Unchecked,
        ..Default::default()
    }
}

struct Counting;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocated_by<T>(work: impl FnOnce() -> T) -> (T, usize) {
    let before = ALLOCATED.load(Ordering::Relaxed);
    let out = work();
    (out, ALLOCATED.load(Ordering::Relaxed) - before)
}

#[test]
fn a_large_request_body_is_hashed_in_place_when_a_response_binds_it() {
    const SIZE: usize = 8 << 20;
    let body = vec![b'x'; SIZE];
    let request = Request {
        method: "POST".into(),
        url: "https://keria.example.com/identifiers".into(),
        headers: BTreeMap::from([("Content-Digest".to_string(), content_digest(&body))]),
        body: Some(body),
    };
    let key = Key::from_seed(&[7u8; 32]).unwrap();
    let opts = SignOptions {
        created: Some(1_700_000_000),
        ..Default::default()
    };

    let (headers, used) =
        allocated_by(|| sign_response(&key, 204, Some(&request), &BTreeMap::new(), &opts));
    let headers = headers.unwrap();
    assert!(
        used < SIZE,
        "signing allocated {used} bytes for an {SIZE}-byte body"
    );

    let (verdict, used) =
        allocated_by(|| verify_response(204, &headers, Some(&request), &opted_out()));
    assert!(verdict
        .unwrap()
        .covered
        .contains(&"\"content-digest\";req".to_string()));
    assert!(
        used < SIZE,
        "verifying allocated {used} bytes for an {SIZE}-byte body"
    );
}
