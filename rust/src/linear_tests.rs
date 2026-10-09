//! Untrusted lists are processed in linear time (bakobo/fiki#8), checked by ratio rather than by a
//! clock (tick 7xbw).
//!
//! In the crate rather than under tests/, because the parser is internal and the parameter test
//! has to reach it below the 8192-byte field bound (review T5): driven through `verify_request`, a
//! list long enough to time is refused for its size before the parser sees it, so a quadratic
//! parser passed the old test.

use std::hint::black_box;
use std::time::{Duration, Instant};

use crate::sfv::parse_dictionary;

/// Fails unless doing the work once over 4n inputs takes about as long as doing it four times over
/// n, which is what linear work does; quadratic work takes four times as long. It compares the two
/// rather than holding either to a wall-clock limit, so a slow or loaded runner slows both alike
/// and cannot fail it (C#'s absolute-time test failed on a loaded machine on 2026-10-09). The two
/// are timed alternately, nine rounds each keeping its fastest, so a stall lands on both or on
/// neither. The limit of 2.5 leaves linear work room for cache and allocator effects, and still
/// refuses quadratic work's 4.
fn scales_linearly<F: Fn()>(n: usize, prepare: impl Fn(usize) -> F) {
    let (small, large) = (prepare(n), prepare(4 * n));
    let runs: [&dyn Fn(); 2] = [
        &|| {
            for _ in 0..4 {
                small();
            }
        },
        &|| large(),
    ];
    let mut fastest = [Duration::MAX; 2];
    for _ in 0..9 {
        for (i, run) in runs.iter().enumerate() {
            let started = Instant::now();
            run();
            fastest[i] = fastest[i].min(started.elapsed());
        }
    }
    let ratio = fastest[1].as_secs_f64() / fastest[0].max(Duration::from_micros(1)).as_secs_f64();
    assert!(
        ratio <= 2.5,
        "work over {n} inputs, done four times, took {:?}, and over {} inputs once took {:?}, \
         {ratio:.1} times as long; linear work takes about as long",
        fastest[0],
        4 * n,
        fastest[1]
    );
}

/// RFC 8941 gives a repeated parameter key its first place and its last value, and the parser
/// indexes the keys it has seen rather than searching them (bakobo/fiki#8). Distinct keys are the
/// case a search would make quadratic. The count bounds apply after parsing, so the parser reads
/// every one of them.
#[test]
fn a_huge_parameter_list_is_parsed_in_linear_time() {
    scales_linearly(10_000, |n| {
        let params: String = (0..n).map(|i| format!(";p{i}=1")).collect();
        let field = format!("sig=(\"@method\");keyid=\"k\"{params}");
        move || {
            let parsed = parse_dictionary(black_box(&field)).unwrap();
            assert_eq!(parsed.len(), 1);
        }
    });
}
