# Cross-port divergence on URL userinfo: fiki-py refuses https://a]b@host.example/x (urlsplit rejects a bracket anywhere in the netloc) while java strips the userinfo first and accepts it (hostile review of #15). RFC 9421 @authority never covers userinfo, so no signed component changes; it is a disagreement about which malformed URLs are refused, not a forgery. Decide one rule for all six ports (likely: refuse a bracket anywhere in the authority outside an IP-literal, userinfo included), and pin it with a vector at the next format bump.
kind: todo
created: 2026-10-08T02:04Z

- 2026-10-09T20:41Z Ruled 2026-10-09: folded into the format-4 bump with 7kle, 7r4c, 44hj, 3ljo and 5kyt.
- 2026-10-09T23:39Z Related, for format 4: RFC 3986's ABNF is case-insensitive, so 'V1.x' is a valid IPvFuture, and CPython 3.13.16/3.14.8 urlsplit now accepts it; fiki-py's ip_literal (and, per the differential, every port) refuses an uppercase V because it mirrors the older urlsplit grammar. Decide one rule for all six with the bracket rule here, and pin it.
- 2026-10-09T23:40Z Correction to the previous note: whether ports other than fiki-py refuse an uppercase 'V' IPvFuture is NOT verified; the differential's 3,000 cases may not include one. Check each port before deciding.
