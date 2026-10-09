# Cross-port divergence on URL userinfo: fiki-py refuses https://a]b@host.example/x (urlsplit rejects a bracket anywhere in the netloc) while java strips the userinfo first and accepts it (hostile review of #15). RFC 9421 @authority never covers userinfo, so no signed component changes; it is a disagreement about which malformed URLs are refused, not a forgery. Decide one rule for all six ports (likely: refuse a bracket anywhere in the authority outside an IP-literal, userinfo included), and pin it with a vector at the next format bump.
kind: todo
created: 2026-10-08T02:04Z

- 2026-10-09T20:41Z Ruled 2026-10-09: folded into the format-4 bump with 7kle, 7r4c, 44hj, 3ljo and 5kyt.
