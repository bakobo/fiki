# A Request handed to verify_response (or sign_response) whose headers announce a body (Content-Length > 0, any Transfer-Encoding) but whose body is not passed binds no request digest, by @7p9s3g9k's 'judged by content' rule, which follows the published KERI profile's assumption that both sides hold the whole request. Format 3 makes that the default for every client (#18 hostile pass, finding 1, reproduced in js). Consider making such a Request a caller error -- the profile's assumption is broken, not the request -- which would be a cross-port contract change and a vector per port.
kind: todo
created: 2026-10-09T04:51Z
closed: 2026-10-12T02:55Z

- 2026-10-09T20:40Z Ruled 2026-10-09: such a Request is a caller error (ErrInvalidOptions and equivalents), superseding @7p9s3g9k by a new this.i node. Format 4.
- 2026-10-12T02:55Z Done in bakobo/fiki#25 (merge e676c7d), vectors_format 4 / keri_vectors_format 6, this.i @646un6k8 and children; all six ports, differential 0 disagreements. Unreleased until the next release.
- 2026-10-12T02:55Z Refined in #25 after its hostile pass: an empty body beside a Content-Length that is not a plain zero is the same caller error; an empty body beside Transfer-Encoding is not (a chunked request may carry nothing).
