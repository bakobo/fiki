# A Request handed to verify_response (or sign_response) whose headers announce a body (Content-Length > 0, any Transfer-Encoding) but whose body is not passed binds no request digest, by @7p9s3g9k's 'judged by content' rule, which follows the published KERI profile's assumption that both sides hold the whole request. Format 3 makes that the default for every client (#18 hostile pass, finding 1, reproduced in js). Consider making such a Request a caller error -- the profile's assumption is broken, not the request -- which would be a cross-port contract change and a vector per port.
kind: todo
created: 2026-10-09T04:51Z

- 2026-10-09T20:40Z Ruled 2026-10-09: such a Request is a caller error (ErrInvalidOptions and equivalents), superseding @7p9s3g9k by a new this.i node. Format 4.
