# Bound URL, Host, covered header values and header count before parsing, and truncate echoed values in refusal messages (a 5 MB URL gave a 10 MB rust error). Also: framework header shapes (set-cookie arrays, repeated headers) raise non-fiki exceptions in py/js; rust to_aid panics and java truncates on wrong byte count. (bakobo/reviews fiki/2026-10-08-input-hardening/synthesis.md 1.9-1.12)
kind: todo
created: 2026-10-08T16:49Z

- 2026-10-09T16:21Z Resolved in #18: URL, Host and covered values bounded at 8192 bytes in every port, error messages quote at most 64 characters and every driver checks it; Rust to_aid returns Result and Java toAid refuses a wrong length (B8). Framework header shapes moved to ~7r4c. A header-count bound was decided against (this.i, part two).
