# fiki-go's optional string options cannot tell 'not supplied' from an explicit empty string (#18 Copilot): VerifyOptions.ExpectedKeyid on a request, and ExpectedAID, which predates format 3, read "" as unset, so a missing configuration value (os.Getenv returning "") silently disables the signer constraint instead of being refused as the empty-AID caller error the other ports raise. VerifyResponse already refuses "" as no decision. Decide one shape for all of Go's optional strings -- *string, a tagged option type, or an explicit Set flag -- since it is an API change; then add a misuse vector per port for an explicit empty expected_aid.
kind: todo
created: 2026-10-09T05:07Z

- 2026-10-09T20:40Z Ruled 2026-10-09 (Daniel, fiki-release session): *string for ExpectedAID and ExpectedKeyid, matching Skew *int64, plus a fiki.String helper; AnyKeyid stays. Lands in format 4.
