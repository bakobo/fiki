package fiki

// The RFC 9421 signature base, section 2.5 (`this.i` @2hwvpm42).
//
// Exported, not internal. When two implementations disagree about a signature, the base is where
// they disagree, and a caller debugging an interop failure needs to see the bytes both sides
// actually hashed.

import (
	"net/url"
	"strings"
)

// Derived components fiki builds. Anything else is refused rather than skipped — a component
// silently dropped from the base is a component the caller believes is covered and is not, which
// is exactly the gap in heti's KERI dialect.
var Derived = []string{"@method", "@authority", "@path", "@query"}

// DefaultCovered is @method, @authority, @path, @query — plus content-digest whenever there is a
// body. This closes the query, host, and body gaps that heti's KERI dialect leaves open and
// structurally cannot close. `created` is a signature parameter rather than a component.
var DefaultCovered = []string{"@method", "@authority", "@path", "@query"}

// ContentDigestHeader is the covered component that binds a request body.
const ContentDigestHeader = "content-digest"

// Order is the signer's choice — a verifier reserializes whatever it received — so fiki fixes one
// order and keeps it, which makes its own output reproducible.
var paramOrder = []string{"created", "expires", "nonce", "alg", "keyid", "tag"}

var defaultPorts = map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443"}

func authority(u *url.URL, headers map[string]string) (string, error) {
	// RFC 9421 section 2.2.3: lowercase host, default port omitted. A relative URL falls back to
	// the Host header, which in HTTP/1.1 *is* the authority — the shape a server-side verifier
	// actually holds. Nothing is normalized away there, because without a scheme no port is a
	// default port.
	if u.Host != "" {
		host := strings.ToLower(u.Hostname())
		port := u.Port()
		if port == "" || port == defaultPorts[strings.ToLower(u.Scheme)] {
			return host, nil
		}
		return host + ":" + port, nil
	}
	host, ok := headers["host"]
	if !ok {
		return "", &Error{
			Kind: KindMissingComponent,
			Message: `The signature covers "@authority", but the URL carries no authority and ` +
				"the request has no Host header, so there is nothing to derive it from.",
			Component: "@authority",
		}
	}
	return strings.ToLower(host), nil
}

func componentValue(component, method string, u *url.URL, headers map[string]string) (string, error) {
	switch component {
	case "@method":
		return strings.ToUpper(method), nil
	case "@authority":
		return authority(u, headers)
	case "@path":
		// An empty path is the "/" the origin server would have received.
		if u.Path == "" {
			return "/", nil
		}
		return u.Path, nil
	case "@query":
		// Section 2.2.7: the whole query string including the leading "?", percent-encoding
		// preserved, and a bare "?" when the request carries no query at all. RawQuery rather
		// than Query(): parsing and re-encoding would normalize what the RFC says not to touch.
		return "?" + u.RawQuery, nil
	}
	if strings.HasPrefix(component, "@") {
		return "", &Error{
			Kind:      KindUnsupportedComponent,
			Message:   "fiki does not build the derived component " + component + "; it builds " + strings.Join(Derived, ", ") + ".",
			Component: component,
		}
	}
	value, ok := headers[component]
	if !ok {
		return "", &Error{
			Kind:      KindMissingComponent,
			Message:   "The signature covers " + component + ", but the request carries no value for it.",
			Component: component,
		}
	}
	return value, nil
}

func lowerHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		// Header field names are case-insensitive and appear lowercased in the base (section 2.1);
		// values are stripped of leading and trailing whitespace.
		out[strings.ToLower(name)] = strings.TrimSpace(value)
	}
	return out
}

// componentLines builds every line of the signature base except the trailing @signature-params.
//
// Split out because the verify side cannot call SignatureBase: it must reserialize the parameters
// exactly as they arrived, in the order they arrived, rather than in fiki's own fixed order.
func componentLines(method, rawURL string, headers map[string]string, covered []string) ([]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errorf(KindMissingComponent, "The URL %q could not be parsed.", rawURL)
	}
	lowered := lowerHeaders(headers)
	lines := make([]string, 0, len(covered))
	for _, component := range covered {
		component = strings.ToLower(component)
		value, err := componentValue(component, method, u, lowered)
		if err != nil {
			return nil, err
		}
		lines = append(lines, `"`+component+`": `+value)
	}
	return lines, nil
}

// SignatureParams carries the RFC 9421 signature parameters a signer sets.
type SignatureParams struct {
	Created int64
	Keyid   string
	Alg     string
	Expires int64
	Nonce   string
	Tag     string
}

// SignatureBase builds the RFC 9421 signature base for a request.
func SignatureBase(method, rawURL string, headers map[string]string, covered []string, params SignatureParams) ([]byte, error) {
	components := make([]string, len(covered))
	for i, component := range covered {
		components[i] = strings.ToLower(component)
	}
	lines, err := componentLines(method, rawURL, headers, components)
	if err != nil {
		return nil, err
	}

	list := innerList{Items: components}
	for _, name := range paramOrder {
		switch name {
		case "created":
			if params.Created != 0 {
				list.Params = append(list.Params, param{Key: name, Value: params.Created})
			}
		case "expires":
			if params.Expires != 0 {
				list.Params = append(list.Params, param{Key: name, Value: params.Expires})
			}
		case "nonce":
			if params.Nonce != "" {
				list.Params = append(list.Params, param{Key: name, Value: params.Nonce})
			}
		case "alg":
			if params.Alg != "" {
				list.Params = append(list.Params, param{Key: name, Value: params.Alg})
			}
		case "keyid":
			if params.Keyid != "" {
				list.Params = append(list.Params, param{Key: name, Value: params.Keyid})
			}
		case "tag":
			if params.Tag != "" {
				list.Params = append(list.Params, param{Key: name, Value: params.Tag})
			}
		}
	}
	lines = append(lines, `"@signature-params": `+serializeInnerList(list))
	return []byte(strings.Join(lines, "\n")), nil
}
