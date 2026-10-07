package fiki

// The RFC 9421 signature base, section 2.5 (`this.i` @2hwvpm42, @7f28p7xk).
//
// Exported, not internal. When two implementations disagree about a signature, the base is where
// they disagree, and a caller debugging an interop failure needs to see the bytes both sides
// actually hashed.
//
// Derived components fiki builds: @method, @authority, @path and @query in a request, and @status
// in a response, which may also name its request's components with the req parameter of section
// 2.4. Anything else is refused rather than skipped — a component silently dropped from the base
// is a component the caller believes is covered and is not, which is exactly the gap in heti's
// KERI dialect.

import (
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Derived lists the derived components fiki builds in a request, and that a response may name
// from its request with req.
var Derived = []string{"@method", "@authority", "@path", "@query"}

// The one derived component a response has of its own (RFC 9421 section 2.2.9). Every request
// component reaches a response only through req.
var responseDerived = []string{"@status"}

// DefaultCovered is @method, @authority, @path, @query — plus content-digest whenever there is a
// body. This closes the query, host, and body gaps that heti's KERI dialect leaves open and
// structurally cannot close. `created` is a signature parameter rather than a component.
var DefaultCovered = []string{"@method", "@authority", "@path", "@query"}

// ContentDigestHeader is the covered component that binds a body.
const ContentDigestHeader = "content-digest"

// The only component parameter fiki supports, and only in a response (RFC 9421 section 2.4).
const reqParam = "req"

// Order is the signer's choice — a verifier reserializes whatever it received — so fiki fixes one
// order and keeps it, which makes its own output reproducible.
var paramOrder = []string{"created", "expires", "nonce", "alg", "keyid", "tag"}

var defaultPorts = map[string]int{"http": 80, "https": 443, "ws": 80, "wss": 443}

// Request is the request a response answers, which a response's req components are read from.
//
// A nil Body means no body was handed over, which is not the same as an empty one: a response
// binding "content-digest";req can only be checked against a body fiki was given.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// componentID is a covered component's identifier: a name and its parameters, in their order.
type componentID struct {
	Name   string
	Params []param
}

// serialize is the RFC 8941 form the base and Signature-Input carry: "@path";req.
func (c componentID) serialize() string {
	return serializeBareItem(c.Name) + serializeParameters(c.Params)
}

// spec is the inverse of parseComponent: a plain name when there are no parameters.
func (c componentID) spec() string {
	if len(c.Params) == 0 {
		return c.Name
	}
	return c.serialize()
}

// identity is what two identifiers must share to be the same component. Parameter order is not
// part of it.
func (c componentID) identity() string {
	params := make([]string, len(c.Params))
	for i, p := range c.Params {
		params[i] = serializeParameters([]param{p})
	}
	sort.Strings(params)
	return serializeBareItem(c.Name) + strings.Join(params, "")
}

// isReq is true when the req parameter is present and true, the only form section 2.4 defines.
func (c componentID) isReq() bool {
	value, _ := paramValue(c.Params, reqParam)
	return value == true
}

// parseComponent reads a caller's spelling of a component: a plain name ("@method",
// "Content-Digest") or its RFC 8941 serialization with parameters (`"@path";req`). Names are
// lowercased as a convenience to a local caller; a name parsed from the wire never is, and is
// refused instead when it is not already lowercase.
func parseComponent(spec string) (componentID, error) {
	if !strings.HasPrefix(spec, `"`) {
		return componentID{Name: strings.ToLower(spec)}, nil
	}
	c := &cursor{text: spec}
	name, err := c.parseString()
	var params []param
	if err == nil {
		params, err = c.parseParameters()
	}
	if err != nil || !c.done() {
		return componentID{}, &Error{
			Kind: KindUnsupportedComponent,
			Message: "fiki cannot read " + spec + " as a component identifier; name a component " +
				`plainly, as "@path", or in its serialized form, as "\"@path\";req".`,
			Component: spec,
			Supported: strings.Join(append(append([]string{}, Derived...), responseDerived...), ", "),
		}
	}
	return componentID{Name: strings.ToLower(name), Params: params}, nil
}

func parseComponents(specs []string) ([]componentID, error) {
	items := make([]componentID, len(specs))
	for i, spec := range specs {
		item, err := parseComponent(spec)
		if err != nil {
			return nil, err
		}
		items[i] = item
	}
	return items, nil
}

// Req is the spelling of a request component named from a response: Req("@path") is
// `"@path";req`.
func Req(name string) string {
	return componentID{Name: strings.ToLower(name), Params: []param{{Key: reqParam, Value: true}}}.serialize()
}

// checkCovered refuses a covered list fiki cannot build faithfully: duplicates first, then the
// unsupported. That order is the KERI profile's section 9, so a list that is both has one correct
// refusal.
func checkCovered(items []componentID, response bool) error {
	seen := map[string]bool{}
	for _, item := range items {
		if seen[item.identity()] {
			return &Error{
				Kind: KindDuplicateComponent,
				Message: "The covered components name " + item.spec() + " twice, so the signature " +
					"base would not be what either copy says it is.",
				Component: item.spec(),
			}
		}
		seen[item.identity()] = true
	}

	for _, item := range items {
		_, hasReq := paramValue(item.Params, reqParam)
		if len(item.Params) > 1 || (len(item.Params) == 1 && !hasReq) || (hasReq && !(item.isReq() && response)) {
			return &Error{
				Kind: KindUnsupportedComponent,
				Message: "fiki does not support the component " + item.spec() + `: the only component ` +
					`parameter it supports is "req", and only in a response.`,
				Component: item.spec(),
				Supported: reqParam,
			}
		}
		if strings.HasPrefix(item.Name, "@") {
			supported, where := Derived, "request"
			if response {
				where = "response"
				if !item.isReq() {
					supported = responseDerived
				}
			}
			if !slices.Contains(supported, item.Name) {
				return &Error{
					Kind: KindUnsupportedComponent,
					Message: "fiki does not build the derived component " + item.spec() + " in a " +
						where + "; it builds " + strings.Join(supported, ", ") + ".",
					Component: item.spec(),
					Supported: strings.Join(supported, ", "),
				}
			}
		}
	}
	return nil
}

// target is a URL split the way the origin server received it: nothing decoded, nothing
// normalized. Go's net/url decodes the path, which is the one thing @path must not do (profile
// section 2, O1), so fiki splits the URL itself, as Python's urlsplit does for fiki-py.
type target struct {
	scheme, netloc, path, query string
}

func splitURL(raw string) target {
	// Leading C0 controls and spaces are stripped, and tab, CR and LF removed wherever they are,
	// as the WHATWG URL parser does and urlsplit follows.
	raw = strings.TrimLeft(raw, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"+
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f ")
	raw = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(raw)
	var t target
	if i := strings.IndexByte(raw, ':'); i > 0 && isAlpha(raw[0]) && isSchemeText(raw[:i]) {
		t.scheme, raw = strings.ToLower(raw[:i]), raw[i+1:]
	}
	if strings.HasPrefix(raw, "//") {
		raw = raw[2:]
		end := strings.IndexAny(raw, "/?#")
		if end < 0 {
			end = len(raw)
		}
		t.netloc, raw = raw[:end], raw[end:]
	}
	raw, _, _ = strings.Cut(raw, "#")
	t.path, t.query, _ = strings.Cut(raw, "?")
	return t
}

func isAlpha(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

func isSchemeText(text string) bool {
	for i := 0; i < len(text); i++ {
		if !isAlpha(text[i]) && !isDigit(text[i]) && strings.IndexByte("+-.", text[i]) < 0 {
			return false
		}
	}
	return true
}

// authority is RFC 9421 section 2.2.3: lowercase host, default port omitted.
//
// A relative URL falls back to the Host header, which in HTTP/1.1 *is* the authority — the shape a
// server-side verifier actually holds. Nothing is normalized away there, because without a scheme
// no port is a default port.
func authority(t target, headers map[string]string) (string, error) {
	if t.netloc == "" {
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
	// Userinfo, if any, ends at the last "@".
	hostinfo := t.netloc[strings.LastIndexByte(t.netloc, '@')+1:]
	unbuildable := func(why string) error {
		return &Error{
			Kind: KindMissingComponent,
			Message: "The signature covers \"@authority\", and the URL's authority " +
				strconv.Quote(hostinfo) + " " + why + ", so there is no authority to build.",
			Component: "@authority",
		}
	}
	host, port := hostinfo, ""
	if open := strings.IndexByte(hostinfo, '['); open >= 0 {
		// An IP literal keeps its brackets: RFC 3986 section 3.2.2 makes them part of the host,
		// and @authority is built from the host (this.i @8f6txftu).
		literal, rest, closed := strings.Cut(hostinfo[open+1:], "]")
		if !closed {
			return "", unbuildable("opens an IP literal it never closes")
		}
		host = "[" + literal + "]"
		_, port, _ = strings.Cut(rest, ":")
	} else if strings.Contains(hostinfo, "]") {
		return "", unbuildable("closes an IP literal it never opened")
	} else {
		host, port, _ = strings.Cut(hostinfo, ":")
	}
	host = strings.ToLower(host)
	if port == "" {
		return host, nil
	}
	number, err := strconv.Atoi(port)
	if strings.TrimLeft(port, "0123456789") != "" || err != nil || number > 65535 {
		return "", unbuildable("has a port that is not a port number")
	}
	if number == defaultPorts[strings.ToLower(t.scheme)] {
		return host, nil
	}
	return host + ":" + strconv.Itoa(number), nil
}

// message is what a component value is read from: a request, or a response with the request it
// answers.
type message struct {
	headers map[string]string
	method  string
	target  target
	status  int
	request *message
}

// canonicalHeaders is the one lowercased view of a headers map that every later step reads.
//
// Header field names are case-insensitive and appear lowercased in the base (section 2.1); values
// lose leading and trailing SP and HTAB only (RFC 9110 section 5.5). Trimming CR, LF or NUL as well
// would let "admin\r\n" verify as "admin"; left in, valueOf refuses it. A map holding two
// spellings of one name is refused rather than collapsed: which one survived would turn on Go's
// map order, so the signature base and the digest check could read different values for one
// field (bakobo/fiki#6). net/http never builds such a map, so it is the caller's construction.
func canonicalHeaders(headers map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(headers)+1)
	for name, value := range headers {
		lowered := strings.ToLower(name)
		if _, seen := out[lowered]; seen {
			return nil, invalidOptions("The headers name %q more than once under different "+
				"capitalizations, so there is no one value to sign or check; merge them first.", lowered)
		}
		out[lowered] = strings.Trim(value, " \t")
	}
	return out, nil
}

func requestMessage(method, rawURL string, headers map[string]string) (*message, error) {
	canonical, err := canonicalHeaders(headers)
	if err != nil {
		return nil, err
	}
	return canonicalMessage(method, rawURL, canonical), nil
}

// canonicalMessage is a request over headers canonicalHeaders has already produced.
func canonicalMessage(method, rawURL string, canonical map[string]string) *message {
	return &message{headers: canonical, method: method, target: splitURL(rawURL)}
}

func responseMessage(status int, headers map[string]string, request *Request) (*message, error) {
	canonical, err := canonicalHeaders(headers)
	if err != nil {
		return nil, err
	}
	m := &message{headers: canonical, status: status}
	if request != nil {
		if m.request, err = requestMessage(request.Method, request.URL, request.Headers); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func componentValue(item componentID, m *message) (string, error) {
	if item.isReq() {
		if m.request == nil {
			return "", &Error{
				Kind: KindMissingComponent,
				Message: "The signature covers " + item.spec() + ", which is read from the request " +
					"this response answers, and no request was supplied.",
				Component: item.spec(),
			}
		}
		m = m.request
	}
	switch item.Name {
	case "@status":
		// Section 2.2.9: the three-digit status code. Anything else is not a status this
		// component can carry, so there is no value to sign or to check.
		if m.status < 100 || m.status > 999 {
			return "", &Error{
				Kind: KindMissingComponent,
				Message: "The signature covers @status, and " + strconv.Itoa(m.status) + " is not a " +
					"three-digit HTTP status code, so there is no status line to build.",
				Component: "@status",
			}
		}
		return strconv.Itoa(m.status), nil
	case "@method":
		// Section 2.2.1: the method as sent, with no case transformation (this.i @22g0xkr8). No
		// request is sent without a method, so an empty one is a mistake in the call, never a
		// value to sign.
		if m.method == "" {
			return "", invalidOptions("The signature covers %s, and no method was given; pass the method as it goes on the wire.", item.spec())
		}
		return m.method, nil
	case "@authority":
		return authority(m.target, m.headers)
	case "@path":
		// An empty path is the "/" the origin server would have received.
		if m.target.path == "" {
			return "/", nil
		}
		return m.target.path, nil
	case "@query":
		// Section 2.2.7: the whole query string including the leading "?", percent-encoding
		// preserved, and a bare "?" when the request carries no query at all.
		return "?" + m.target.query, nil
	}
	value, ok := m.headers[item.Name]
	if !ok {
		return "", &Error{
			Kind: KindMissingComponent,
			Message: "The signature covers " + item.spec() + ", but the message carries no value " +
				"for it, so the signature base cannot be built.",
			Component: item.spec(),
		}
	}
	return value, nil
}

// valueOf is a component's value, refused when it has no single serialization both sides agree
// on. A line break inside a value would forge a line of the base, and a byte outside visible
// ASCII is encoded differently by different stacks, so the KERI profile names such a base
// unbuildable, and so a signature-mismatch (this.i @2f227n4r).
func valueOf(item componentID, m *message) (string, error) {
	value, err := componentValue(item, m)
	if err != nil {
		return "", err
	}
	for i := 0; i < len(value); i++ {
		if value[i] != '\t' && (value[i] < ' ' || value[i] > '~') {
			return "", errorf(KindSignatureMismatch,
				"The value of %s contains a line break, a control character or a non-ASCII "+
					"character, so there is no signature base both sides would build from it.", item.spec())
		}
	}
	return value, nil
}

// componentLines is every line of the signature base except the trailing @signature-params.
func componentLines(items []componentID, m *message) ([]string, error) {
	lines := make([]string, 0, len(items)+1)
	for _, item := range items {
		value, err := valueOf(item, m)
		if err != nil {
			return nil, err
		}
		lines = append(lines, item.serialize()+": "+value)
	}
	return lines, nil
}

// SignatureParams carries the RFC 9421 signature parameters a signer sets. A zero value is an
// absent parameter.
type SignatureParams struct {
	Created int64
	Keyid   string
	Alg     string
	Expires int64
	Nonce   string
	Tag     string
}

func (p SignatureParams) list() []param {
	values := map[string]any{"created": p.Created, "expires": p.Expires, "nonce": p.Nonce,
		"alg": p.Alg, "keyid": p.Keyid, "tag": p.Tag}
	var out []param
	for _, name := range paramOrder {
		if value := values[name]; value != int64(0) && value != "" {
			out = append(out, param{Key: name, Value: value})
		}
	}
	return out
}

func buildBase(items []componentID, m *message, response bool, params SignatureParams) ([]byte, error) {
	if err := checkCovered(items, response); err != nil {
		return nil, err
	}
	lines, err := componentLines(items, m)
	if err != nil {
		return nil, err
	}
	list := innerList{Params: params.list()}
	for _, c := range items {
		list.Items = append(list.Items, item{Value: c.Name, Params: c.Params})
	}
	lines = append(lines, `"@signature-params": `+serializeInnerList(list))
	return []byte(strings.Join(lines, "\n")), nil
}

// SignatureBase builds the RFC 9421 signature base for a request.
//
// rawURL is a full URL, because @authority and @query cannot be derived from a path alone. It
// returns a DuplicateComponent for a component named twice, an UnsupportedComponent for a derived
// component outside Derived or any component parameter, and a MissingComponent for a covered
// header the request does not carry.
func SignatureBase(method, rawURL string, headers map[string]string, covered []string, params SignatureParams) ([]byte, error) {
	items, err := parseComponents(covered)
	if err != nil {
		return nil, err
	}
	m, err := requestMessage(method, rawURL, headers)
	if err != nil {
		return nil, err
	}
	return buildBase(items, m, false, params)
}

// ResponseSignatureBase builds the RFC 9421 signature base for a response (sections 2.2.9 and
// 2.4).
//
// request is the request being answered, which req components are read from — spelled
// Req("@path") or `"@path";req`. Without one, a req component is a MissingComponent.
func ResponseSignatureBase(status int, request *Request, headers map[string]string, covered []string, params SignatureParams) ([]byte, error) {
	items, err := parseComponents(covered)
	if err != nil {
		return nil, err
	}
	m, err := responseMessage(status, headers, request)
	if err != nil {
		return nil, err
	}
	return buildBase(items, m, true, params)
}
