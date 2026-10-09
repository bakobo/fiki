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
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
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

// ipLiteral is RFC 3986 section 3.2.2's IP-literal, as Python's urlsplit checks it from 3.11.4, so
// a host fiki-py refuses is refused here too: IPvFuture ("v", hex digits, ".", then anything but a
// line feed), or an IPv6address with an optional zone after "%". The IPv6 grammar is RFC 3986's
// own, which accepts exactly what Python's ipaddress.IPv6Address does.
var ipLiteral = func() *regexp.Regexp {
	const h16 = `[0-9A-Fa-f]{1,4}`
	const decOctet = `(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`
	const ls32 = `(?:` + h16 + `:` + h16 + `|` + decOctet + `(?:\.` + decOctet + `){3})`
	ipv6 := strings.Join([]string{
		`(?:` + h16 + `:){6}` + ls32,
		`::(?:` + h16 + `:){5}` + ls32,
		`(?:` + h16 + `)?::(?:` + h16 + `:){4}` + ls32,
		`(?:(?:` + h16 + `:){0,1}` + h16 + `)?::(?:` + h16 + `:){3}` + ls32,
		`(?:(?:` + h16 + `:){0,2}` + h16 + `)?::(?:` + h16 + `:){2}` + ls32,
		`(?:(?:` + h16 + `:){0,3}` + h16 + `)?::` + h16 + `:` + ls32,
		`(?:(?:` + h16 + `:){0,4}` + h16 + `)?::` + ls32,
		`(?:(?:` + h16 + `:){0,5}` + h16 + `)?::` + h16,
		`(?:(?:` + h16 + `:){0,6}` + h16 + `)?::`,
	}, "|")
	return regexp.MustCompile(`^(?:v[0-9A-Fa-f]+\.[^\n]+|(?:` + ipv6 + `)(?:%[^%]+)?)$`)
}()

// RFC 8941 section 3.3.1: an integer has at most fifteen digits.
const sfIntegerMax = 999_999_999_999_999

const portMax = 65535

// isTchar is RFC 9110 section 5.6.2's tchar. A token, one or more of them, is what a method is
// (section 9.1) and what a field name is (section 5.1).
func isTchar(b byte) bool {
	return isAlpha(b) || isDigit(b) || strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0
}

func isToken(text string) bool {
	for i := 0; i < len(text); i++ {
		if !isTchar(text[i]) {
			return false
		}
	}
	return text != ""
}

// isSfString is true when text is RFC 8941 sf-string content (section 3.3.3): printable ASCII,
// 0x20 to 0x7E, and nothing else, so a line break can never be serialized into a header.
func isSfString(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] < ' ' || text[i] > '~' {
			return false
		}
	}
	return true
}

// isSfKey is true when text is an RFC 8941 key (section 3.1.2), which is what a label is.
func isSfKey(text string) bool {
	if text == "" || !isKeyStart(text[0]) {
		return false
	}
	for i := 1; i < len(text); i++ {
		if !isKeyChar(text[i]) {
			return false
		}
	}
	return true
}

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
// refused instead when it is not already lowercase. A field name that is not a token is the
// caller's mistake, because it would be serialized into Signature-Input as given (this.i
// @5zrf8gjk); a derived name fiki does not build is refused later, as UnsupportedComponent.
func parseComponent(spec string) (componentID, error) {
	id, err := readComponent(spec)
	if err == nil && !strings.HasPrefix(id.Name, "@") && !isToken(id.Name) {
		return componentID{}, invalidOptions("%s is not a component fiki can name: a field is named "+
			"by an HTTP field name, one or more token characters, and a derived component by its @ name.", shown(spec))
	}
	return id, err
}

func readComponent(spec string) (componentID, error) {
	if !strings.HasPrefix(spec, `"`) {
		return componentID{Name: asciiLower(spec)}, nil
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
			Message: "fiki cannot read " + brief(spec) + " as a component identifier; name a component " +
				`plainly, as "@path", or in its serialized form, as "\"@path\";req".`,
			Component: spec,
			Supported: strings.Join(append(append([]string{}, Derived...), responseDerived...), ", "),
		}
	}
	return componentID{Name: asciiLower(name), Params: params}, nil
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
	return componentID{Name: asciiLower(name), Params: []param{{Key: reqParam, Value: true}}}.serialize()
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
				Message: "The covered components name " + brief(item.spec()) + " twice, so the signature " +
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
				Message: "fiki does not support the component " + brief(item.spec()) + `: the only component ` +
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
					Message: "fiki does not build the derived component " + brief(item.spec()) + " in a " +
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
// section 2, O1), so fiki splits the URL itself. unreadable, when set, is why the target has no
// components at all; it is reported only when a covered component needs one, as fiki-py reads
// the target lazily.
type target struct {
	scheme, netloc, path, query string
	unreadable                  string
}

// splitURL reads a request target as RFC 9112 section 3.2 does (this.i @524c8qgv).
//
// A target beginning with "/" is origin-form: everything before the first "?" is the path,
// verbatim, however many slashes it starts with, and it has no authority of its own, so authority
// reads the Host header. Reading "//evil.example/p" as a network-path reference would let the
// sender choose the authority (review A1). Anything else must be a scheme, "://" and a non-empty
// authority. A space or an ASCII control anywhere is refused rather than stripped, since
// stripping made "/\nx" verify as "/x", and so is a fragment, which no request target has.
func splitURL(raw string) target {
	// Bounded before it is read, size before shape (this.i @524c8qgv).
	if len(raw) > MaxFieldBytes {
		return target{unreadable: fmt.Sprintf("is over %d bytes", MaxFieldBytes)}
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] == 0x7f {
			return target{unreadable: "contains a space or a control character"}
		}
	}
	if strings.IndexByte(raw, '#') >= 0 {
		return target{unreadable: "carries a fragment, which no request target has"}
	}
	var t target
	if !strings.HasPrefix(raw, "/") {
		scheme, rest, ok := strings.Cut(raw, "://")
		if !ok || scheme == "" || !isAlpha(scheme[0]) || !isSchemeText(scheme) ||
			rest == "" || strings.IndexByte("/?", rest[0]) >= 0 {
			return target{unreadable: "is neither origin-form, beginning with a slash, nor an " +
				"absolute URI with a scheme and an authority"}
		}
		end := strings.IndexAny(rest, "/?")
		if end < 0 {
			end = len(rest)
		}
		t.scheme, t.netloc, raw = strings.ToLower(scheme), rest[:end], rest[end:]
	}
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

// unbuildable is a target fiki cannot read: the caller's mistake when signing, and a base that
// cannot be built, so a SignatureMismatch (profile section 9), when the message was received
// (this.i @5zrf8gjk).
func (m *message) unbuildable(what, why string) error {
	if m.received {
		return errorf(KindSignatureMismatch, "The %s %s, so there is no signature base to check "+
			"the signature against.", what, why)
	}
	return invalidOptions("The %s %s, so there is no signature base to sign.", what, why)
}

// targetOf is the message's target, or the reason it has none.
func targetOf(m *message) (target, error) {
	if m.target.unreadable != "" {
		return target{}, m.unbuildable("URL "+shown(m.url), m.target.unreadable)
	}
	return m.target, nil
}

// authority is RFC 9421 section 2.2.3: lowercase host, default port omitted.
//
// An origin-form target takes its authority from the Host header, which in HTTP/1.1 *is* the
// authority — the shape a server-side verifier actually holds. Host passes every check an
// absolute URL's authority does, holds no userinfo and no list of hosts, and keeps its port,
// because without a scheme no port is a default one (this.i, "Host is validated like any
// authority").
//
// A port is any run of ASCII digits read as a number, so :000080 is 80, and an empty port is no
// port at all (RFC 3986 section 6.2.3). Every byte is checked to be visible ASCII before the host
// is lowercased, since Unicode case mapping turns U+212A KELVIN SIGN into "k" (review A6).
func authority(m *message) (string, error) {
	t, err := targetOf(m)
	if err != nil {
		return "", err
	}
	if t.netloc != "" {
		if strings.IndexByte(t.netloc, '@') >= 0 {
			// RFC 9110 section 4.2.4: treat userinfo as an error, since it is used to obscure the
			// authority (this.i @524c8qgv). An empty one is userinfo too.
			return "", m.unbuildable("URL "+shown(m.url), "carries user information in its authority")
		}
		return hostport(m, "URL's authority", t.netloc, t.scheme)
	}
	host, ok := m.headers["host"]
	if !ok {
		return "", &Error{
			Kind: KindMissingComponent,
			Message: `The signature covers "@authority", but the URL carries no authority and ` +
				"the request has no Host header, so there is nothing to derive it from.",
			Component: "@authority",
		}
	}
	// Host supplies a covered value, so it is bounded like one (this.i @524c8qgv).
	if err := checkRaw(host, "@authority", true); err != nil {
		return "", err
	}
	host = strings.Trim(host, " \t")
	if strings.ContainsAny(host, "@,") {
		return "", m.unbuildable("Host header "+shown(host), "is not a single host and optional port")
	}
	return hostport(m, "Host header", host, "")
}

// hostport is host[:port] normalized per RFC 9421 section 2.2.3, or a base that cannot be built.
func hostport(m *message, where, hostinfo, scheme string) (string, error) {
	unbuildable := func(why string) error {
		return m.unbuildable(where+" "+shown(hostinfo), why)
	}
	for i := 0; i < len(hostinfo); i++ {
		if hostinfo[i] > '~' {
			return "", unbuildable("is not ASCII")
		}
	}
	var host, port string
	if strings.HasPrefix(hostinfo, "[") {
		// An IP literal keeps its brackets: RFC 3986 section 3.2.2 makes them part of the host,
		// and @authority is built from the host (this.i @8f6txftu). Nothing but ":port" may
		// follow the "]", or text after it would be dropped from the authority (bakobo/fiki#6).
		literal, rest, closed := strings.Cut(hostinfo[1:], "]")
		if !closed {
			return "", unbuildable("opens an IP literal it never closes")
		}
		if rest != "" && !strings.HasPrefix(rest, ":") {
			return "", unbuildable("has text after its IP literal that is not a port")
		}
		if !ipLiteral.MatchString(literal) {
			return "", unbuildable("has an IP literal that is not an IPv6 address or IPvFuture")
		}
		host, port = "["+literal+"]", strings.TrimPrefix(rest, ":")
	} else if strings.ContainsAny(hostinfo, "[]") {
		return "", unbuildable("has a bracket outside an IP literal")
	} else {
		host, port, _ = strings.Cut(hostinfo, ":")
	}
	host = strings.ToLower(host)
	if port == "" {
		return host, nil
	}
	number, err := strconv.Atoi(port)
	if strings.TrimLeft(port, "0123456789") != "" || err != nil || number > portMax {
		return "", unbuildable("has a port that is not a number from 0 to 65535")
	}
	if standard, ok := defaultPorts[scheme]; ok && number == standard {
		return host, nil
	}
	return host + ":" + strconv.Itoa(number), nil
}

// message is what a component value is read from: a request, or a response with the request it
// answers.
type message struct {
	headers map[string]string
	method  string
	url     string
	target  target
	status  int
	request *message
	// received is a message handed to a verifier rather than built by a signer, which decides
	// what a URL that cannot be read is: a base that cannot be built, or the caller's mistake.
	received bool
}

// canonicalHeaders is the one lowercased view of a headers map that every later step reads.
//
// Header field names are case-insensitive and appear lowercased in the base (section 2.1). Values
// are kept as received: valueOf checks a covered one raw and only then trims SP and HTAB (RFC 9110
// section 5.5), so "admin\r\n" is refused rather than verified as "admin", and the input bounds
// measure a field before anything is trimmed from it (this.i @5zrf8gjk). A map holding two
// spellings of one name is refused rather than collapsed: which one survived would turn on Go's
// map order, so the signature base and the digest check could read different values for one
// field (bakobo/fiki#6). net/http never builds such a map, so it is the caller's construction.
func canonicalHeaders(headers map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(headers)+1)
	for name, value := range headers {
		lowered := asciiLower(name)
		if _, seen := out[lowered]; seen {
			return nil, invalidOptions("The headers name %s more than once under different "+
				"capitalizations, so there is no one value to sign or check; merge them first.", shown(lowered))
		}
		out[lowered] = value
	}
	return out, nil
}

func requestMessage(method, rawURL string, headers map[string]string, received bool) (*message, error) {
	canonical, err := canonicalHeaders(headers)
	if err != nil {
		return nil, err
	}
	return canonicalMessage(method, rawURL, canonical, received)
}

// canonicalMessage is a request over headers canonicalHeaders has already produced. Every
// request message is built here, so the method is checked on every path, whether or not @method
// is covered: it is an RFC 9110 token, one or more tchar, or the call is a mistake (this.i
// @5zrf8gjk, bakobo/fiki#6). Its case is kept as given (@22g0xkr8).
func canonicalMessage(method, rawURL string, canonical map[string]string, received bool) (*message, error) {
	if !isToken(method) {
		return nil, invalidOptions("The method %s is not an HTTP method: a method is one or more token "+
			"characters, with no spaces, line breaks or separators; pass it as it goes on the wire.", shown(method))
	}
	return &message{headers: canonical, method: method, url: rawURL, target: splitURL(rawURL), received: received}, nil
}

func responseMessage(status int, headers map[string]string, request *Request, received bool) (*message, error) {
	canonical, err := canonicalHeaders(headers)
	if err != nil {
		return nil, err
	}
	m := &message{headers: canonical, status: status, received: received}
	if request != nil {
		if m.request, err = requestMessage(request.Method, request.URL, request.Headers, received); err != nil {
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
				Message: "The signature covers " + brief(item.spec()) + ", which is read from the request " +
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
		// Section 2.2.1: the method as sent, with no case transformation (this.i @22g0xkr8).
		return m.method, nil
	case "@authority":
		return authority(m)
	case "@path":
		t, err := targetOf(m)
		if err != nil {
			return "", err
		}
		// An empty path is the "/" the origin server would have received.
		if t.path == "" {
			return "/", nil
		}
		return t.path, nil
	case "@query":
		t, err := targetOf(m)
		if err != nil {
			return "", err
		}
		// Section 2.2.7: the whole query string including the leading "?", percent-encoding
		// preserved, and a bare "?" when the request carries no query at all.
		return "?" + t.query, nil
	}
	value, ok := m.headers[item.Name]
	if !ok {
		return "", &Error{
			Kind: KindMissingComponent,
			Message: "The signature covers " + brief(item.spec()) + ", but the message carries no value " +
				"for it, so the signature base cannot be built.",
			Component: item.spec(),
		}
	}
	return value, nil
}

// valueOf is a component's value, refused when it has no single serialization both sides agree
// on. A line break inside a value would forge a line of the base, and a byte outside visible
// ASCII is encoded differently by different stacks, so the KERI profile names such a base
// unbuildable, and so a signature-mismatch (this.i @2f227n4r). A field value is checked as
// received and only then trimmed of SP and HTAB, so a line break at its edge is refused too.
func valueOf(item componentID, m *message) (string, error) {
	value, err := componentValue(item, m)
	if err != nil {
		return "", err
	}
	// Content-Digest keeps its own bound and its own kind, MalformedDigest, checked when it is
	// parsed (this.i @5zrf8gjk); every other field value is bounded here (@524c8qgv).
	field := !strings.HasPrefix(item.Name, "@")
	if err := checkRaw(value, item.spec(), field && item.Name != ContentDigestHeader); err != nil {
		return "", err
	}
	if field {
		value = strings.Trim(value, " \t")
	}
	return value, nil
}

// checkRaw refuses a value holding anything but visible ASCII, SP and HTAB, and, when bounded, a
// value over MaxFieldBytes as received, before anything is trimmed from it. Size is checked before
// shape, so an oversized value is never scanned (this.i @524c8qgv).
func checkRaw(value, spec string, bounded bool) error {
	if bounded && len(value) > MaxFieldBytes {
		return errorf(KindSignatureMismatch, "The value of %s is over %d bytes, so no signature base "+
			"is built from it.", shown(spec), MaxFieldBytes)
	}
	for i := 0; i < len(value); i++ {
		if value[i] != '\t' && (value[i] < ' ' || value[i] > '~') {
			return errorf(KindSignatureMismatch,
				"The value of %s contains a line break, a control character or a non-ASCII "+
					"character, so there is no signature base both sides would build from it.", shown(spec))
		}
	}
	return nil
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

// check refuses what a signer could not serialize faithfully, as the caller's mistake (this.i
// @5zrf8gjk): created and expires are RFC 8941 integers that are not negative, and the strings
// are sf-strings, printable ASCII only, so a line break can never forge a header line. A zero
// created or expires is an absent one.
func (p SignatureParams) check() error {
	for _, n := range []struct {
		name  string
		value int64
	}{{"created", p.Created}, {"expires", p.Expires}} {
		if n.value < 0 || n.value > sfIntegerMax {
			return invalidOptions("%s is %d, and RFC 8941 carries an integer of at most fifteen digits; "+
				"fiki signs one from 0 to 999999999999999.", n.name, n.value)
		}
	}
	for _, s := range []struct{ name, value string }{
		{"keyid", p.Keyid}, {"alg", p.Alg}, {"nonce", p.Nonce}, {"tag", p.Tag},
	} {
		if !isSfString(s.value) {
			return invalidOptions("The %s %s holds a character outside printable ASCII, which an "+
				"RFC 8941 string cannot carry; a line break there would forge a header line.", s.name, shown(s.value))
		}
	}
	return nil
}

func buildBase(items []componentID, m *message, response bool, params SignatureParams) ([]byte, error) {
	if err := params.check(); err != nil {
		return nil, err
	}
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
	m, err := requestMessage(method, rawURL, headers, false)
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
	m, err := responseMessage(status, headers, request, false)
	if err != nil {
		return nil, err
	}
	return buildBase(items, m, true, params)
}

// asciiLower folds A-Z to a-z and nothing else (this.i @524c8qgv). strings.ToLower folds U+212A
// KELVIN SIGN to an ASCII "k", so a field named with it would become a covered name it is not
// (review A6, B5). Byte by byte, so a value that is not UTF-8 is never rewritten either.
func asciiLower(text string) string {
	raw := []byte(text)
	for i, b := range raw {
		if b >= 'A' && b <= 'Z' {
			raw[i] = b + 'a' - 'A'
		}
	}
	return string(raw)
}

// shownMax is the longest stretch of an untrusted value an error message quotes.
const shownMax = 64

// shown is an untrusted value as an error message may quote it: escaped, so no control character
// reaches a log, and cut at 64 characters with its length said, so a 5 MB URL does not make a
// 5 MB message (this.i @524c8qgv, review A9 and B9).
func shown(text string) string {
	count := utf8.RuneCountInString(text)
	if count <= shownMax {
		return strconv.Quote(text)
	}
	end, n := 0, 0
	for end = range text {
		if n == shownMax {
			break
		}
		n++
	}
	return fmt.Sprintf("%s (cut from %d characters)", strconv.Quote(text[:end]), count)
}

// brief is a name as an error message may show it: bare when it is short and printable ASCII, as
// a component identifier or keyid usually is, and otherwise shown, so a name a peer chose cannot
// make a message long or carry a control character into a log (bakobo/fiki#18).
func brief(text string) string {
	if len(text) <= shownMax && isSfString(text) {
		return text
	}
	return shown(text)
}
