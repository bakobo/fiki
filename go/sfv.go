package fiki

// The RFC 8941 subset RFC 9421 actually uses (`this.i` @2q9gv70t, @2tt6fmc0).
//
// Hand-rolled rather than depended upon, for the reason every port hand-rolls it: fiki's slice of
// structured fields is small and CLOSED — a dictionary whose members are inner lists of strings
// with parameters, plus byte sequences — and the shared vectors pin its entire output surface byte
// for byte. The usual argument against writing your own parser holds where the grammar is
// open-ended; this one is a few hundred lines whose every output is checked against committed
// bytes shared with four other implementations.
//
// What is deliberately NOT here: inner lists nested in parameters, and every field type RFC 9421
// never puts in these two headers. A parser that accepts less than the spec can only refuse things
// fiki would not have understood anyway. Tokens and decimals ARE read, though fiki never accepts
// one anywhere it matters, so that a header carrying one is refused for what it means — an
// unsupported component parameter, an unknown signature parameter — rather than as unparsable,
// which is the refusal fiki-py gives it (`this.i` @9z57sejw).

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Input bounds (`this.i` @5zrf8gjk, ticks 65q7 and 6mhg), far above anything an honest signer sends
// and low enough that no parse is slow. Each of Signature, Signature-Input and Content-Digest is
// measured in bytes as received, before it is trimmed or parsed, so size is checked before shape;
// the counts apply to every dictionary, inner list and item in all three. Over any of them is the
// malformed kind of the header being read.
const (
	MaxFieldBytes        = 8192
	MaxDictionaryMembers = 16
	MaxInnerListItems    = 64
	MaxParameters        = 16
)

// errSyntax is this file's alone and never escapes the package: the parser cannot know WHICH
// header it is reading, and the taxonomy distinguishes an unparsable Signature from an unparsable
// Signature-Input, so callers translate it into the kind that names the header.
var errSyntax = errors.New("structured field syntax")

type param struct {
	Key   string
	Value any // string, int64, bool, []byte, token, or decimal
}

// sfToken and sfDecimal keep the two bare-item types fiki never acts on distinct from a string, so
// that they serialize back as they arrived. A decimal is kept as its own text.
type (
	sfToken   string
	sfDecimal string
)

// item is a bare item with its parameters, as an inner list carries it.
type item struct {
	Value  any
	Params []param
}

// innerList is a covered-component list with its signature parameters, in the order they arrived.
// Order is load-bearing on the verify side: a verifier that reorders what it received computes a
// different base and rejects a good signature.
type innerList struct {
	Items  []item
	Params []param
}

func (l innerList) param(key string) (any, bool) { return paramValue(l.Params, key) }

type member struct {
	IsList bool
	List   innerList
	Value  any
}

// paramValue is the value a parameter list gives key, and whether it gives one at all.
func paramValue(params []param, key string) (any, bool) {
	for _, p := range params {
		if p.Key == key {
			return p.Value, true
		}
	}
	return nil, false
}

type cursor struct {
	text string
	at   int
}

func (c *cursor) done() bool { return c.at >= len(c.text) }

func (c *cursor) peek() byte {
	if c.done() {
		return 0
	}
	return c.text[c.at]
}

// skipSP discards SP, the only whitespace RFC 8941 allows inside an inner list, after a
// parameter's semicolon, and at the start of a field (sections 3.1.1, 3.1.2 and 4.2, this.i
// @524c8qgv). An HTAB there is malformed.
func (c *cursor) skipSP() {
	for !c.done() && c.peek() == ' ' {
		c.at++
	}
}

// skipOWS discards SP and HTAB, which RFC 8941 section 4.2.2 allows around a dictionary's comma
// and after its last member.
func (c *cursor) skipOWS() {
	for !c.done() && (c.peek() == ' ' || c.peek() == '\t') {
		c.at++
	}
}

func (c *cursor) expect(ch byte) error {
	if c.done() || c.peek() != ch {
		return fmt.Errorf("%w: expected %q at offset %d", errSyntax, ch, c.at)
	}
	c.at++
	return nil
}

func isKeyStart(b byte) bool { return (b >= 'a' && b <= 'z') || b == '*' }

func isKeyChar(b byte) bool {
	return isKeyStart(b) || (b >= '0' && b <= '9') || b == '_' || b == '-' || b == '.'
}

func (c *cursor) parseKey() (string, error) {
	if c.done() || !isKeyStart(c.peek()) {
		return "", fmt.Errorf("%w: a key starts with a lowercase letter or *", errSyntax)
	}
	start := c.at
	for !c.done() && isKeyChar(c.peek()) {
		c.at++
	}
	return c.text[start:c.at], nil
}

// parseString, parseByteSequence and parseInnerList each consume their opening delimiter without
// checking it: every call site is parseBareItem or parseDictionary switching on that exact byte,
// so a check could not fail. Guards that cannot fire read as safety and are not.
func (c *cursor) parseString() (string, error) {
	c.at++ // the opening quote
	var out strings.Builder
	for !c.done() {
		ch := c.text[c.at]
		c.at++
		switch ch {
		case '\\':
			if c.done() {
				return "", fmt.Errorf("%w: a string ended mid-escape", errSyntax)
			}
			esc := c.text[c.at]
			c.at++
			if esc != '"' && esc != '\\' {
				return "", fmt.Errorf("%w: only \\\" and \\\\ may be escaped", errSyntax)
			}
			out.WriteByte(esc)
		case '"':
			return out.String(), nil
		default:
			// RFC 8941 section 3.3.3: visible ASCII and space only, so a line break can never
			// travel inside a string into a line of the signature base.
			if ch < ' ' || ch > '~' {
				return "", fmt.Errorf("%w: a string carries a byte outside visible ASCII", errSyntax)
			}
			out.WriteByte(ch)
		}
	}
	return "", fmt.Errorf("%w: a string ran to the end of the field", errSyntax)
}

func (c *cursor) parseByteSequence() ([]byte, error) {
	c.at++ // the opening colon
	start := c.at
	for !c.done() && c.peek() != ':' {
		c.at++
	}
	encoded := c.text[start:c.at]
	if err := c.expect(':'); err != nil {
		return nil, err
	}
	// Go's decoder skips CR and LF wherever they are, so the alphabet is checked first: a byte
	// sequence holds base64 and its padding, and nothing else (this.i @5zrf8gjk). The decoder
	// itself refuses padding that is missing, incomplete or anywhere but the end.
	if strings.TrimLeft(encoded, base64Alphabet) != "" {
		return nil, fmt.Errorf("%w: a byte sequence holds a character outside base64", errSyntax)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: a byte sequence must be base64 between colons", errSyntax)
	}
	return raw, nil
}

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// parseNumber reads an RFC 8941 integer, or a decimal kept as its text.
func (c *cursor) parseNumber() (any, error) {
	start := c.at
	if c.peek() == '-' {
		c.at++
	}
	digits := c.at
	for !c.done() && isDigit(c.peek()) {
		c.at++
	}
	if c.peek() == '.' && c.at > digits && c.at-digits <= 12 {
		c.at++
		fraction := c.at
		for !c.done() && isDigit(c.peek()) {
			c.at++
		}
		if c.at == fraction || c.at-fraction > 3 {
			return nil, fmt.Errorf("%w: a decimal has one to three fractional digits", errSyntax)
		}
		return sfDecimal(c.text[start:c.at]), nil
	}
	if c.at == digits || c.at-digits > 15 {
		return nil, fmt.Errorf("%w: expected an integer at offset %d", errSyntax, start)
	}
	value, _ := strconv.ParseInt(c.text[start:c.at], 10, 64) // at most 15 digits: cannot overflow
	return value, nil
}

func isTokenChar(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		strings.IndexByte("!#$%&'*+-.^_`|~:/", b) >= 0
}

func (c *cursor) parseToken() sfToken {
	start := c.at
	for !c.done() && isTokenChar(c.peek()) {
		c.at++
	}
	return sfToken(c.text[start:c.at])
}

func (c *cursor) parseBareItem() (any, error) {
	switch ch := c.peek(); {
	case ch == '"':
		return c.parseString()
	case ch == ':':
		return c.parseByteSequence()
	case ch == '?':
		c.at++
		if c.done() {
			return nil, fmt.Errorf("%w: a boolean is ?0 or ?1", errSyntax)
		}
		flag := c.text[c.at]
		c.at++
		if flag != '0' && flag != '1' {
			return nil, fmt.Errorf("%w: a boolean is ?0 or ?1", errSyntax)
		}
		return flag == '1', nil
	case ch == '-' || isDigit(ch):
		return c.parseNumber()
	case ch == '*' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'):
		return c.parseToken(), nil
	default:
		return nil, fmt.Errorf("%w: unsupported item at offset %d", errSyntax, c.at)
	}
}

func (c *cursor) parseParameters() ([]param, error) {
	var params []param
	// Where each key sits, so a duplicated key overwrites its first value in place, as RFC 8941
	// section 4.2.3.2 says a parser must, without rescanning every earlier parameter: a scan per
	// parameter made a long Signature-Input cost quadratic time before it was refused
	// (bakobo/fiki#6). A duplicated parameter therefore cannot smuggle a second value past a
	// check that reads the first.
	at := map[string]int{}
	for !c.done() && c.peek() == ';' {
		c.at++
		c.skipSP()
		key, err := c.parseKey()
		if err != nil {
			return nil, err
		}
		var value any = true
		if !c.done() && c.peek() == '=' {
			c.at++
			if value, err = c.parseBareItem(); err != nil {
				return nil, err
			}
		}
		if i, seen := at[key]; seen {
			params[i].Value = value
			continue
		}
		if len(params) == MaxParameters {
			return nil, fmt.Errorf("%w: an item carries more than %d parameters", errSyntax, MaxParameters)
		}
		at[key] = len(params)
		params = append(params, param{Key: key, Value: value})
	}
	return params, nil
}

func (c *cursor) parseInnerList() (innerList, error) {
	var list innerList
	c.at++ // the opening parenthesis
	for {
		c.skipSP()
		if c.done() {
			return list, fmt.Errorf("%w: an inner list ran to the end of the field", errSyntax)
		}
		if c.peek() == ')' {
			c.at++
			break
		}
		value, err := c.parseBareItem()
		if err != nil {
			return list, err
		}
		// Parameters on a covered component are read, not refused here: "@path";req is how a
		// response names its request's path, and any other parameter is refused by name later,
		// as an unsupported component rather than as an unparsable header.
		params, err := c.parseParameters()
		if err != nil {
			return list, err
		}
		if !c.done() && c.peek() != ' ' && c.peek() != ')' {
			return list, fmt.Errorf("%w: expected a space or ) at offset %d", errSyntax, c.at)
		}
		if len(list.Items) == MaxInnerListItems {
			return list, fmt.Errorf("%w: an inner list holds more than %d items", errSyntax, MaxInnerListItems)
		}
		list.Items = append(list.Items, item{Value: value, Params: params})
	}
	params, err := c.parseParameters()
	if err != nil {
		return list, err
	}
	list.Params = params
	return list, nil
}

// parseMember reads what a list member or a dictionary member's value is: an inner list, or a bare
// item, each with its parameters.
func (c *cursor) parseMember() (member, error) {
	if c.peek() == '(' {
		list, err := c.parseInnerList()
		return member{IsList: true, List: list}, err
	}
	value, err := c.parseBareItem()
	if err != nil {
		return member{}, err
	}
	params, err := c.parseParameters()
	return member{Value: value, List: innerList{Params: params}}, err
}

// nextMember steps over the comma between two members of a list or a dictionary, with the OWS
// around it, and reports whether the field has ended instead (RFC 8941 sections 4.2.1 and 4.2.2).
func (c *cursor) nextMember(what string) (bool, error) {
	c.skipOWS()
	if c.done() {
		return true, nil
	}
	if err := c.expect(','); err != nil {
		return false, err
	}
	c.skipOWS()
	if c.done() {
		return false, fmt.Errorf("%w: a %s ended with a trailing comma", errSyntax, what)
	}
	return false, nil
}

// parseDictionary reads an RFC 8941 dictionary whose members are inner lists or bare items.
// Order is preserved because RFC 9421's verify side depends on it.
func parseDictionary(text string) ([]string, map[string]member, error) {
	c := &cursor{text: text}
	order := []string{}
	out := map[string]member{}
	c.skipSP()
	for !c.done() {
		key, err := c.parseKey()
		if err != nil {
			return nil, nil, err
		}
		m := member{Value: true}
		if !c.done() && c.peek() == '=' {
			c.at++
			m, err = c.parseMember()
		} else {
			m.List.Params, err = c.parseParameters()
		}
		if err != nil {
			return nil, nil, err
		}
		if _, seen := out[key]; !seen {
			if len(order) == MaxDictionaryMembers {
				return nil, nil, fmt.Errorf("%w: a dictionary holds more than %d members", errSyntax, MaxDictionaryMembers)
			}
			order = append(order, key)
		}
		out[key] = m
		if end, err := c.nextMember("dictionary"); end || err != nil {
			return order, out, err
		}
	}
	return order, out, nil
}

// parseList reads an RFC 8941 list (section 4.2.1). No header fiki reads is a list; it is here so
// that the httpwg corpus (this.i @7fexwu3s) can hold the parser's every piece to the grammar, and
// so that the fuzz target reaches every piece.
func parseList(text string) ([]member, error) {
	c := &cursor{text: text}
	members := []member{}
	c.skipSP()
	for !c.done() {
		m, err := c.parseMember()
		if err != nil {
			return nil, err
		}
		members = append(members, m)
		if end, err := c.nextMember("list"); end || err != nil {
			return members, err
		}
	}
	return members, nil
}

// parseItem reads an RFC 8941 item (section 4.2.3), for the same reason parseList exists. Only SP
// may surround it.
func parseItem(text string) (item, error) {
	c := &cursor{text: text}
	c.skipSP()
	value, err := c.parseBareItem()
	if err != nil {
		return item{}, err
	}
	params, err := c.parseParameters()
	if err != nil {
		return item{}, err
	}
	c.skipSP()
	if !c.done() {
		return item{}, fmt.Errorf("%w: unexpected text after an item at offset %d", errSyntax, c.at)
	}
	return item{Value: value, Params: params}, nil
}

func serializeBareItem(value any) string {
	switch v := value.(type) {
	case string:
		return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
	case int64:
		return strconv.FormatInt(v, 10)
	case sfToken:
		return string(v)
	case sfDecimal:
		return string(v)
	case []byte:
		return ":" + base64.StdEncoding.EncodeToString(v) + ":"
	case bool:
		if v {
			return "?1"
		}
		return "?0"
	}
	panic(fmt.Sprintf("fiki: no RFC 8941 serialization for %T", value)) // a bug in fiki, not input
}

func serializeParameters(params []param) string {
	var out strings.Builder
	for _, p := range params {
		if b, ok := p.Value.(bool); ok && b {
			out.WriteString(";" + p.Key)
			continue
		}
		out.WriteString(";" + p.Key + "=" + serializeBareItem(p.Value))
	}
	return out.String()
}

// serializeInnerList renders a covered-component list with its signature parameters.
func serializeInnerList(list innerList) string {
	quoted := make([]string, len(list.Items))
	for i, member := range list.Items {
		quoted[i] = serializeBareItem(member.Value) + serializeParameters(member.Params)
	}
	return "(" + strings.Join(quoted, " ") + ")" + serializeParameters(list.Params)
}
