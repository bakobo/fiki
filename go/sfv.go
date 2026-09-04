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
// What is deliberately NOT here: decimals, tokens, inner-list items with their own parameters, and
// every field type RFC 9421 never puts in these two headers. A parser that accepts less than the
// spec can only refuse things fiki would not have understood anyway.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// errSyntax is this file's alone and never escapes the package: the parser cannot know WHICH
// header it is reading, and the taxonomy distinguishes an unparsable Signature from an unparsable
// Signature-Input, so callers translate it into the kind that names the header.
var errSyntax = errors.New("structured field syntax")

type param struct {
	Key   string
	Value any // string, int64, bool, or []byte
}

// innerList is a covered-component list with its signature parameters, in the order they arrived.
// Order is load-bearing on the verify side: a verifier that reorders what it received computes a
// different base and rejects a good signature.
type innerList struct {
	Items  []string
	Params []param
}

func (l innerList) param(key string) (any, bool) {
	for _, p := range l.Params {
		if p.Key == key {
			return p.Value, true
		}
	}
	return nil, false
}

type member struct {
	IsList bool
	List   innerList
	Value  any
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

func (c *cursor) skipSpace() {
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
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: a byte sequence must be base64 between colons", errSyntax)
	}
	return raw, nil
}

func (c *cursor) parseInteger() (int64, error) {
	start := c.at
	if c.peek() == '-' {
		c.at++
	}
	for !c.done() && c.peek() >= '0' && c.peek() <= '9' {
		c.at++
	}
	value, err := strconv.ParseInt(c.text[start:c.at], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: expected an integer at offset %d", errSyntax, start)
	}
	return value, nil
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
	case ch == '-' || (ch >= '0' && ch <= '9'):
		return c.parseInteger()
	default:
		return nil, fmt.Errorf("%w: unsupported item at offset %d", errSyntax, c.at)
	}
}

func (c *cursor) parseParameters() ([]param, error) {
	var params []param
	for !c.done() && c.peek() == ';' {
		c.at++
		c.skipSpace()
		key, err := c.parseKey()
		if err != nil {
			return nil, err
		}
		if !c.done() && c.peek() == '=' {
			c.at++
			value, err := c.parseBareItem()
			if err != nil {
				return nil, err
			}
			params = append(params, param{Key: key, Value: value})
			continue
		}
		params = append(params, param{Key: key, Value: true})
	}
	return params, nil
}

func (c *cursor) parseInnerList() (innerList, error) {
	var list innerList
	c.at++ // the opening parenthesis
	for {
		c.skipSpace()
		if c.done() {
			return list, fmt.Errorf("%w: an inner list ran to the end of the field", errSyntax)
		}
		if c.peek() == ')' {
			c.at++
			break
		}
		item, err := c.parseBareItem()
		if err != nil {
			return list, err
		}
		text, ok := item.(string)
		if !ok {
			return list, fmt.Errorf("%w: fiki's covered components are strings", errSyntax)
		}
		// RFC 9421 never puts parameters on the members of a covered-component list, and
		// accepting them would mean carrying a shape nothing here can render back.
		if !c.done() && c.peek() == ';' {
			return list, fmt.Errorf("%w: parameters on a covered component", errSyntax)
		}
		if !c.done() && c.peek() != ' ' && c.peek() != ')' {
			return list, fmt.Errorf("%w: expected a space or ) at offset %d", errSyntax, c.at)
		}
		list.Items = append(list.Items, text)
	}
	params, err := c.parseParameters()
	if err != nil {
		return list, err
	}
	list.Params = params
	return list, nil
}

// parseDictionary reads an RFC 8941 dictionary whose members are inner lists or bare items.
// Order is preserved because RFC 9421's verify side depends on it.
func parseDictionary(text string) ([]string, map[string]member, error) {
	c := &cursor{text: text}
	order := []string{}
	out := map[string]member{}
	c.skipSpace()
	for !c.done() {
		key, err := c.parseKey()
		if err != nil {
			return nil, nil, err
		}
		var m member
		if !c.done() && c.peek() == '=' {
			c.at++
			if c.peek() == '(' {
				list, err := c.parseInnerList()
				if err != nil {
					return nil, nil, err
				}
				m = member{IsList: true, List: list}
			} else {
				value, err := c.parseBareItem()
				if err != nil {
					return nil, nil, err
				}
				params, err := c.parseParameters()
				if err != nil {
					return nil, nil, err
				}
				m = member{Value: value, List: innerList{Params: params}}
			}
		} else {
			params, err := c.parseParameters()
			if err != nil {
				return nil, nil, err
			}
			m = member{Value: true, List: innerList{Params: params}}
		}
		if _, seen := out[key]; !seen {
			order = append(order, key)
		}
		out[key] = m
		c.skipSpace()
		if c.done() {
			break
		}
		if err := c.expect(','); err != nil {
			return nil, nil, err
		}
		c.skipSpace()
		if c.done() {
			return nil, nil, fmt.Errorf("%w: a dictionary ended with a trailing comma", errSyntax)
		}
	}
	return order, out, nil
}

func serializeBareItem(value any) string {
	switch v := value.(type) {
	case string:
		return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
	case int64:
		return strconv.FormatInt(v, 10)
	default:
		// Only false reaches here: RFC 8941 renders a true-valued parameter as a bare key, which
		// serializeParameters does before calling this, and fiki never puts a boolean in an item
		// position. A "?1" arm would be unreachable.
		return "?0"
	}
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
	for i, item := range list.Items {
		quoted[i] = serializeBareItem(item)
	}
	return "(" + strings.Join(quoted, " ") + ")" + serializeParameters(list.Params)
}
