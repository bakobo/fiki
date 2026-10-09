package fiki

// The httpwg structured-field-tests corpus, vendored at vectors/third_party (`this.i` @7fexwu3s),
// run against this port's RFC 8941 parser.
//
// The corpus is written by RFC 8941's authors and is independent of fiki, so where this parser
// disagrees with it the parser is wrong, except where a recorded fiki decision says otherwise.
// Those exceptions are the only ones, and each is named below: RFC 9651's Dates and Display
// Strings are refused (@7vdhfv3q), fiki's input bounds are refused (@5zrf8gjk), a byte sequence
// whose padding is missing, partial or excessive is refused (@2g4xxev9), and the entry point
// refuses a field that is empty after OWS (review B7, pinned by vectors/refusals.json).
//
// Entry points. A dictionary case runs through parseField, the bounded entry point VerifyRequest
// reads Signature-Input through, which measures MaxFieldBytes and whose parser counts
// MaxDictionaryMembers, MaxInnerListItems and MaxParameters. A list or item case runs through
// parseList or parseItem behind the same MaxFieldBytes check, and the parser applies the
// inner-list and parameter bounds there as it does in a dictionary, and MaxDictionaryMembers to a
// list's members, as the other five ports do.

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var corpusDir = filepath.Join("..", "vectors", "third_party", "structured-field-tests")

// corpusCounts pins every file's case count, read once from the corpus at 00462dd when this test
// was written. A corpus refresh that adds, drops or empties a file fails here rather than quietly
// changing what is covered; no case in any file is skipped.
var corpusCounts = map[string]int{
	"binary.json":           17,
	"boolean.json":          12,
	"date.json":             17,
	"dictionary.json":       26,
	"display-string.json":   22,
	"examples.json":         21,
	"item.json":             5,
	"key-generated.json":    640,
	"large-generated.json":  11,
	"list.json":             11,
	"listlist.json":         12,
	"number-generated.json": 193,
	"number.json":           37,
	"param-dict.json":       14,
	"param-list.json":       20,
	"param-listlist.json":   3,
	"string-generated.json": 256,
	"string.json":           14,
	"token-generated.json":  256,
	"token.json":            6,
}

// corpusFikiWay is every case fiki answers differently from the corpus for a reason other than the
// two rules applied to every case (RFC 9651 types and the bounds), with the decision behind it.
// A can_fail case is always here, because fiki's decisions dictate one outcome for each of them.
var corpusFikiWay = map[string]struct {
	refused bool
	why     string
}{
	"binary.json/unpadded":          {true, "@2g4xxev9: missing padding is refused"},
	"binary.json/partially padded":  {true, "@2g4xxev9: partial padding is refused"},
	"binary.json/extra padding":     {true, "@2g4xxev9: padding beyond the final quantum is refused"},
	"binary.json/non-zero pad bits": {false, "@2g4xxev9: non-zero pad bits are accepted"},
	// can_fail in the corpus because two field lines are joined inside a string; fiki-py's
	// http_sfv reads the joined value as the string "foo, bar", and so does this port.
	"string.json/two lines string": {false, "fiki-py's outcome for a can_fail case: accepted"},
	// Not can_fail: the corpus parses an empty dictionary, and fiki's entry point refuses a
	// signature header that is present but empty after OWS (review B7, pinned at vectors_format 3
	// under @524c8qgv by vectors/refusals.json signature-header-of-spaces), as fiki-py's _parse
	// does through http_sfv.
	"dictionary.json/empty dictionary": {true, "review B7, refusals.json signature-header-of-spaces"},
}

type sfCase struct {
	Name       string          `json:"name"`
	Raw        []string        `json:"raw"`
	HeaderType string          `json:"header_type"`
	Expected   json.RawMessage `json:"expected"`
	MustFail   bool            `json:"must_fail"`
	CanFail    bool            `json:"can_fail"`
	Canonical  []string        `json:"canonical"`
}

func loadCorpus(t testing.TB, name string) []sfCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusDir, name))
	if err != nil {
		t.Fatalf("the httpwg corpus is not where every port reaches it: %v", err)
	}
	var cases []sfCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return cases
}

// decodeExpected keeps every number's literal, so 1.0 is a decimal and 1 an integer: a loader
// that reads both as a float cannot tell them apart.
func decodeExpected(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatalf("expected value: %v", err)
	}
	return v
}

// The corpus's expected values and this parser's results are both rendered into one notation,
// so a comparison covers the type of every value, the order of members and parameters, and
// nothing else. An integer is i:, a decimal d: at three fractional digits, a string q:, a token t:,
// a byte sequence b: in hex, a boolean ?0 or ?1.

func renderDecimal(text string) string {
	r, ok := new(big.Rat).SetString(text)
	if !ok {
		panic("not a decimal: " + text)
	}
	return "d:" + r.FloatString(3)
}

func renderGotBare(v any) string {
	switch v := v.(type) {
	case int64:
		return "i:" + strconv.FormatInt(v, 10)
	case sfDecimal:
		return renderDecimal(string(v))
	case string:
		return "q:" + strconv.Quote(v)
	case sfToken:
		return "t:" + string(v)
	case []byte:
		return fmt.Sprintf("b:%x", v)
	case bool:
		if v {
			return "?1"
		}
		return "?0"
	}
	return fmt.Sprintf("unknown %T", v)
}

func renderGotParams(params []param) string {
	var out strings.Builder
	for _, p := range params {
		out.WriteString(";" + p.Key + "=" + renderGotBare(p.Value))
	}
	return out.String()
}

func renderGotMember(m member) string {
	if !m.IsList {
		return renderGotBare(m.Value) + renderGotParams(m.List.Params)
	}
	items := make([]string, len(m.List.Items))
	for i, it := range m.List.Items {
		items[i] = renderGotBare(it.Value) + renderGotParams(it.Params)
	}
	return "(" + strings.Join(items, " ") + ")" + renderGotParams(m.List.Params)
}

// rfc9651 is set when an expected value uses a type RFC 9651 added, which fiki refuses (@7vdhfv3q).
type rendering struct{ rfc9651 bool }

func (r *rendering) bare(t *testing.T, v any) string {
	switch v := v.(type) {
	case json.Number:
		if strings.ContainsAny(string(v), ".eE") {
			return renderDecimal(string(v))
		}
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			t.Fatalf("integer %s: %v", v, err)
		}
		return "i:" + strconv.FormatInt(n, 10)
	case string:
		return "q:" + strconv.Quote(v)
	case bool:
		if v {
			return "?1"
		}
		return "?0"
	case map[string]any:
		value, _ := v["value"].(string)
		switch v["__type"] {
		case "token":
			return "t:" + value
		case "binary":
			raw, err := base32.StdEncoding.DecodeString(value)
			if err != nil {
				t.Fatalf("binary %q: %v", value, err)
			}
			return fmt.Sprintf("b:%x", raw)
		case "date", "displaystring":
			r.rfc9651 = true
			return "rfc9651"
		}
	}
	t.Fatalf("an expected bare item fiki cannot read: %#v", v)
	return ""
}

func (r *rendering) params(t *testing.T, v any) (string, int) {
	list := v.([]any)
	var out strings.Builder
	for _, p := range list {
		pair := p.([]any)
		out.WriteString(";" + pair[0].(string) + "=" + r.bare(t, pair[1]))
	}
	return out.String(), len(list)
}

// shape is what an expected value says about fiki's bounds, so a case can be refused for
// exceeding one without trusting the parser under test to say so.
type shape struct{ innerItems, params int }

func (s *shape) see(innerItems, params int) {
	s.innerItems = max(s.innerItems, innerItems)
	s.params = max(s.params, params)
}

// member renders an [item-or-inner-list, params] pair; an inner list's value is a JSON array.
func (r *rendering) member(t *testing.T, v any, s *shape) string {
	pair := v.([]any)
	params, n := r.params(t, pair[1])
	inner, isList := pair[0].([]any)
	if !isList {
		s.see(0, n)
		return r.bare(t, pair[0]) + params
	}
	items := make([]string, len(inner))
	for i, it := range inner {
		ip := it.([]any)
		ps, pn := r.params(t, ip[1])
		s.see(0, pn)
		items[i] = r.bare(t, ip[0]) + ps
	}
	s.see(len(inner), n)
	return "(" + strings.Join(items, " ") + ")" + params
}

// expectation is what the corpus says a successful parse renders as, and whether fiki refuses the
// case by one of the rules every case is held to, before any per-case exception.
type expectation struct {
	rendered string
	rfc9651  bool
	overSize bool
}

func expect(t *testing.T, c sfCase, joined string) expectation {
	var r rendering
	var s shape
	v := decodeExpected(t, c.Expected)
	var rendered string
	members := 0
	switch c.HeaderType {
	case "item":
		rendered = r.member(t, v, &s)
	case "list":
		parts := []string{}
		for _, m := range v.([]any) {
			parts = append(parts, r.member(t, m, &s))
		}
		members = len(parts)
		rendered = "[" + strings.Join(parts, ", ") + "]"
	case "dictionary":
		parts := []string{}
		for _, kv := range v.([]any) {
			pair := kv.([]any)
			parts = append(parts, pair[0].(string)+"="+r.member(t, pair[1], &s))
		}
		members = len(parts)
		rendered = "{" + strings.Join(parts, ", ") + "}"
	}
	over := len(joined) > MaxFieldBytes || members > MaxDictionaryMembers ||
		s.innerItems > MaxInnerListItems || s.params > MaxParameters
	return expectation{rendered: rendered, rfc9651: r.rfc9651, overSize: over}
}

// boundedList and boundedItem are the list and item entry points: MaxFieldBytes on the combined
// value, then the parser, which applies the inner-list and parameter bounds as it reads.
func boundedList(raw string) ([]member, error) {
	if len(raw) > MaxFieldBytes {
		return nil, fmt.Errorf("%w: the field is over %d bytes", errSyntax, MaxFieldBytes)
	}
	return parseList(raw)
}

func boundedItem(raw string) (item, error) {
	if len(raw) > MaxFieldBytes {
		return item{}, fmt.Errorf("%w: the field is over %d bytes", errSyntax, MaxFieldBytes)
	}
	return parseItem(raw)
}

// parseCorpus runs one case through its entry point and renders what came back. A refusal must be
// the entry point's own malformed error; anything else fails the test.
func parseCorpus(t *testing.T, headerType, raw string) (string, bool) {
	t.Helper()
	switch headerType {
	case "dictionary":
		order, members, err := parseField(raw, "Signature-Input", KindMalformedSignatureInput)
		if err != nil {
			var fe *Error
			if !errors.As(err, &fe) || fe.Kind != KindMalformedSignatureInput {
				t.Fatalf("a refusal that is not MalformedSignatureInput: %v", err)
			}
			return "", false
		}
		parts := make([]string, len(order))
		for i, key := range order {
			parts[i] = key + "=" + renderGotMember(members[key])
		}
		return "{" + strings.Join(parts, ", ") + "}", true
	case "list":
		members, err := boundedList(raw)
		if err != nil {
			if !errors.Is(err, errSyntax) {
				t.Fatalf("a refusal that is not a syntax error: %v", err)
			}
			return "", false
		}
		parts := make([]string, len(members))
		for i, m := range members {
			parts[i] = renderGotMember(m)
		}
		return "[" + strings.Join(parts, ", ") + "]", true
	case "item":
		it, err := boundedItem(raw)
		if err != nil {
			if !errors.Is(err, errSyntax) {
				t.Fatalf("a refusal that is not a syntax error: %v", err)
			}
			return "", false
		}
		return renderGotBare(it.Value) + renderGotParams(it.Params), true
	}
	t.Fatalf("a header_type fiki does not know: %q", headerType)
	return "", false
}

func TestTheHttpwgCorpus(t *testing.T) {
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			files = append(files, e.Name())
		}
	}
	var pinned []string
	for name := range corpusCounts {
		pinned = append(pinned, name)
	}
	slices.Sort(pinned)
	if !slices.Equal(files, pinned) {
		t.Fatalf("the corpus holds %v, and this test pins %v", files, pinned)
	}

	usedExceptions := map[string]bool{}
	total := 0
	for _, file := range files {
		cases := loadCorpus(t, file)
		ran := 0
		for _, c := range cases {
			id := file + "/" + c.Name
			t.Run(id, func(t *testing.T) {
				joined := strings.Join(c.Raw, ", ")
				got, ok := parseCorpus(t, c.HeaderType, joined)

				exception, excepted := corpusFikiWay[id]
				var want expectation
				if !c.MustFail {
					want = expect(t, c, joined)
				}
				// RFC 9651's types decide a can_fail Date or Display String: refused.
				if c.CanFail && !excepted && !want.rfc9651 {
					t.Fatalf("a can_fail case with no outcome decided for fiki")
				}
				refuse := c.MustFail || want.rfc9651 || want.overSize
				if (file == "date.json" || file == "display-string.json") && !refuse {
					t.Fatalf("an RFC 9651 case fiki would not refuse")
				}
				if excepted {
					usedExceptions[id] = true
					refuse = exception.refused
				}
				switch {
				case refuse && ok:
					t.Errorf("fiki refuses %.300q, and this port parsed it as %.300s", joined, got)
				case !refuse && !ok:
					t.Errorf("the corpus parses %.300q as %.300s, and this port refused it", joined, want.rendered)
				case !refuse && got != want.rendered:
					t.Errorf("%.300q parsed as %.300s, and the corpus says %.300s", joined, got, want.rendered)
				}
			})
			ran++
		}
		if ran != corpusCounts[file] || len(cases) != corpusCounts[file] {
			t.Errorf("%s: %d cases held, %d run, %d pinned, 0 skipped", file, len(cases), ran, corpusCounts[file])
		}
		total += ran
	}
	if total != 1593 {
		t.Errorf("ran %d corpus parse cases, and 1593 are pinned", total)
	}
	for id := range corpusFikiWay {
		if !usedExceptions[id] {
			t.Errorf("an exception for %s, which the corpus no longer holds", id)
		}
	}
}

// The serialisation subset, through the public signing API. Every case it runs is one the corpus
// says must not serialize, so each must be refused before anything is signed.
func TestTheHttpwgSerialisationCases(t *testing.T) {
	key := testKey(t)
	sign := func(opts SignOptions, covered ...string) error {
		if covered != nil {
			opts.Covered = covered
		}
		if opts.Created == 0 {
			opts.Created = 1700000000
		}
		_, err := SignRequest(key, "GET", "https://api.example.com/x", map[string]string{}, opts)
		return err
	}
	ran := map[string]int{}

	// A key is refused as a label, the caller's mistake; and as a covered component's parameter
	// key, where both this port and fiki-py report UnsupportedComponent: the spec string is read as
	// an RFC 8941 serialization, and one that does not read as one is a component fiki cannot name.
	for _, c := range loadCorpus(t, filepath.Join("serialisation-tests", "key-generated.json")) {
		if !c.MustFail {
			t.Fatalf("%s: a key the corpus serializes", c.Name)
		}
		v := decodeExpected(t, c.Expected).([]any)[0].([]any)
		k, _ := v[0].(string)
		if c.HeaderType == "list" {
			k = v[1].([]any)[0].([]any)[0].(string)
		}
		err := sign(SignOptions{Label: k})
		if !errors.Is(err, ErrInvalidOptions) || !strings.Contains(err.Error(), "is not an RFC 8941 key") {
			t.Errorf("%s: label %q gave %v", c.Name, k, err)
		}
		err = sign(SignOptions{}, "@method", `"@path";`+k)
		var fe *Error
		if !errors.As(err, &fe) || fe.Kind != KindUnsupportedComponent {
			t.Errorf("%s: parameter key %q gave %v", c.Name, k, err)
		}
		ran["key"]++
	}

	for _, c := range loadCorpus(t, filepath.Join("serialisation-tests", "string-generated.json")) {
		if !c.MustFail {
			t.Fatalf("%s: a string the corpus serializes", c.Name)
		}
		s := decodeExpected(t, c.Expected).([]any)[0].(string)
		for _, opts := range []SignOptions{{Keyid: s}, {Nonce: s}, {Tag: s}} {
			err := sign(opts)
			if !errors.Is(err, ErrInvalidOptions) || !strings.Contains(err.Error(), "outside printable ASCII") {
				t.Errorf("%s: %q gave %v", c.Name, s, err)
			}
		}
		ran["string"]++
	}

	// Created is an int64, so the two too-big decimals have no Go spelling and are skipped: the
	// type system refuses them before fiki is called.
	skipped := 0
	for _, c := range loadCorpus(t, filepath.Join("serialisation-tests", "number.json")) {
		if !strings.HasPrefix(c.Name, "too big") {
			continue
		}
		n := decodeExpected(t, c.Expected).([]any)[0].(json.Number)
		created, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil {
			skipped++
			continue
		}
		err = sign(SignOptions{Created: created})
		if !c.MustFail || !errors.Is(err, ErrInvalidOptions) || !strings.Contains(err.Error(), "fiki signs one from 0 to 999999999999999") {
			t.Errorf("%s: created %d gave %v", c.Name, created, err)
		}
		ran["number"]++
	}

	if ran["key"] != 378 || ran["string"] != 33 || ran["number"] != 2 || skipped != 2 {
		t.Errorf("ran %v and skipped %d, and 378 key, 33 string and 2 number cases are pinned, with 2 skipped", ran, skipped)
	}
}

// The corpus has no item whose parameters fail to parse, so this one is named.
func TestAnItemWhoseParametersAreMalformedIsRefused(t *testing.T) {
	for _, raw := range []string{"1;", "1;A=2", `"a";b="\x"`} {
		if _, err := parseItem(raw); !errors.Is(err, errSyntax) {
			t.Errorf("%q: %v", raw, err)
		}
	}
}
