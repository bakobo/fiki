package fiki

// A deterministic, seeded mutation test of the RFC 8941 parser and VerifyRequest (tick 7xbw), and
// a native fuzz target over the same check for `go test -fuzz`.
//
// The seeds are the httpwg corpus's inputs and the Signature-Input and Signature values of the
// shared accept and refusal vectors. Mutation works on bytes, with an alphabet that leans on what
// has broken parsers before: RFC 8941's delimiters, HTAB, non-ASCII, the C1 controls and U+2028.
// Every mutant is fed twice: as Go hands it over, which may be invalid UTF-8, and after lossy
// decoding, which never drops a mutant for being invalid.
//
// From a parser the only allowed outcomes are a value or its malformed error; from VerifyRequest,
// a verdict or an *Error, never ErrInvalidOptions, because the policy is a valid one and only wire
// input varies, and never a panic. A refusal's message holds no control character.

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// xorshift is Marsaglia's xorshift64, so the run is the same on every machine and Go release.
type xorshift uint64

func (x *xorshift) next() uint64 {
	v := uint64(*x)
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	*x = xorshift(v)
	return v
}

func (x *xorshift) below(n int) int { return int(x.next() % uint64(n)) }

var fuzzAlphabet = []string{
	`"`, `(`, `)`, `:`, `;`, `=`, `,`, `?`, `*`, `\`, ` `, "\t", "@", "%", "-", ".", "0", "9", "a",
	"z", "A", "=", "+", "/", "\r", "\n", "\x00", "\x7f",
	"é", "�", "\U0001f600", " ", " ",
	"\u0080", "\u0085", "\u009b", "\u009f",
	"\xc2", "\xe2\x80", "\xff", // fragments of UTF-8, which only the raw feed carries
}

func mutate(r *xorshift, seed string, seeds []string) []byte {
	b := []byte(seed)
	for range 1 + r.below(4) {
		switch r.below(6) {
		case 0: // flip a byte to any value
			if len(b) > 0 {
				b[r.below(len(b))] = byte(r.next())
			}
		case 1: // insert from the alphabet
			at := r.below(len(b) + 1)
			b = append(b[:at], append([]byte(fuzzAlphabet[r.below(len(fuzzAlphabet))]), b[at:]...)...)
		case 2: // delete a run
			if len(b) > 0 {
				at := r.below(len(b))
				end := min(len(b), at+1+r.below(8))
				b = append(b[:at], b[end:]...)
			}
		case 3: // truncate
			b = b[:r.below(len(b)+1)]
		case 4: // splice in a piece of another seed
			other := seeds[r.below(len(seeds))]
			from := r.below(len(other) + 1)
			piece := other[from : from+r.below(len(other)-from+1)]
			at := r.below(len(b) + 1)
			b = append(b[:at], append([]byte(piece), b[at:]...)...)
		case 5: // replace a byte with one from the alphabet
			if len(b) > 0 {
				at := r.below(len(b))
				b = append(b[:at], append([]byte(fuzzAlphabet[r.below(len(fuzzAlphabet))]), b[at+1:]...)...)
			}
		}
	}
	return b
}

// fuzzTarget is a vector request whose policy is valid, so only its wire input can fail it.
type fuzzTarget struct {
	c    requestCase
	opts VerifyOptions
}

// fuzzTargets reads the vectors in a fixed order, since the run must be the same every time.
func fuzzTargets(t *testing.T) ([]fuzzTarget, []string) {
	var targets []fuzzTarget
	var seeds []string
	for _, name := range []string{"accepts.json", "refusals.json"} {
		var file struct{ Cases []requestCase }
		load(t, name, &file)
		for _, c := range file.Cases {
			opts, err := c.options(t)
			if err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			targets = append(targets, fuzzTarget{c, opts})
			for _, k := range sortedKeys(c.Headers) {
				if lower := strings.ToLower(k); lower == "signature" || lower == "signature-input" {
					seeds = append(seeds, c.Headers[k])
				}
			}
		}
	}
	return targets, seeds
}

func corpusSeeds(t testing.TB) []string {
	var seeds []string
	for _, name := range sortedKeys(corpusCounts) {
		for _, c := range loadCorpus(t, name) {
			seeds = append(seeds, strings.Join(c.Raw, ", "))
		}
	}
	return seeds
}

// controlFree is the part-two message rule: no C0 control and no DEL in a refusal's message.
func controlFree(err error) bool {
	return !strings.ContainsFunc(err.Error(), func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// checkParsers feeds input to every parser entry point and says what went wrong, if anything.
func checkParsers(input string) (problem string) {
	defer func() {
		if p := recover(); p != nil {
			problem = fmt.Sprintf("panic: %v", p)
		}
	}()
	if _, _, err := parseField(input, "Signature-Input", KindMalformedSignatureInput); err != nil {
		var fe *Error
		if !errors.As(err, &fe) || fe.Kind != KindMalformedSignatureInput || !controlFree(err) {
			return fmt.Sprintf("parseField: %v", err)
		}
	}
	if _, err := boundedList(input); err != nil && !errors.Is(err, errSyntax) {
		return fmt.Sprintf("parseList: %v", err)
	}
	if _, err := boundedItem(input); err != nil && !errors.Is(err, errSyntax) {
		return fmt.Sprintf("parseItem: %v", err)
	}
	return ""
}

// checkVerify puts input in place of one signature header of a vector request and verifies it.
func checkVerify(target fuzzTarget, header, input string) (problem string) {
	defer func() {
		if p := recover(); p != nil {
			problem = fmt.Sprintf("panic: %v", p)
		}
	}()
	headers := map[string]string{}
	for k, v := range target.c.Headers {
		if !strings.EqualFold(k, header) {
			headers[k] = v
		}
	}
	headers[header] = input
	_, err := VerifyRequest(target.c.Method, target.c.URL, headers, target.opts)
	if err == nil {
		return ""
	}
	var fe *Error
	if !errors.As(err, &fe) || errors.Is(err, ErrInvalidOptions) {
		return fmt.Sprintf("VerifyRequest (%s): not an *Error: %v", target.c.ID, err)
	}
	if !controlFree(err) {
		return fmt.Sprintf("VerifyRequest (%s): a control character in %q", target.c.ID, err)
	}
	return ""
}

const fuzzSeed, fuzzIterations = 0x9e3779b97f4a7c15, 60000

func TestSeededMutationsOfTheParserAndVerifyRequest(t *testing.T) {
	targets, vectorSeeds := fuzzTargets(t)
	seeds := append(corpusSeeds(t), vectorSeeds...)
	r := xorshift(fuzzSeed)
	started := time.Now()
	for i := range fuzzIterations {
		mutant := mutate(&r, seeds[r.below(len(seeds))], seeds)
		target := targets[r.below(len(targets))]
		header := [...]string{"Signature-Input", "Signature"}[r.below(2)]
		for _, input := range []string{string(mutant), strings.ToValidUTF8(string(mutant), "�")} {
			problem := checkParsers(input)
			if problem == "" {
				problem = checkVerify(target, header, input)
			}
			if problem != "" {
				t.Fatalf("seed %#x, iteration %d: %s\ninput: %q", uint64(fuzzSeed), i, problem, input)
			}
		}
	}
	t.Logf("%d mutants in %v", fuzzIterations, time.Since(started))
}

// FuzzParseStructuredFields is the native target the CI's `go test -fuzz` runs for a fixed time,
// seeded from the httpwg corpus; under a plain `go test` it runs the seeds alone.
func FuzzParseStructuredFields(f *testing.F) {
	for _, seed := range corpusSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if problem := checkParsers(input); problem != "" {
			t.Fatalf("%s\ninput: %q", problem, input)
		}
	})
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
