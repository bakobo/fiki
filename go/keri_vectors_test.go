package fiki

// fiki-go runs the KERI profile's vector set, vectors/keri/ (`this.i` @8vwrexxc, @9z57sejw).
//
// A separate contract from the shared vectors/: its own format number, refusals named by the
// profile's neutral section 9 codes rather than fiki's kind names, and a resolver a KERI verifier
// would back with key event logs, built here from the keys table each file carries. fiki-py's
// driver imports the generator's resolver, well-formedness rule and policy-applying verifier;
// this one cannot import Python, so it restates them from the rules the files themselves state
// (keys_rule, policy, case_policy), and the files are read from the repository root, never copied.
//
// The resolver is authoritative (@6g9zjsv9). It derives a non-transferable B keyid from the
// prefix, looks every transferable keyid up in the table, answers (nil, nil) for a well-formed AID
// it holds no key state for, returns UnsupportedSigner for a key state with no single effective
// signer, and refuses a keyid that is not an AID at all. It never decodes a D keyid as a key,
// which is exactly what one of the vectors is there to catch.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var keriDir = filepath.Join("..", "vectors", "keri")

var keriFiles = []string{"rfc9421.json", "requests.json", "responses.json", "refusals.json", "legacy.json"}

// The kinds to the profile's section 9 codes, as vectors/keri/generate.py's CODES table maps
// fiki-py's classes. MissingKey has no code of its own: keyid is REQUIRED in the profile, so its
// absence is a malformed Signature-Input.
var profileCodes = map[string]string{
	KindMissingSignature:        "missing-signature",
	KindMissingSignatureInput:   "missing-signature-input",
	KindMalformedSignature:      "malformed-signature",
	KindMalformedSignatureInput: "malformed-signature-input",
	KindMissingKey:              "malformed-signature-input",
	KindMalformedSignatureLabel: "malformed-signature-label",
	KindMissingSignatureLabel:   "missing-signature-label",
	KindMalformedSignatureValue: "malformed-signature-value",
	KindDuplicateComponent:      "duplicate-component",
	KindUnsupportedComponent:    "unsupported-component",
	KindInsufficientCoverage:    "insufficient-coverage",
	KindMalformedKey:            "malformed-key",
	KindUnknownKey:              "unknown-key",
	KindUnsupportedSigner:       "unsupported-signer",
	KindUnsupportedAlgorithm:    "unsupported-algorithm",
	KindMissingComponent:        "missing-component",
	KindSignatureMismatch:       "signature-mismatch",
	KindSignatureTooOld:         "signature-stale",
	KindSignatureExpired:        "signature-expired",
	KindMalformedDigest:         "malformed-digest",
	KindDigestMismatch:          "digest-mismatch",
	KindUncoveredBody:           "uncovered-body",
	KindUnauthenticated:         "unauthenticated",
}

type keriMessage struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
}

func (m *keriMessage) body() []byte {
	if m.Body == nil {
		return nil
	}
	return []byte(*m.Body)
}

func (m *keriMessage) asRequest() *Request {
	return &Request{Method: m.Method, URL: m.URL, Headers: m.Headers, Body: m.body()}
}

type keriKey struct {
	Keyid        string  `json:"keyid"`
	Kind         string  `json:"kind"`
	EffectiveKey *string `json:"effective_key"`
	SeedHex      string  `json:"seed_hex"`
	KeyState     *struct {
		Keys []string `json:"keys"`
	} `json:"key_state"`
}

type keriPolicy struct {
	MaxAge          int64    `json:"max_age"`
	Skew            int64    `json:"skew"`
	RequestMinimum  []string `json:"request_minimum"`
	ResponseMinimum []string `json:"response_minimum"`
	ExpectedKeyid   string   `json:"expected_keyid"`
	Authorities     []string `json:"authorities"`
}

type keriCase struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	Request        keriMessage     `json:"request"`
	Response       *keriMessage    `json:"response"`
	Policy         json.RawMessage `json:"policy"`
	Now            int64           `json:"now"`
	Error          string          `json:"error"`
	VerifiedByFiki *bool           `json:"verified_by_fiki"`
	Why            string          `json:"why"`
	Covered        []string        `json:"covered"`
	Keyid          string          `json:"keyid"`
	SeedHex        string          `json:"seed_hex"`
	Created        int64           `json:"created"`
	Expected       struct {
		Keyid     string   `json:"keyid"`
		Covered   []string `json:"covered"`
		Base      string   `json:"base"`
		Signature string   `json:"signature"`
	} `json:"expected"`
}

type keriFile struct {
	KeriVectorsFormat *int            `json:"keri_vectors_format"`
	VectorsFormat     *int            `json:"vectors_format"`
	Profile           json.RawMessage `json:"profile"`
	Policy            json.RawMessage `json:"policy"`
	KeysRule          string          `json:"keys_rule"`
	Keys              []keriKey       `json:"keys"`
	Codes             []string        `json:"codes"`
	VerifyOnly        []string        `json:"verify_only"`
	Cases             []keriCase      `json:"cases"`
}

func loadKeri(t *testing.T, name string) keriFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(keriDir, name))
	if err != nil {
		t.Fatalf("the KERI vectors are not where every port reaches them: %v", err)
	}
	var file keriFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return file
}

// policyFor is the file's policy extended by the case's, as the file's case_policy rule states.
func policyFor(t *testing.T, file keriFile, c keriCase) keriPolicy {
	t.Helper()
	var policy keriPolicy
	if err := json.Unmarshal(file.Policy, &policy); err != nil {
		t.Fatal(err)
	}
	if len(c.Policy) > 0 {
		if err := json.Unmarshal(c.Policy, &policy); err != nil {
			t.Fatal(err)
		}
	}
	return policy
}

func b64urlLoose(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(text, "="))
	if err != nil {
		t.Fatalf("%q: %v", text, err)
	}
	return raw
}

// wellFormedAID is the files' keys_rule: 44 characters, a B, D or E code, and 43 base64url
// characters that decode behind one pad character to 32 bytes with a zero pad byte, so that
// re-encoding gives back the keyid exactly.
func wellFormedAID(keyid string) bool {
	if len(keyid) != 44 || !strings.ContainsRune("BDE", rune(keyid[0])) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString("A" + keyid[1:])
	if err != nil || len(decoded) != 33 || strings.ContainsAny(keyid, "\r\n") {
		return false
	}
	padded := append([]byte{0}, decoded[1:]...)
	return keyid[:1]+base64.RawURLEncoding.EncodeToString(padded)[1:] == keyid
}

// keriResolver is what a KERI verifier's key lookup does, for a keys table.
func keriResolver(keys []keriKey) Resolver {
	table := map[string]keriKey{}
	for _, entry := range keys {
		if entry.Kind == "transferable" {
			table[entry.Keyid] = entry
		}
	}
	return func(keyid string) ([]byte, error) {
		if !wellFormedAID(keyid) {
			return nil, &Error{Kind: KindMalformedKey, Message: keyid + " is not a well-formed AID.", Keyid: keyid}
		}
		if strings.HasPrefix(keyid, "B") {
			return VerifyingKey(keyid)
		}
		entry, ok := table[keyid]
		if !ok {
			return nil, nil
		}
		if entry.EffectiveKey == nil {
			return nil, &Error{
				Kind:    KindUnsupportedSigner,
				Message: "The key state of " + keyid + " has no single key that satisfies its threshold.",
				Keyid:   keyid,
			}
		}
		return base64.RawURLEncoding.DecodeString(*entry.EffectiveKey)
	}
}

// keriVerify verifies a case's message as a KERI verifier would, under the given policy.
func keriVerify(request keriMessage, response *keriMessage, now int64, policy keriPolicy, keys []keriKey) (*Verdict, error) {
	opts := VerifyOptions{
		MaxAge:        &policy.MaxAge,
		Skew:          &policy.Skew,
		Now:           now,
		Resolve:       keriResolver(keys),
		ExpectedKeyid: policy.ExpectedKeyid,
	}
	if response != nil {
		opts.Body = response.body()
		opts.Minimum = policy.ResponseMinimum
		return VerifyResponse(response.Status, request.asRequest(), response.Headers, opts)
	}
	opts.Body = request.body()
	opts.Minimum = policy.RequestMinimum
	// The KERI profile's policy names authorities only where a case does; elsewhere it declines
	// the check, which format 3 requires saying aloud (@524c8qgv).
	opts.Authorities = policy.Authorities
	opts.AnyAuthority = policy.Authorities == nil
	return VerifyRequest(request.Method, request.URL, request.Headers, opts)
}

// expectedBase rebuilds the base through the signing-side builders from the parameters the
// message's Signature-Input carries, and checks the message's signature over it under the
// resolved key, so the base an accept case publishes is the one that was signed.
func expectedBase(t *testing.T, request keriMessage, response *keriMessage, keys []keriKey) (string, string) {
	t.Helper()
	message := &request
	if response != nil {
		message = response
	}
	order, members, err := parseDictionary(message.Headers["Signature-Input"])
	if err != nil || len(order) != 1 {
		t.Fatalf("Signature-Input does not hold one member: %v", err)
	}
	list := members[order[0]].List
	covered := make([]string, len(list.Items))
	for i, item := range list.Items {
		covered[i] = componentID{Name: item.Value.(string), Params: item.Params}.serialize()
	}
	var params SignatureParams
	for _, p := range list.Params {
		switch p.Key {
		case "created":
			params.Created = p.Value.(int64)
		case "expires":
			params.Expires = p.Value.(int64)
		case "nonce":
			params.Nonce = p.Value.(string)
		case "alg":
			params.Alg = p.Value.(string)
		case "keyid":
			params.Keyid = p.Value.(string)
		case "tag":
			params.Tag = p.Value.(string)
		}
	}
	var base []byte
	if response != nil {
		base, err = ResponseSignatureBase(response.Status, request.asRequest(), response.Headers, covered, params)
	} else {
		base, err = SignatureBase(request.Method, request.URL, request.Headers, covered, params)
	}
	if err != nil {
		t.Fatal(err)
	}
	signature := strings.Trim(strings.SplitN(message.Headers["Signature"], "=", 2)[1], ":")
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keriResolver(keys)(params.Keyid)
	if err != nil || key == nil {
		t.Fatalf("no key resolves for %s: %v", params.Keyid, err)
	}
	if !ed25519.Verify(key, base, raw) {
		t.Fatal("the message's signature does not verify over the rebuilt base")
	}
	return string(base), signature
}

func serialized(t *testing.T, covered []string) []string {
	t.Helper()
	out := make([]string, len(covered))
	for i, spec := range covered {
		id, err := parseComponent(spec)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = id.serialize()
	}
	return out
}

func codeOf(t *testing.T, err error) string {
	t.Helper()
	var fikiErr *Error
	if !errors.As(err, &fikiErr) {
		t.Fatalf("expected a fiki.Error, got %T: %v", err, err)
	}
	code, ok := profileCodes[fikiErr.Kind]
	if !ok {
		t.Fatalf("the kind %s has no profile code", fikiErr.Kind)
	}
	return code
}

// --- the files themselves ---

func TestThisPortSatisfiesTheKeriVectorsFormatItIsRunning(t *testing.T) {
	// The same guard @4fhrre0m gives the shared set, against its own number.
	for _, name := range keriFiles {
		t.Run(name, func(t *testing.T) {
			file := loadKeri(t, name)
			if file.KeriVectorsFormat == nil || *file.KeriVectorsFormat != KeriVectorsFormat {
				t.Errorf("%s declares keri_vectors_format %v; this port satisfies %d", name, file.KeriVectorsFormat, KeriVectorsFormat)
			}
			if file.VectorsFormat != nil {
				t.Errorf("%s declares a vectors_format, which belongs to the shared set", name)
			}
			if len(file.Cases) == 0 {
				t.Errorf("%s carries no cases", name)
			}
		})
	}
}

func TestEachKeriFileNamesThePublishedProfileItPins(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "docs", "keri-profile.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range keriFiles {
		t.Run(name, func(t *testing.T) {
			var profile struct {
				Title   string `json:"title"`
				Version int    `json:"version"`
				Where   string `json:"where"`
			}
			if err := json.Unmarshal(loadKeri(t, name).Profile, &profile); err != nil {
				t.Fatal(err)
			}
			if profile.Version != 1 || profile.Where != "https://github.com/bakobo/fiki/blob/main/docs/keri-profile.md" {
				t.Errorf("profile = %+v", profile)
			}
			if !strings.HasPrefix(string(doc), "# "+profile.Title+"\n\nVersion 1, ") {
				t.Errorf("docs/keri-profile.md is not version 1 of %q", profile.Title)
			}
		})
	}
}

func TestEachKeriFileStatesThePolicyItAssumes(t *testing.T) {
	for _, name := range []string{"requests.json", "responses.json", "refusals.json"} {
		t.Run(name, func(t *testing.T) {
			policy := policyFor(t, loadKeri(t, name), keriCase{})
			if policy.MaxAge != 300 || policy.Skew != 60 {
				t.Errorf("max_age %d, skew %d", policy.MaxAge, policy.Skew)
			}
			if !slices.Equal(policy.RequestMinimum, []string{`"@method"`, `"@path"`, `"@query"`}) {
				t.Errorf("request_minimum = %v", policy.RequestMinimum)
			}
			if !slices.Equal(policy.ResponseMinimum, []string{`"@status"`, `"@method";req`, `"@path";req`, `"@query";req`}) {
				t.Errorf("response_minimum = %v", policy.ResponseMinimum)
			}
			// The port's own constants are the profile's minimum sets.
			if !slices.Equal(serialized(t, RequestMinimum), policy.RequestMinimum) {
				t.Errorf("RequestMinimum = %v", RequestMinimum)
			}
			if !slices.Equal(serialized(t, ResponseMinimum), policy.ResponseMinimum) {
				t.Errorf("ResponseMinimum = %v", ResponseMinimum)
			}
		})
	}
}

func TestTheKeysTableAgreesWithItsSeedsAndKeyStates(t *testing.T) {
	// A table entry that disagrees with its own seed would make every case using it a lie.
	for _, name := range []string{"requests.json", "responses.json", "refusals.json"} {
		t.Run(name, func(t *testing.T) {
			file := loadKeri(t, name)
			if file.KeysRule == "" {
				t.Error("no keys_rule")
			}
			for _, entry := range file.Keys {
				if !wellFormedAID(entry.Keyid) {
					t.Errorf("%s is not well formed", entry.Keyid)
				}
				key, err := FromSeed(mustHex(t, entry.SeedHex))
				if err != nil {
					t.Fatal(err)
				}
				signer := key.private.Public().(ed25519.PublicKey)
				if entry.Kind == "non-transferable" {
					if entry.Keyid != key.AID() {
						t.Errorf("%s is not the AID of its seed", entry.Keyid)
					}
					continue
				}
				var state [][]byte
				for _, verfer := range entry.KeyState.Keys {
					if !strings.HasPrefix(verfer, "D") || len(verfer) != 44 {
						t.Errorf("%s is not a D verfer", verfer)
					}
					state = append(state, b64urlLoose(t, "A"+verfer[1:])[1:])
				}
				if entry.EffectiveKey == nil {
					if !bytes.Equal(signer, state[0]) {
						t.Errorf("%s: the vectors' messages are signed by the first key", entry.Keyid)
					}
					continue
				}
				if !bytes.Equal(b64urlLoose(t, *entry.EffectiveKey), signer) {
					t.Errorf("%s: the effective key is not the seed's", entry.Keyid)
				}
				if !slices.ContainsFunc(state, func(k []byte) bool { return bytes.Equal(k, signer) }) {
					t.Errorf("%s: the effective key is not in the key state", entry.Keyid)
				}
			}
		})
	}
}

func TestTheWellFormednessRuleRefusesNearMisses(t *testing.T) {
	for _, keyid := range []string{"E" + strings.Repeat("!", 43), "A" + strings.Repeat("A", 43), "not-an-aid"} {
		if wellFormedAID(keyid) {
			t.Errorf("%q should not be well formed", keyid)
		}
	}
	// bakobo/fiki#4: a keyid spelled with a non-zero pad bit would alias the same key.
	for _, entry := range loadKeri(t, "requests.json").Keys {
		if !wellFormedAID(entry.Keyid) || wellFormedAID(paddingBitAlias(entry.Keyid)) {
			t.Errorf("%s: the canonical spelling alone is well formed", entry.Keyid)
		}
	}
}

func TestEveryRefusalNamesAProfileCodeAndEveryProfileCodeIsExercised(t *testing.T) {
	file := loadKeri(t, "refusals.json")
	named := map[string]bool{}
	for _, c := range file.Cases {
		named[c.Error] = true
		// Neutral codes, never this port's kind names.
		if c.Error != strings.ToLower(c.Error) {
			t.Errorf("%s names %q, which is not a profile code", c.ID, c.Error)
		}
		if _, isKind := profileCodes[c.Error]; isKind {
			t.Errorf("%s names a kind rather than a code", c.ID)
		}
	}
	codes := map[string]bool{}
	for _, code := range file.Codes {
		codes[code] = true
	}
	if len(named) != len(codes) {
		t.Errorf("the cases name %d codes and the file lists %d", len(named), len(codes))
	}
	for code := range named {
		if !codes[code] {
			t.Errorf("%s is named by a case and not listed", code)
		}
	}
	for _, code := range profileCodes {
		if !named[code] {
			t.Errorf("%s is never exercised", code)
		}
	}
}

func TestEveryKindHasAProfileCode(t *testing.T) {
	// The totality heti's boundary test enforces (@8zw78n0v), against the profile's codes. Go
	// cannot enumerate a package's constants by reflection, so this reads errors.go itself: every
	// exported Kind constant declared there must have a code, and nothing else may.
	parsed, err := parser.ParseFile(token.NewFileSet(), "errors.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if strings.HasPrefix(name.Name, "Kind") {
				literal := spec.Values[i].(*ast.BasicLit).Value
				declared[strings.Trim(literal, `"`)] = true
			}
		}
		return true
	})
	if len(declared) != len(profileCodes) {
		t.Errorf("errors.go declares %d kinds and %d have codes", len(declared), len(profileCodes))
	}
	for kind := range declared {
		if _, ok := profileCodes[kind]; !ok {
			t.Errorf("the kind %s has no profile code", kind)
		}
	}
}

// --- RFC 9421 B.2.6, which anchors the set to something no Bakobo party wrote ---

func TestRFC9421B26IsReproducedByteForByte(t *testing.T) {
	for _, c := range loadKeri(t, "rfc9421.json").Cases {
		t.Run(c.ID, func(t *testing.T) {
			base, err := SignatureBase(c.Request.Method, c.Request.URL, c.Request.Headers, c.Covered,
				SignatureParams{Created: c.Created, Keyid: c.Keyid})
			if err != nil {
				t.Fatal(err)
			}
			if string(base) != c.Expected.Base {
				t.Errorf("base mismatch\n got: %q\nwant: %q", base, c.Expected.Base)
			}
			key, err := FromSeed(mustHex(t, c.SeedHex))
			if err != nil {
				t.Fatal(err)
			}
			if got := base64.StdEncoding.EncodeToString(key.Sign(base)); got != c.Expected.Signature {
				t.Errorf("signature = %s, want %s", got, c.Expected.Signature)
			}
		})
	}
}

// --- the accept cases ---

func TestKeriRequestAcceptVectors(t *testing.T) {
	file := loadKeri(t, "requests.json")
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			verdict, err := keriVerify(c.Request, nil, c.Now, policyFor(t, file, c), file.Keys)
			if err != nil {
				t.Fatalf("expected this request to verify, got %v", err)
			}
			if verdict.Keyid != c.Expected.Keyid {
				t.Errorf("keyid = %q, want %q", verdict.Keyid, c.Expected.Keyid)
			}
			if got := serialized(t, verdict.Covered); !slices.Equal(got, c.Expected.Covered) {
				t.Errorf("covered = %v, want %v", got, c.Expected.Covered)
			}
			base, signature := expectedBase(t, c.Request, nil, file.Keys)
			if base != c.Expected.Base || signature != c.Expected.Signature {
				t.Errorf("base mismatch\n got: %q\nwant: %q", base, c.Expected.Base)
			}
		})
	}
}

func TestKeriResponseAcceptVectors(t *testing.T) {
	file := loadKeri(t, "responses.json")
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			// The request each response answers verifies in its own right first.
			if _, err := keriVerify(c.Request, nil, c.Now, policyFor(t, file, keriCase{}), file.Keys); err != nil {
				t.Fatalf("the request should verify: %v", err)
			}
			verdict, err := keriVerify(c.Request, c.Response, c.Now, policyFor(t, file, c), file.Keys)
			if err != nil {
				t.Fatalf("expected this response to verify, got %v", err)
			}
			if verdict.Keyid != c.Expected.Keyid {
				t.Errorf("keyid = %q, want %q", verdict.Keyid, c.Expected.Keyid)
			}
			if got := serialized(t, verdict.Covered); !slices.Equal(got, c.Expected.Covered) {
				t.Errorf("covered = %v, want %v", got, c.Expected.Covered)
			}
			base, signature := expectedBase(t, c.Request, c.Response, file.Keys)
			if base != c.Expected.Base || signature != c.Expected.Signature {
				t.Errorf("base mismatch\n got: %q\nwant: %q", base, c.Expected.Base)
			}
		})
	}
}

func TestTheSHA512CasesAreMarkedVerifyOnly(t *testing.T) {
	file := loadKeri(t, "requests.json")
	ids := map[string]bool{}
	for _, c := range file.Cases {
		ids[c.ID] = true
	}
	for _, id := range file.VerifyOnly {
		if !ids[id] {
			t.Errorf("verify_only names %s, which is not a case", id)
		}
	}
	for _, c := range file.Cases {
		digest := c.Request.Headers["Content-Digest"]
		if (digest != "" && !strings.HasPrefix(digest, "sha-256=")) || strings.Contains(digest, ",") {
			if !slices.Contains(file.VerifyOnly, c.ID) {
				t.Errorf("%s carries a digest a sha-256 signer cannot emit and is not verify_only", c.ID)
			}
		}
	}
}

// --- the refusals ---

func TestKeriRefusalVectors(t *testing.T) {
	// Each case has one defect and so one correct code under the profile's section 9 order.
	file := loadKeri(t, "refusals.json")
	var policy keriPolicy
	if err := json.Unmarshal(file.Policy, &policy); err != nil {
		t.Fatal(err)
	}
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.VerifiedByFiki != nil && !*c.VerifiedByFiki {
				// Carried as data (@4tkkp50h): fiki has no legacy mode to detect it with.
				if c.Error != "mode-mismatch" || c.Why == "" {
					t.Errorf("a case fiki does not verify must be a mode-mismatch that says why")
				}
				return
			}
			var err error
			if c.Kind == "sign-request" {
				key, keyErr := FromSeed(mustHex(t, c.SeedHex))
				if keyErr != nil {
					t.Fatal(keyErr)
				}
				_, err = SignRequest(key, c.Request.Method, c.Request.URL, c.Request.Headers, SignOptions{
					Body: c.Request.body(), Covered: c.Covered, Keyid: c.Keyid, Minimum: policy.RequestMinimum,
				})
			} else {
				_, err = keriVerify(c.Request, c.Response, c.Now, policyFor(t, file, c), file.Keys)
			}
			if err == nil {
				t.Fatalf("expected %s, got a verdict", c.Error)
			}
			if got := codeOf(t, err); got != c.Error {
				t.Errorf("code = %s, want %s (%v)", got, c.Error, err)
			}
		})
	}
}

// --- legacy material, which fiki carries and never verifies (@8vwrexxc) ---

type legacyCase struct {
	ID     string `json:"id"`
	Source struct {
		Repo   string `json:"repo"`
		Commit string `json:"commit"`
		File   string `json:"file"`
		Lines  string `json:"lines"`
	} `json:"source"`
	Headers map[string]string `json:"headers"`
	Key     string            `json:"key"`
	Base    string            `json:"base"`
}

func TestLegacyVectorsCarryWhatALegacyVerifierNeedsAndTheirProvenance(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(keriDir, "legacy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, fields := range file.Cases {
		for _, field := range []string{"kind", "method", "path", "headers", "key", "keyid", "created"} {
			if _, ok := fields[field]; !ok {
				t.Errorf("a legacy case lacks %s", field)
			}
		}
	}
	var cases struct{ Cases []legacyCase }
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases.Cases {
		if c.Source.Repo != "WebOfTrust/keria" && c.Source.Repo != "WebOfTrust/signify-ts" {
			t.Errorf("%s: source repo %q", c.ID, c.Source.Repo)
		}
		if len(c.Source.Commit) != 40 || c.Source.File == "" || c.Source.Lines == "" {
			t.Errorf("%s: incomplete provenance %+v", c.ID, c.Source)
		}
		if !strings.HasPrefix(c.Headers["Signature-Input"], "signify=") ||
			!strings.HasPrefix(c.Headers["Signature"], `indexed="?0";signify="0B`) {
			t.Errorf("%s: not a legacy header pair", c.ID)
		}
	}
}

func TestEachLegacySignatureVerifiesOverItsStatedBase(t *testing.T) {
	// Transcription check only: pure Ed25519 over the base the file states, no legacy logic.
	raw, err := os.ReadFile(filepath.Join(keriDir, "legacy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct{ Cases []legacyCase }
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			qb64 := strings.TrimSuffix(strings.SplitN(c.Headers["Signature"], `signify="`, 2)[1], `"`)
			signature := b64urlLoose(t, "AA"+qb64[2:])[2:]
			key := b64urlLoose(t, "A"+c.Key[1:])[1:]
			if !ed25519.Verify(key, []byte(c.Base), signature) {
				t.Error("the legacy signature does not verify over its stated base")
			}
		})
	}
}

func paddingBitAlias(aid string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	value := strings.IndexByte(alphabet, aid[1])
	return aid[:1] + string(alphabet[value^0b010000]) + aid[2:]
}
