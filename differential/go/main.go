// The Go port's answers to differential/cases.json, as a map from case id to outcome.
//
// `go run . [cases.json] [out.json]` from differential/go. The outcome spelling is shared by all
// six runners and described in differential/README.md.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	fiki "github.com/bakobo/fiki/go"
)

// prefix is how much of a caller error's message an outcome carries; the same in every runner.
const prefix = 40

type testCase struct {
	ID          string            `json:"id"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        *string           `json:"body"`
	MaxAge      *int64            `json:"max_age"`
	Now         int64             `json:"now"`
	Authorities json.RawMessage   `json:"authorities"`
	Minimum     json.RawMessage   `json:"minimum"`
	ExpectedAID *string           `json:"expected_aid"`
}

// options is the case's stated policy in Go's spelling: a null max_age is AnyAge, null
// authorities AnyAuthority, a null minimum NoMinimum, and "default" leaves Minimum nil.
func (c testCase) options() (fiki.VerifyOptions, error) {
	opts := fiki.VerifyOptions{MaxAge: c.MaxAge, AnyAge: c.MaxAge == nil, Now: c.Now, ExpectedAID: c.ExpectedAID}
	if c.Body != nil {
		opts.Body = []byte(*c.Body)
	}
	if string(c.Authorities) == "null" {
		opts.AnyAuthority = true
	} else if err := json.Unmarshal(c.Authorities, &opts.Authorities); err != nil {
		return opts, err
	}
	switch string(c.Minimum) {
	case `"default"`:
	case "null":
		opts.NoMinimum = true
	default:
		if err := json.Unmarshal(c.Minimum, &opts.Minimum); err != nil {
			return opts, err
		}
	}
	return opts, nil
}

func outcome(c testCase, opts fiki.VerifyOptions) (result string) {
	defer func() {
		if r := recover(); r != nil {
			result = "crash:panic"
		}
	}()
	verdict, err := fiki.VerifyRequest(c.Method, c.URL, c.Headers, opts)
	var fikiErr *fiki.Error
	switch {
	case err == nil:
		return "ok:" + verdict.AID
	case errors.As(err, &fikiErr):
		return fikiErr.Kind
	case errors.Is(err, fiki.ErrInvalidOptions):
		// The message after Go's "fiki: invalid options: " sentinel, which is how Go marks the
		// class rather than part of what the port says.
		message := err.Error()
		if rest, ok := strings.CutPrefix(message, fiki.ErrInvalidOptions.Error()+": "); ok {
			message = rest
		}
		return "caller:" + truncate(message, prefix)
	default:
		return fmt.Sprintf("crash:%T", err)
	}
}

// truncate cuts to n characters, not bytes, as the other runners do.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		runes = runes[:n]
	}
	return string(runes)
}

func main() {
	here, _ := os.Getwd()
	casesPath := filepath.Join(here, "..", "cases.json")
	outPath := filepath.Join(here, "..", "out", "go.json")
	if len(os.Args) > 1 {
		casesPath = os.Args[1]
	}
	if len(os.Args) > 2 {
		outPath = os.Args[2]
	}
	raw, err := os.ReadFile(casesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var file struct {
		Cases []testCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	start := time.Now()
	out := make(map[string]string, len(file.Cases))
	for _, c := range file.Cases {
		opts, err := c.options()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: the case states a policy this runner cannot read: %v\n", c.ID, err)
			os.Exit(2)
		}
		out[c.ID] = outcome(c, opts)
	}
	// encoding/json writes a map's keys sorted, so the file is the same on every run.
	encoded, _ := json.MarshalIndent(out, "", "")
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := os.WriteFile(outPath, append(encoded, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("go: %d cases in %.1fs\n", len(out), time.Since(start).Seconds())
}
