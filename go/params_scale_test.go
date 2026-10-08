package fiki

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Hostile review of 365f522 on bakobo/fiki#6, item 2: setParam rescanned every earlier
// parameter, so a long Signature-Input cost quadratic time before it was refused. Since 0.8.0 an
// item carries at most MaxParameters distinct ones (this.i @5zrf8gjk), so the run repeats them,
// which is the path that once rescanned.
func TestManyParametersParseInLinearTime(t *testing.T) {
	var b strings.Builder
	b.WriteString(`sig=("@method")`)
	for i := 0; i < 200000; i++ {
		fmt.Fprintf(&b, ";p%d=1", i%MaxParameters)
	}
	started := time.Now()
	if _, _, err := parseDictionary(b.String()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("200000 parameters took %v", elapsed)
	}
}
