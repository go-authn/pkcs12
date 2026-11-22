//go:build ignore

// Command rfc9579_vectors extracts the base64 test vectors of RFC 9579
// Appendix A (A.1 to A.6) into testdata/rfc9579/a<N>.p12. Run from the
// repository root:
//
//	go run gen/rfc9579_vectors.go <path to rfc9579.txt>
package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: rfc9579_vectors rfc9579.txt")
		os.Exit(2)
	}
	text, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	head := regexp.MustCompile(`^A\.([1-6])\.  `)
	stop := regexp.MustCompile(`^(A\.[0-9]+\.|B\.|Authors|Acknowledg|[0-9]+\.  )`)
	b64 := regexp.MustCompile(`^   [A-Za-z0-9+/]{4,}={0,2}$`)

	cur := ""
	got := map[string]*strings.Builder{}
	for _, line := range strings.Split(string(text), "\n") {
		if m := head.FindStringSubmatch(line); m != nil {
			cur = m[1]
			got[cur] = &strings.Builder{}
			continue
		}
		if stop.MatchString(line) {
			cur = ""
			continue
		}
		if cur != "" && b64.MatchString(line) {
			got[cur].WriteString(strings.TrimSpace(line))
		}
	}
	os.MkdirAll("testdata/rfc9579", 0o755)
	for n := 1; n <= 6; n++ {
		k := fmt.Sprint(n)
		sb := got[k]
		if sb == nil {
			fmt.Fprintf(os.Stderr, "A.%d not found\n", n)
			os.Exit(1)
		}
		der, err := base64.StdEncoding.DecodeString(sb.String())
		if err != nil {
			fmt.Fprintf(os.Stderr, "A.%d: %v\n", n, err)
			os.Exit(1)
		}
		os.WriteFile(fmt.Sprintf("testdata/rfc9579/a%d.p12", n), der, 0o644)
		fmt.Printf("A.%d: %d bytes\n", n, len(der))
	}
}
