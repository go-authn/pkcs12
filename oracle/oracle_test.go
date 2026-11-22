// Package oracle compares go-authn/pkcs12 with software.sslmate.com/src/go-pkcs12
// and with the `openssl pkcs12` command. It is a separate module so that the
// reference is never a dependency of the library: the library's go.mod has no
// requirements at all.
//
//	cd oracle && go test ./...                     # differential test
//	cd oracle && go test -bench . -benchmem -run X # speed and allocations
//
// Timing is only meaningful at a 1-minute load average of 8 or less; the
// allocation counts are exact at any load.
package oracle

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	ours "github.com/go-authn/pkcs12"
	theirs "software.sslmate.com/src/go-pkcs12"
)

type entry struct {
	Name       string `json:"name"`
	Password   string `json:"password"`
	NoPassword bool   `json:"no_password"`
	AllowNoMAC bool   `json:"allow_no_mac"`
}

func manifest(t testing.TB) []entry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "openssl", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m []entry
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func file(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "openssl", name+".p12"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAgainstSSLMate: on every fixture the two decoders agree, or ours reads
// strictly more. Where sslmate refuses a file ours reads, the reason is logged
// so the table in the README can be checked against it.
func TestAgainstSSLMate(t *testing.T) {
	var both, onlyOurs, onlyTheirs int
	for _, e := range manifest(t) {
		t.Run(e.Name, func(t *testing.T) {
			data := file(t, e.Name)
			b, oerr := ours.Decode(data, e.Password, &ours.Options{AllowNoMAC: e.AllowNoMAC, NoPassword: e.NoPassword})
			key, cert, cas, terr := theirs.DecodeChain(data, e.Password)
			switch {
			case oerr == nil && terr == nil:
				both++
				if !bytes.Equal(b.Certificate.Raw, cert.Raw) {
					t.Error("leaf differs")
				}
				if len(b.CACerts) != len(cas) {
					t.Fatalf("%d CA certificates, sslmate %d", len(b.CACerts), len(cas))
				}
				for i := range cas {
					if !bytes.Equal(b.CACerts[i].Raw, cas[i].Raw) {
						t.Errorf("CA %d differs (order or content)", i)
					}
				}
				a, _ := x509.MarshalPKCS8PrivateKey(b.PrivateKey)
				c, _ := x509.MarshalPKCS8PrivateKey(key)
				if !bytes.Equal(a, c) {
					t.Error("private key differs")
				}
			case oerr == nil:
				onlyOurs++
				t.Logf("sslmate refuses, we read: %v", terr)
			default:
				onlyTheirs++
				t.Errorf("we refuse, sslmate reads: %v", oerr)
			}
		})
	}
	t.Logf("both read %d, only ours %d, only sslmate %d", both, onlyOurs, onlyTheirs)
}

func opensslPath(t testing.TB) string {
	p, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl")
	}
	return p
}

var benchFiles = []string{"rsa-default", "rsa-aes128", "rsa-legacy", "rsa-iter-100000", "ec-default"}

func benchEntry(b *testing.B, name string) entry {
	for _, e := range manifest(b) {
		if e.Name == name {
			return e
		}
	}
	b.Fatalf("no fixture %s", name)
	return entry{}
}

func BenchmarkOurs(b *testing.B) {
	for _, n := range benchFiles {
		e, data := benchEntry(b, n), file(b, n)
		b.Run(n, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := ours.Decode(data, e.Password, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSSLMate(b *testing.B) {
	for _, n := range benchFiles {
		e, data := benchEntry(b, n), file(b, n)
		b.Run(n, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, _, err := theirs.DecodeChain(data, e.Password); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOpenSSL times the whole process (fork, exec, library start-up)
// reading the same file, which is how a shell-out would pay for it.
func BenchmarkOpenSSL(b *testing.B) {
	bin := opensslPath(b)
	for _, n := range benchFiles {
		e := benchEntry(b, n)
		path, _ := filepath.Abs(filepath.Join("..", "testdata", "openssl", n+".p12"))
		b.Run(n, func(b *testing.B) {
			args := []string{"pkcs12", "-in", path, "-passin", "env:P12PW", "-noenc"}
			if n == "rsa-legacy" {
				args = append(args, "-legacy")
			}
			for i := 0; i < b.N; i++ {
				cmd := exec.Command(bin, args...)
				cmd.Env = append(os.Environ(), "P12PW="+e.Password)
				cmd.Stdin = nil
				if err := cmd.Run(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
