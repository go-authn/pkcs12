package pkcs12

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type manifestEntry struct {
	Name       string   `json:"name"`
	Password   string   `json:"password"`
	NoPassword bool     `json:"no_password"`
	AllowNoMAC bool     `json:"allow_no_mac"`
	Key        string   `json:"key"`
	PubSHA256  string   `json:"pub_sha256"`
	Leaf       string   `json:"leaf_sha256"`
	CA         []string `json:"ca_sha256"`
	Flags      []string `json:"flags"`
	Needs      string   `json:"needs"`
}

func loadManifest(t testing.TB) []manifestEntry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "openssl", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m []manifestEntry
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func hexSum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func readFixture(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestOpenSSLFixtures decodes every file OpenSSL 4.1 wrote and compares what
// came out with the manifest, which was computed by OpenSSL from the inputs.
func TestOpenSSLFixtures(t *testing.T) {
	for _, e := range loadManifest(t) {
		t.Run(e.Name, func(t *testing.T) {
			data := readFixture(t, "openssl/"+e.Name+".p12")
			b, err := Decode(data, e.Password, &Options{AllowNoMAC: e.AllowNoMAC, NoPassword: e.NoPassword})
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKIXPublicKey(b.Certificate.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if got := hexSum(der); got != e.PubSHA256 {
				t.Errorf("certificate public key %s, want %s", got, e.PubSHA256)
			}
			if got := hexSum(b.Certificate.Raw); got != e.Leaf {
				t.Errorf("leaf %s, want %s", got, e.Leaf)
			}
			var got []string
			for _, c := range b.CACerts {
				got = append(got, hexSum(c.Raw))
			}
			if len(got) != len(e.CA) {
				t.Fatalf("%d CA certificates, want %d", len(got), len(e.CA))
			}
			for _, w := range e.CA {
				found := false
				for _, g := range got {
					found = found || g == w
				}
				if !found {
					t.Errorf("CA %s missing", w)
				}
			}
			ok, err := keyMatches(b.PrivateKey, b.Certificate.PublicKey)
			if err != nil || !ok {
				t.Errorf("key does not match certificate: %v", err)
			}
		})
	}
}

// TestWrongPassword: every encrypted or MAC'd fixture refuses a wrong
// password with ErrIncorrectPassword, never with a parse error.
func TestWrongPassword(t *testing.T) {
	for _, e := range loadManifest(t) {
		if e.NoPassword || e.AllowNoMAC {
			continue
		}
		t.Run(e.Name, func(t *testing.T) {
			data := readFixture(t, "openssl/"+e.Name+".p12")
			_, err := Decode(data, e.Password+"x", nil)
			if !errors.Is(err, ErrIncorrectPassword) {
				t.Fatalf("got %v, want ErrIncorrectPassword", err)
			}
		})
	}
}

// TestRFC9579 reads the vectors of RFC 9579 Appendix A: A.1 to A.3 MUST be
// readable, A.4 to A.6 MUST NOT.
func TestRFC9579(t *testing.T) {
	for _, tc := range []struct {
		file string
		ok   bool
	}{{"a1", true}, {"a2", true}, {"a3", true}, {"a4", false}, {"a5", false}, {"a6", false}} {
		t.Run(tc.file, func(t *testing.T) {
			data := readFixture(t, "rfc9579/"+tc.file+".p12")
			_, err := Decode(data, "1234", nil)
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok && err == nil {
				t.Fatal("read a file the RFC says must be refused")
			}
			if !tc.ok {
				t.Log(err)
			}
		})
	}
}
