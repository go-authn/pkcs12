package pkcs12

import (
	"crypto/rsa"
	"crypto/x509"
	"net/url"
	"os"
	"testing"
)

func rsa8192(t testing.TB) []byte {
	t.Helper()
	p8, err := os.ReadFile("testdata/rsa8192.p8")
	if err != nil {
		t.Fatal(err)
	}
	return p8
}

// TestWorstCaseFamily is the most expensive input the defaults admit: copies
// of the densest certificate that fits MaxCertSize (names of 2 bytes), enough
// of them to fill MaxCertBytes, once as plain bags and once with the bags
// inside an encrypted, constructed (BER) authSafe, the layered form the
// external review measured at 47x. Each is run with the cheap Ed25519 key and
// with the largest RSA key the defaults accept (8192 bits), which is the JOINT
// worst case: both costs are paid by one Decode. The suite's own measurement
// is what the README quotes.
func TestWorstCaseFamily(t *testing.T) {
	material(t)
	der := tinyCert(t, DefaultMaxCertSize)
	if len(der) < DefaultMaxCertSize-64 {
		t.Fatalf("certificate of %d bytes does not reach the cap %d", len(der), DefaultMaxCertSize)
	}
	copies := DefaultMaxCertBytes / len(der)
	// The RSA key needs a certificate that matches it, or Decode refuses the
	// file without reading the rest: that leaf is as dense as the others.
	big8192 := rsa8192(t)
	k, err := x509.ParsePKCS8PrivateKey(big8192)
	if err != nil {
		t.Fatal(err)
	}
	u := &url.URL{Scheme: "a"}
	leaf := uriCertFor(t, DefaultMaxCertSize, func(int) *url.URL { return u }, k.(*rsa.PrivateKey).Public())
	for _, key := range []struct {
		name  string
		p8    []byte
		certs [][]byte
	}{
		{"ed25519", mat.p8, nil},
		{"rsa8192", big8192, [][]byte{leaf}},
	} {
		certs := key.certs
		for len(certs) < copies {
			certs = append(certs, der)
		}
		plain := [][]byte{keyBagDER(key.p8)}
		layered := [][]byte{keyBagDER(key.p8)}
		for _, c := range certs {
			plain = append(plain, certBagDER(c))
			layered = append(layered, bagDER(oidCertBag, seq(oidDER(oidX509Certificate), ctx(0, tlv(0x24, oct(c))))))
		}
		p := aesP2(16)
		ct := p.seal(t, pw, pad(seq(layered...), 16))
		eci := seq(oidDER(oidData), p.alg(), tlv(0xa0, oct(ct)))
		safe := seq(seq(oidDER(oidEncryptedData), ctx(0, seq(integer(0), eci))))
		inputs := map[string][]byte{
			"plain":   fileOf(pw, dataCI(plain...)),
			"layered": seq(integer(3), seq(oidDER(oidData), ctx(0, tlv(0x24, oct(safe)))), sha1MAC(pw).der(safe)),
		}
		for _, name := range []string{"plain", "layered"} {
			in := inputs[name]
			b, err, a := decodeAlloc(t, in, nil)
			if err != nil {
				t.Fatalf("%s %s: %v", key.name, name, err)
			}
			if kept := len(b.CACerts); b.Certificate != nil {
				kept++
			} else if kept != copies {
				t.Fatalf("%s %s: %d certificates kept, want %d", key.name, name, kept, copies)
			}
			r := float64(a) / float64(len(in))
			t.Logf("%s, %s: %d certificates of %d B, file %d B: alloc %d B, ratio %.1f", key.name, name, copies, len(der), len(in), a, r)
			if a > absoluteBound {
				t.Errorf("%s %s: alloc %d exceeds the absolute bound %d", key.name, name, a, absoluteBound)
			}
			if r > maxCertRatio {
				t.Errorf("%s %s: ratio %.1f exceeds %.0f", key.name, name, r, maxCertRatio)
			}
		}
	}
}
