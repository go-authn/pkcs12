package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
)

// noCRT is an RSAPrivateKey without Dp, Dq and Qinv, which RFC 8017 requires
// and crypto/x509 reads (it derives them), so the pre-flight must not refuse it.
func noCRT(n, p, q, d *big.Int) []byte {
	inner, err := asn1.Marshal(struct {
		Version int
		N       *big.Int
		E       int
		D       *big.Int
		P, Q    *big.Int
	}{0, n, 65537, d, p, q})
	if err != nil {
		panic(err)
	}
	return p8Of(oidRSAEncryption, inner)
}

func TestKeyWithoutCRTValuesIsAccepted(t *testing.T) {
	material(t)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := noCRT(k.N, k.Primes[0], k.Primes[1], k.D)
	if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
		t.Fatalf("the standard library no longer reads a key without CRT values: %v", err)
	}
	if err := preflightKey(der, DefaultMaxRSABits); err != nil {
		t.Fatalf("pre-flight: %v", err)
	}
	f := realRSA(t, der)
	b, err := Decode(f.file(), pw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := b.PrivateKey.(*rsa.PrivateKey); !ok || got.N.Cmp(k.N) != 0 {
		t.Fatalf("decoded key %T does not match", b.PrivateKey)
	}
}

// Without CRT values the sizes of the others are still bounded: the CPU
// attack does not need them.
func TestHostileKeyWithoutCRTValuesIsRefused(t *testing.T) {
	big1 := func(bits int) *big.Int { return bitsOf(bits) }
	cases := []struct {
		name       string
		n, p, q, d int
		want       error
	}{
		{"consistent", 64, 32, 32, 64, nil},
		{"huge factors", 64, 20000, 20000, 64, ErrMalformed},
		{"huge exponent", 64, 32, 32, 20000, ErrMalformed},
		{"modulus over the cap", 65, 32, 33, 64, ErrLimit},
		{"zero factor", 64, 0, 32, 64, ErrMalformed},
	}
	for _, c := range cases {
		safely(t, func() {
			err := preflightKey(noCRT(big1(c.n), big1(c.p), big1(c.q), big1(c.d)), 64)
			if c.want == nil {
				if err != nil {
					t.Errorf("%s: %v", c.name, err)
				}
			} else if !isOnly(err, c.want) {
				t.Errorf("%s: got %v, want %v", c.name, err, c.want)
			}
		})
	}
}
