package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
)

// withCRT builds an RSAPrivateKey that carries the first n of Dp, Dq, Qinv.
func withCRT(k *rsa.PrivateKey, n int) []byte {
	crt := []*big.Int{k.Precomputed.Dp, k.Precomputed.Dq, k.Precomputed.Qinv}[:n]
	fields := []any{0, k.N, k.E, k.D, k.Primes[0], k.Primes[1]}
	for _, v := range crt {
		fields = append(fields, v)
	}
	var body []byte
	for _, f := range fields {
		b, err := asn1.Marshal(f)
		if err != nil {
			panic(err)
		}
		body = append(body, b...)
	}
	return p8Of(oidRSAEncryption, seq(body))
}

// A key without CRT values is refused, typed, BEFORE crypto/x509: the library
// reads it but derives them with big-number arithmetic (16.4 MB and 21 744
// allocations at 8192 bits, against 0.36 MB and 618 with them), which would
// break the allocation bound. Every exporter writes them.
func TestKeyWithoutCRTValuesIsRefusedBeforeStdlib(t *testing.T) {
	material(t)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(withCRT(k, 0)); err != nil {
		t.Fatalf("the standard library no longer reads a key without CRT values: %v", err)
	}
	if err := preflightKey(withCRT(k, 3), DefaultMaxRSABits); err != nil {
		t.Fatalf("a complete key: %v", err)
	}
	for n := 0; n < 3; n++ { // no CRT value, Dp only, Dp and Dq only
		safely(t, func() {
			wantErr(t, preflightKey(withCRT(k, n), DefaultMaxRSABits), ErrUnsupported, "CRT")
		})
	}

	f := realRSA(t, withCRT(k, 3))
	f.p8 = withCRT(k, 0)
	c := spyStdlib(t)
	_, err = Decode(f.file(), pw, nil)
	wantErr(t, err, ErrUnsupported, "CRT")
	c.want(t, 0, 0)
}
