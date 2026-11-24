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

// wrongCRT builds an RSAPrivateKey whose Dp, Dq, Qinv are the given numbers.
func wrongCRT(k *rsa.PrivateKey, dp, dq, qinv *big.Int) []byte {
	var body []byte
	for _, f := range []any{0, k.N, k.E, k.D, k.Primes[0], k.Primes[1], dp, dq, qinv} {
		b, err := asn1.Marshal(f)
		if err != nil {
			panic(err)
		}
		body = append(body, b...)
	}
	return p8Of(oidRSAEncryption, seq(body))
}

// Under GODEBUG=x509rsacrt=0 crypto/x509 drops wrong CRT values and derives them
// again (pkcs1.go), which stepped over the cost bound (pkcs12#2). The values are
// checked here, so the refusal holds whatever the setting says.
func TestWrongCRTValuesAreRefusedWhateverGODEBUG(t *testing.T) {
	material(t)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	one := big.NewInt(1)
	dp, dq, qinv := k.Precomputed.Dp, k.Precomputed.Dq, k.Precomputed.Qinv
	bad := map[string][3]*big.Int{
		"all one":    {one, one, one},
		"wrong qinv": {dp, dq, new(big.Int).Add(qinv, one)},
		"wrong dp":   {new(big.Int).Add(dp, one), dq, qinv},
		"wrong dq":   {dp, new(big.Int).Sub(dq, one), qinv},
	}
	for _, setting := range []string{"x509rsacrt=0", "x509rsacrt=1"} {
		t.Setenv("GODEBUG", setting)
		for name, v := range bad {
			t.Run(setting+"/"+name, func(t *testing.T) {
				safely(t, func() {
					wantErr(t, preflightKey(wrongCRT(k, v[0], v[1], v[2]), DefaultMaxRSABits), ErrMalformed, "CRT")
				})
			})
		}
		if err := preflightKey(withCRT(k, 3), DefaultMaxRSABits); err != nil {
			t.Fatalf("%s: a correct key: %v", setting, err)
		}
	}

	f := realRSA(t, withCRT(k, 3))
	f.p8 = wrongCRT(k, one, one, one)
	c := spyStdlib(t)
	_, err = Decode(f.file(), pw, nil)
	wantErr(t, err, ErrMalformed, "CRT")
	c.want(t, 0, 0)
}

// wrongCRTKeys returns PKCS#8 keys with all-one, wrong Qinv, wrong Dp and wrong
// Dq values, the seeds of FuzzDecode for pkcs12#2.
func wrongCRTKeys(tb testing.TB) [][]byte {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	one := big.NewInt(1)
	dp, dq, qinv := k.Precomputed.Dp, k.Precomputed.Dq, k.Precomputed.Qinv
	return [][]byte{
		wrongCRT(k, one, one, one),
		wrongCRT(k, dp, dq, new(big.Int).Add(qinv, one)),
		wrongCRT(k, new(big.Int).Add(dp, one), dq, qinv),
		wrongCRT(k, dp, new(big.Int).Sub(dq, one), qinv),
	}
}
