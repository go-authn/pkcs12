package pkcs12

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"
)

// What a valid, authenticated file can make crypto/x509 do. The threat model
// is an uploader who knows the password, so the MAC proves nothing about the
// content: everything below DECODES (or is refused by a typed bound) and the
// bytes allocated are asserted in absolute terms as well as per input byte.

// calls counts what reached the two crypto/x509 parsers.
type calls struct{ certs, keys int }

// spyStdlib counts the calls to the two crypto/x509 parsers: a refusal that
// must happen before them is proved by their count staying where it was.
func spyStdlib(t *testing.T) *calls {
	t.Helper()
	c := &calls{}
	pc, pk := parseCertificate, parsePKCS8
	parseCertificate = func(der []byte) (*x509.Certificate, error) {
		c.certs++
		return pc(der)
	}
	parsePKCS8 = func(der []byte) (any, error) {
		c.keys++
		return pk(der)
	}
	t.Cleanup(func() { parseCertificate, parsePKCS8 = pc, pk })
	return c
}

func (c *calls) want(t *testing.T, certs, keys int) {
	t.Helper()
	if c.certs != certs || c.keys != keys {
		t.Fatalf("crypto/x509 parsed %d certificates and %d keys, want %d and %d", c.certs, c.keys, certs, keys)
	}
}

// bigCert is a self-signed certificate of the material key, as large as it can
// be without exceeding limit bytes, made of thousands of the shortest URI names
// (5 bytes each), the shape on which crypto/x509 allocates most per byte.
func bigCert(t testing.TB, limit int) []byte {
	return uriCert(t, limit, func(i int) *url.URL {
		return &url.URL{Scheme: "a", Opaque: string(rune('a' + i%26))}
	})
}

// tinyCert is bigCert with names of 2 bytes ("a:"), the densest the standard
// library accepts: the external review's worst case, about 8 100 names.
func tinyCert(t testing.TB, limit int) []byte {
	u := &url.URL{Scheme: "a"}
	return uriCert(t, limit, func(int) *url.URL { return u })
}

func uriCert(t testing.TB, limit int, name func(i int) *url.URL) []byte {
	t.Helper()
	material(t)
	return uriCertFor(t, limit, name, mat.priv.Public())
}

// uriCertFor certifies pub, signed by the material key (nothing verifies the
// signature): the leaf that matches a private key under test.
func uriCertFor(t testing.TB, limit int, name func(i int) *url.URL, pub crypto.PublicKey) []byte {
	t.Helper()
	material(t)
	build := func(n int) []byte {
		uris := make([]*url.URL, n)
		for i := range uris {
			uris[i] = name(i)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "leaf"},
			NotBefore:    time.Unix(1_700_000_000, 0),
			NotAfter:     time.Unix(4_000_000_000, 0),
			URIs:         uris,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, mat.priv)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	// The signature has a fixed size, so the length is linear in the names.
	base, more := len(build(100)), len(build(200))
	n := 100 + (limit-base)*100/(more-base)
	for {
		der := build(n)
		if len(der) <= limit {
			return der
		}
		n--
	}
}

// rsaFixture is one real RSA key and its self-signed certificate.
type rsaFixture struct {
	p8, cert []byte
	bits     int
}

func realRSA(t testing.TB, p8 []byte) rsaFixture {
	t.Helper()
	k, err := x509.ParsePKCS8PrivateKey(p8)
	if err != nil {
		t.Fatal(err)
	}
	rk := k.(*rsa.PrivateKey)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa"},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(4_000_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, rk.Public(), crypto.Signer(rk))
	if err != nil {
		t.Fatal(err)
	}
	return rsaFixture{p8: p8, cert: der, bits: rk.N.BitLen()}
}

func (f rsaFixture) file() []byte {
	return fileOf(pw, dataCI(keyBagDER(f.p8), certBagDER(f.cert))) // the key first: its refusal leaves the certificate unread
}

func rsa4096(t testing.TB) rsaFixture {
	t.Helper()
	p8, err := os.ReadFile("testdata/rsa4096.p8")
	if err != nil {
		t.Fatal(err)
	}
	return realRSA(t, p8)
}

func rsa2048(t testing.TB) rsaFixture {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return realRSA(t, p8)
}

// absoluteBound is the most a Decode may allocate whatever the input: 64 bytes
// for every byte x509 may be handed, which is above the 52x measured for a
// certificate of tiny names.
const absoluteBound = 64 * DefaultMaxCertBytes

func decodeAlloc(t *testing.T, in []byte, o *Options) (b *Bundle, err error, alloc uint64) {
	t.Helper()
	alloc = allocOf(func() { b, err = Decode(in, pw, o) })
	return
}

func TestLargeValidCertificateDecodes(t *testing.T) {
	material(t)
	var worst float64
	for _, size := range []int{4 << 10, 16 << 10, DefaultMaxCertSize} {
		c := bigCert(t, size)
		if size == DefaultMaxCertSize && len(c) < size-64 {
			t.Fatalf("certificate of %d bytes does not reach the cap %d", len(c), size)
		}
		in := fileOf(pw, dataCI(certBagDER(c), keyBagDER(mat.p8)))
		b, err, a := decodeAlloc(t, in, nil)
		if err != nil {
			t.Fatalf("%d: %v", len(c), err)
		}
		if len(b.Certificate.URIs) < 100 {
			t.Fatalf("only %d names parsed", len(b.Certificate.URIs))
		}
		r := float64(a) / float64(len(in))
		t.Logf("one certificate of %6d B (file %6d B, %5d names): alloc %9d B, ratio %5.1f", len(c), len(in), len(b.Certificate.URIs), a, r)
		if r > worst {
			worst = r
		}
		if a > absoluteBound {
			t.Errorf("alloc %d exceeds the absolute bound %d", a, absoluteBound)
		}
	}
	if worst > maxCertRatio {
		t.Errorf("ratio %.1f exceeds %.0f", worst, maxCertRatio)
	}
}

// maxCertRatio is what crypto/x509 itself costs for a certificate of tiny
// names: 36x of the file for names of 5 bytes, 43x (47x layered) for names of
// 2 bytes (TestWorstCaseFamily), 48 to 52x in the external review's first
// probe (20 000 names, since refused). It cannot be lowered from outside, which is
// why the absolute bytes handed to it are bounded instead.
const maxCertRatio = 64.0

func TestFullChainOfLargeCertificatesDecodes(t *testing.T) {
	material(t)
	c := bigCert(t, DefaultMaxCertSize)
	bags := [][]byte{certBagDER(mat.cert), keyBagDER(mat.p8)}
	total := len(mat.cert)
	for total+len(c) <= DefaultMaxCertBytes {
		bags = append(bags, certBagDER(c))
		total += len(c)
	}
	in := fileOf(pw, dataCI(bags...))
	b, err, a := decodeAlloc(t, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := float64(a) / float64(len(in))
	t.Logf("%d certificates, %d B of DER (file %d B): alloc %d B, ratio %.1f", 1+len(b.CACerts), total, len(in), a, r)
	if a > absoluteBound {
		t.Errorf("alloc %d exceeds the absolute bound %d", a, absoluteBound)
	}
	if r > maxCertRatio {
		t.Errorf("ratio %.1f exceeds %.0f", r, maxCertRatio)
	}
}

func TestLargeValidRSAKeyDecodes(t *testing.T) {
	for _, f := range []rsaFixture{rsa2048(t), rsa4096(t)} {
		in := f.file()
		_, err, a := decodeAlloc(t, in, nil)
		if err != nil {
			t.Fatalf("%d bits: %v", f.bits, err)
		}
		r := float64(a) / float64(len(in))
		t.Logf("RSA %d: file %d B, alloc %d B, ratio %.1f", f.bits, len(in), a, r)
		if a > 4<<20 {
			t.Errorf("RSA %d: alloc %d exceeds 4 MiB", f.bits, a)
		}
		if r > maxRatio*4 {
			t.Errorf("RSA %d: ratio %.1f", f.bits, r)
		}
	}
}

func TestCertSizeLimit(t *testing.T) {
	c := bigCert(t, 8<<10)
	in := fileOf(pw, dataCI(certBagDER(c), keyBagDER(mat.p8)))
	mustDecode(t, in, pw, &Options{MaxCertSize: len(c)})
	safely(t, func() {
		spy := spyStdlib(t)
		_, err := Decode(in, pw, &Options{MaxCertSize: len(c) - 1})
		wantErr(t, err, ErrLimit, "certificate of")
		spy.want(t, 0, 0)
	})
}

func TestCertBytesLimit(t *testing.T) {
	material(t)
	const k = 5
	bags := [][]byte{certBagDER(mat.cert), keyBagDER(mat.p8)}
	for i := 0; i < k; i++ {
		bags = append(bags, certBagDER(mat.other))
	}
	in := fileOf(pw, dataCI(bags...))
	total := len(mat.cert) + k*len(mat.other)
	mustDecode(t, in, pw, &Options{MaxCertBytes: total})
	_, err := Decode(in, pw, &Options{MaxCertBytes: total - 1})
	wantErr(t, err, ErrLimit, "certificates exceed")
}

func TestCertLimitsRefuseBeforeStdlib(t *testing.T) {
	big := bigCert(t, DefaultMaxCertSize)
	// One certificate over the cap, and many under it that add up past the total.
	over := append(append([]byte{}, big...), make([]byte, DefaultMaxCertSize)...)
	safely(t, func() {
		spy := spyStdlib(t)
		_, err := Decode(fileOf(pw, dataCI(certBagDER(over))), pw, nil)
		wantErr(t, err, ErrLimit, "certificate of")
		spy.want(t, 0, 0)
		var bags [][]byte
		fit := DefaultMaxCertBytes / len(big)
		for i := 0; i <= fit; i++ {
			bags = append(bags, certBagDER(big))
		}
		_, err = Decode(fileOf(pw, dataCI(bags...)), pw, nil)
		wantErr(t, err, ErrLimit, "certificates exceed")
		spy.want(t, fit, 0) // the one that tips the total is never parsed
	})
}

func TestMaxRSABitsLimit(t *testing.T) {
	f := rsa4096(t)
	in := f.file()
	mustDecode(t, in, pw, &Options{MaxRSABits: 4096})
	safely(t, func() {
		spy := spyStdlib(t)
		_, err := Decode(in, pw, &Options{MaxRSABits: 4095})
		wantErr(t, err, ErrLimit, "RSA modulus of 4096 bits")
		spy.want(t, 0, 0)
	})
}

// bitsOf returns a number of exactly n bits; 0 is zero and negative n is -1.
func bitsOf(n int) *big.Int {
	switch {
	case n == 0:
		return new(big.Int)
	case n < 0:
		return big.NewInt(-1)
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(n-1))
}

// fakeRSA is an RSAPrivateKey whose numbers have the stated sizes and no other
// property: the pre-flight reads sizes only.
type fakeRSA struct{ n, p, q, d, dp, dq, qinv int }

var baseRSA = fakeRSA{n: 64, p: 32, q: 32, d: 64, dp: 32, dq: 32, qinv: 32}

func (f fakeRSA) p8(extra ...asn1.RawValue) []byte {
	inner, err := asn1.Marshal(struct {
		Version int
		N       *big.Int
		E       int
		D       *big.Int
		P, Q    *big.Int
		Dp, Dq  *big.Int
		Qinv    *big.Int
		Extra   []asn1.RawValue `asn1:"optional,omitempty"`
	}{0, bitsOf(f.n), 65537, bitsOf(f.d), bitsOf(f.p), bitsOf(f.q), bitsOf(f.dp), bitsOf(f.dq), bitsOf(f.qinv), extra})
	if err != nil {
		panic(err)
	}
	return p8Of(oidRSAEncryption, inner)
}

func p8Of(oid asn1.ObjectIdentifier, key []byte) []byte {
	der, err := asn1.Marshal(struct {
		Version int
		Algo    pkix.AlgorithmIdentifier
		Key     []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue}, key})
	if err != nil {
		panic(err)
	}
	return der
}

func TestPreflightKey(t *testing.T) {
	material(t)
	with := func(f func(*fakeRSA)) fakeRSA { r := baseRSA; f(&r); return r }
	cases := []struct {
		name string
		k    fakeRSA
		want error // nil: accepted
	}{
		// Sizes inside every bound but numbers that are not a key: the CRT check
		// (pkcs12#2) refuses them, a real key is accepted in TestWrongCRTValues...
		{"sizes within the bounds, CRT values not matching", baseRSA, ErrMalformed},
		{"modulus over the cap", with(func(r *fakeRSA) { r.n = 65 }), ErrLimit},
		{"factors as long as the modulus plus one bit", with(func(r *fakeRSA) { r.p = 33 }), ErrMalformed},
		{"factors longer than the modulus allows", with(func(r *fakeRSA) { r.p, r.q = 33, 33 }), ErrMalformed},
		{"private exponent as long as the modulus", baseRSA, ErrMalformed},
		{"private exponent too long", with(func(r *fakeRSA) { r.d = 65 }), ErrMalformed},
		{"dp too long", with(func(r *fakeRSA) { r.dp = 33 }), ErrMalformed},
		{"dq too long", with(func(r *fakeRSA) { r.dq = 33 }), ErrMalformed},
		{"qinv too long", with(func(r *fakeRSA) { r.qinv = 33 }), ErrMalformed},
		{"a zero factor", with(func(r *fakeRSA) { r.p = 0 }), ErrMalformed},
		{"a zero exponent, which no size check can see", with(func(r *fakeRSA) { r.dp = 0 }), ErrMalformed},
		{"a negative exponent", with(func(r *fakeRSA) { r.d = -1 }), ErrMalformed},
		{"huge factors", with(func(r *fakeRSA) { r.p, r.q = 20000, 20000 }), ErrMalformed},
	}
	for _, c := range cases {
		safely(t, func() {
			err := preflightKey(c.k.p8(), 64)
			if c.want == nil {
				if err != nil {
					t.Errorf("%s: %v", c.name, err)
				}
				return
			}
			if !isOnly(err, c.want) {
				t.Errorf("%s: got %v, want %v", c.name, err, c.want)
			}
		})
	}
	safely(t, func() {
		extra := asn1.RawValue{FullBytes: seq(integer(3), integer(3), integer(3))}
		wantErr(t, preflightKey(baseRSA.p8(extra), 64), ErrUnsupported, "multi-prime")
		wantErr(t, preflightKey([]byte{1, 2, 3}, 64), ErrMalformed, "private key")
		wantErr(t, preflightKey(p8Of(oidRSAEncryption, []byte{1, 2, 3}), 64), ErrMalformed, "RSA private key")
		if err := preflightKey(mat.p8, 64); err != nil {
			t.Errorf("Ed25519: %v", err)
		}
	})
}

func TestPreflightKeySize(t *testing.T) {
	material(t)
	pad := func(n int) []byte { return append(append([]byte{}, mat.p8...), make([]byte, n-len(mat.p8))...) }
	safely(t, func() {
		if err := preflightKey(pad(maxKeyDER), 64); err != nil {
			t.Errorf("a key of exactly %d bytes: %v", maxKeyDER, err)
		}
		wantErr(t, preflightKey(pad(maxKeyDER+1), 64), ErrLimit, "private key of")
	})
}

// TestHostileRSAKeyIsRefusedBeforeStdlib is the CPU test: crypto/rsa validates
// by arithmetic on declared numbers, so a key whose factors are far longer
// than its modulus must never reach it. It decodes (the MAC is valid) into a
// refusal, with the stdlib parser forbidden and a small absolute allocation.
func TestHostileRSAKeyIsRefusedBeforeStdlib(t *testing.T) {
	material(t)
	hostile := []struct {
		name string
		k    fakeRSA
		want error
	}{
		{"factors 5 KB each, modulus 2048 bits", fakeRSA{n: 2048, p: 40000, q: 40000, d: 2048, dp: 2048, dq: 2048, qinv: 2048}, ErrMalformed},
		{"exponents 5 KB, modulus 2048 bits", fakeRSA{n: 2048, p: 1024, q: 1024, d: 40000, dp: 1024, dq: 1024, qinv: 1024}, ErrMalformed},
		{"modulus over the cap", fakeRSA{n: 16384, p: 8192, q: 8192, d: 16384, dp: 8192, dq: 8192, qinv: 8192}, ErrLimit},
	}
	for _, h := range hostile {
		safely(t, func() {
			spy := spyStdlib(t)
			in := fileOf(pw, dataCI(keyBagDER(h.k.p8()), certBagDER(mat.cert)))
			_, err, a := decodeAlloc(t, in, nil)
			if !isOnly(err, h.want) {
				t.Fatalf("%s: got %v, want %v", h.name, err, h.want)
			}
			spy.want(t, 0, 0)
			t.Logf("%s: file %d B, alloc %d B", h.name, len(in), a)
			if a > 1<<20 {
				t.Errorf("%s: alloc %d exceeds 1 MiB", h.name, a)
			}
		})
	}
	// A key over the size cap, of every type, is refused the same way.
	safely(t, func() {
		spy := spyStdlib(t)
		big := p8Of(oidRSAEncryption, make([]byte, maxKeyDER))
		in := fileOf(pw, dataCI(keyBagDER(big), certBagDER(mat.cert)))
		_, err := Decode(in, pw, nil)
		wantErr(t, err, ErrLimit, "private key of")
		spy.want(t, 0, 0)
	})
}

// A well-formed envelope that crypto/x509 itself refuses (an algorithm it does
// not know) still ends in the typed refusal.
func TestStdlibRefusalOfAKeyIsTyped(t *testing.T) {
	material(t)
	safely(t, func() {
		unknown := p8Of(asn1.ObjectIdentifier{1, 2, 3, 4}, []byte{1, 2, 3})
		_, err := Decode(fileOf(pw, dataCI(keyBagDER(unknown), certBagDER(mat.cert))), pw, nil)
		wantErr(t, err, ErrMalformed, "private key")
	})
}

func TestECAndEd25519KeysCostLittle(t *testing.T) {
	material(t)
	_, err, a := decodeAlloc(t, goodFile(t, pw), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Ed25519 file: alloc %d B", a)
	if a > 512<<10 {
		t.Errorf("Ed25519: alloc %d exceeds 512 KiB", a)
	}
}
