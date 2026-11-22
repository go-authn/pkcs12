package pkcs12

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// A test-only ASN.1 builder: crafted files whose every field can be bent.

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func tlv(id byte, content []byte) []byte {
	n := len(content)
	var hdr []byte
	switch {
	case n < 0x80:
		hdr = []byte{id, byte(n)}
	case n < 1<<8:
		hdr = []byte{id, 0x81, byte(n)}
	case n < 1<<16:
		hdr = []byte{id, 0x82, byte(n >> 8), byte(n)}
	case n < 1<<24:
		hdr = []byte{id, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		hdr = []byte{id, 0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(hdr, content...)
}

// indef is a constructed element of indefinite length.
func indef(id byte, parts ...[]byte) []byte {
	return cat([]byte{id, 0x80}, cat(parts...), []byte{0, 0})
}

func seq(parts ...[]byte) []byte { return tlv(0x30, cat(parts...)) }
func set(parts ...[]byte) []byte { return tlv(0x31, cat(parts...)) }
func oct(b []byte) []byte        { return tlv(0x04, b) }
func oidDER(c []byte) []byte     { return tlv(0x06, c) }
func null() []byte               { return []byte{5, 0} }
func ctx(n int, parts ...[]byte) []byte {
	return tlv(0xa0|byte(n), cat(parts...))
}

func integer(v int64) []byte {
	var b []byte
	for x := v; ; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
		if r := x >> 8; (r == 0 && b[0]&0x80 == 0) || (r == -1 && b[0]&0x80 != 0) {
			break
		}
	}
	return tlv(0x02, b)
}

func algDER(oid []byte, params ...[]byte) []byte { return seq(oidDER(oid), cat(params...)) }

// material is one key and two certificates, made once.
var (
	matOnce sync.Once
	mat     struct {
		priv  ed25519.PrivateKey
		p8    []byte
		cert  []byte // matches priv
		other []byte // an unrelated certificate
	}
)

func material(t testing.TB) {
	t.Helper()
	matOnce.Do(func() {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		mk := func(serial int64, cn string, pub ed25519.PublicKey, signer ed25519.PrivateKey) []byte {
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(serial),
				Subject:      pkix.Name{CommonName: cn},
				NotBefore:    time.Unix(1_700_000_000, 0),
				NotAfter:     time.Unix(4_000_000_000, 0),
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
			if err != nil {
				t.Fatal(err)
			}
			return der
		}
		mat.priv = priv
		mat.p8, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		mat.cert = mk(1, "leaf", pub, priv)
		opub, opriv, _ := ed25519.GenerateKey(rand.Reader)
		mat.other = mk(2, "other", opub, opriv)
	})
}

// encodeOtherKey is a second PKCS#8 key.
func encodeOtherKey() ([]byte, error) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(k)
}

func bagDER(id, val []byte, attrs ...[]byte) []byte {
	parts := [][]byte{oidDER(id), ctx(0, val)}
	if len(attrs) > 0 {
		parts = append(parts, set(attrs...))
	}
	return seq(parts...)
}

func certBagDER(der []byte) []byte {
	return bagDER(oidCertBag, seq(oidDER(oidX509Certificate), ctx(0, oct(der))))
}
func keyBagDER(p8 []byte) []byte { return bagDER(oidKeyBag, p8) }

// dataCI is a ContentInfo of type data holding the bags as a SafeContents.
func dataCI(bags ...[]byte) []byte {
	return seq(oidDER(oidData), ctx(0, oct(seq(bags...))))
}

// macSpecT describes a classic (B.2) MAC.
type macSpecT struct {
	oid         []byte
	spec        hashSpec
	salt        []byte
	iter        int64
	pw          string
	absent      bool // no password at all: zero bytes, not the empty BMPString
	defaultIter bool // leave the iteration count out (DEFAULT 1); iter must be 1
}

func sha1MAC(pw string) macSpecT {
	return macSpecT{oid: oidSHA1, spec: specSHA1, salt: []byte("saltsalt"), iter: 3, pw: pw}
}

func (m macSpecT) digest(content []byte) []byte {
	pw := bmpPassword(m.pw)
	if m.absent {
		pw = nil
	}
	key := pkcs12KDF(m.spec.new, m.spec.u, m.spec.v, m.salt, pw, int(m.iter), 3, m.spec.u)
	h := hmac.New(m.spec.new, key)
	h.Write(content)
	return h.Sum(nil)
}

func (m macSpecT) der(content []byte) []byte {
	parts := [][]byte{seq(algDER(m.oid, null()), oct(m.digest(content))), oct(m.salt)}
	if !m.defaultIter {
		parts = append(parts, integer(m.iter))
	}
	return seq(parts...)
}

// pfxDER assembles a PFX around authSafe (the DER of the AuthenticatedSafe).
func pfxDER(version int64, authType, authSafe []byte, tail ...[]byte) []byte {
	return seq(integer(version), seq(oidDER(authType), ctx(0, oct(authSafe))), cat(tail...))
}

// goodFile is a MAC'd file with the key bag and the matching certificate.
func goodFile(t testing.TB, pw string) []byte {
	material(t)
	safe := seq(dataCI(certBagDER(mat.cert), keyBagDER(mat.p8)))
	return pfxDER(3, oidData, safe, sha1MAC(pw).der(safe))
}

// fileOf is a MAC'd file around the given ContentInfos.
func fileOf(pw string, cis ...[]byte) []byte {
	safe := seq(cis...)
	return pfxDER(3, oidData, safe, sha1MAC(pw).der(safe))
}

// safely runs f and turns a panic into a named failure. A refusal test that
// lets a panic through goes red whatever guard was removed, so it holds none:
// the sweep reports that as luck.
func safely(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic instead of a refusal: %v", r)
		}
	}()
	f()
}

func wantErr(t *testing.T, err, sentinel error, substr string) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want %v", err, sentinel)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not mention %q", err, substr)
	}
}
