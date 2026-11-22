package pkcs12

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 2268 section 5.
func TestRC2Vectors(t *testing.T) {
	for _, v := range []struct {
		key  string
		bits int
		pt   string
		ct   string
	}{
		{"0000000000000000", 63, "0000000000000000", "ebb773f993278eff"},
		{"ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"},
		{"3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"},
		{"88", 64, "0000000000000000", "61a8a244adacccf0"},
		{"88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"},
		{"88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"},
		{"88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"},
		{"88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e", 129, "0000000000000000", "5b78d3a43dfff1f1"},
	} {
		t.Run(v.key[:2]+"/"+v.ct, func(t *testing.T) {
			safely(t, func() {
				c, err := newRC2(unhex(t, v.key), v.bits)
				if err != nil {
					t.Fatal(err)
				}
				if c.BlockSize() != 8 {
					t.Fatalf("block size %d", c.BlockSize())
				}
				pt, ct := unhex(t, v.pt), unhex(t, v.ct)
				got := make([]byte, 8)
				c.Encrypt(got, pt)
				if !bytes.Equal(got, ct) {
					t.Fatalf("encrypt %x, want %x", got, ct)
				}
				c.Decrypt(got, ct)
				if !bytes.Equal(got, pt) {
					t.Fatalf("decrypt %x, want %x", got, pt)
				}
			})
		})
	}
}

func TestRC2KeySizes(t *testing.T) {
	for _, tc := range []struct {
		n, bits int
		ok      bool
	}{{0, 64, false}, {129, 64, false}, {8, 0, false}, {8, 1025, false}, {1, 1, true}, {128, 1024, true}} {
		var err error
		safely(t, func() { _, err = newRC2(make([]byte, tc.n), tc.bits) })
		if (err == nil) != tc.ok {
			t.Errorf("key %d bytes, %d bits: %v", tc.n, tc.bits, err)
		}
	}
}

// Vectors from golang.org/x/crypto/pkcs12 (BSD-3, Go Authors), through
// SSLMate/go-pkcs12's copy of its tests.
func TestPKCS12KDFVectors(t *testing.T) {
	safely(t, func() {
		got := pkcs12KDF(specSHA1.new, 20, 64, bytes.Repeat([]byte{0xff}, 8), bmpPassword("sesame"), 2048, 1, 24)
		want := unhex(t, "7cd9fd3e2b3be7691a44e3bef0f9ea0fb9b897d4e325d9d1")
		if !bytes.Equal(got, want) {
			t.Fatalf("long key: %x, want %x", got, want)
		}
		// I_j with a leading zero byte after step 6C.
		got = pkcs12KDF(specSHA1.new, 20, 64, unhex(t, "f37e05b518324b4b"), []byte{0, 0}, 2048, 1, 24)
		want = unhex(t, "00f759ff47d14dd03665d5943cb3c4a39a2555c02aed66e1")
		if !bytes.Equal(got, want) {
			t.Fatalf("leading zeros: %x, want %x", got, want)
		}
	})
}

func TestKDFEmptyInputs(t *testing.T) {
	safely(t, func() {
		// No salt and no password: I is empty, the derivation still runs.
		a := pkcs12KDF(specSHA256.new, 32, 64, nil, nil, 2, 3, 40)
		b := pkcs12KDF(specSHA256.new, 32, 64, nil, nil, 2, 3, 40)
		if len(a) != 40 || !bytes.Equal(a, b) {
			t.Fatal("empty derivation is not deterministic or the wrong length")
		}
		if stretch(nil, 64) != nil {
			t.Fatal("stretch(nil) is not nil")
		}
		if s := stretch([]byte{1, 2, 3}, 4); !bytes.Equal(s, []byte{1, 2, 3, 1}) {
			t.Fatalf("stretch = %v", s)
		}
	})
}

func TestBMPPassword(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "0000"},
		{"Beavis", "00420065006100760069007300" + "00"},
		{"é", "00e90000"},
		{"\U0001F600", "d83dde000000"}, // outside the BMP: a surrogate pair
	} {
		if got := hex.EncodeToString(bmpPassword(tc.in)); got != tc.want {
			t.Errorf("%q: %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestPasswordForms(t *testing.T) {
	f, err := passwordForms("", &Options{})
	if err != nil || len(f) != 2 || len(f[0].bmp) != 2 || f[1].bmp != nil || f[1].utf8 != nil {
		t.Fatalf("empty password: %+v, %v", f, err)
	}
	f, err = passwordForms("", &Options{NoPassword: true})
	if err != nil || len(f) != 1 || f[0].bmp != nil {
		t.Fatalf("no password: %+v, %v", f, err)
	}
	f, err = passwordForms("é", &Options{})
	if err != nil || len(f) != 1 || string(f[0].utf8) != "é" {
		t.Fatalf("one password: %+v, %v", f, err)
	}
	for name, tc := range map[string]struct {
		pw string
		o  Options
	}{
		"no password with a password": {"x", Options{NoPassword: true}},
		"invalid UTF-8":               {"\xff", Options{}},
		"too long":                    {strings.Repeat("a", maxPasswordRunes+1), Options{}},
	} {
		if _, err := passwordForms(tc.pw, &tc.o); err != ErrPassword {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := passwordForms(strings.Repeat("a", maxPasswordRunes), &Options{}); err != nil {
		t.Errorf("a password at the limit: %v", err)
	}
}

func TestOIDString(t *testing.T) {
	long := append([]byte{0x2a}, bytes.Repeat([]byte{0x01}, 40)...)
	for _, tc := range []struct {
		in   []byte
		want string
	}{
		{nil, "(empty)"},
		{mustOID(1, 2, 840, 113549), "1.2.840.113549"},
		{mustOID(2, 16, 840, 1, 101, 3, 4, 2, 1), "2.16.840.1.101.3.4.2.1"},
		{mustOID(1, 3, 6, 1, 4, 1, 311, 17, 3, 20), "1.3.6.1.4.1.311.17.3.20"},
		{long, "1.2." + strings.Repeat("1.", 31) + "1.…"},
	} {
		safely(t, func() {
			if got := oidString(tc.in); got != tc.want {
				t.Errorf("%x: %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestMustOIDLargeArc(t *testing.T) {
	safely(t, func() {
		if got := hex.EncodeToString(mustOID(1, 2, 840, 113549)); got != "2a864886f70d" {
			t.Fatalf("got %s", got)
		}
	})
}

func TestHashTables(t *testing.T) {
	digests := map[string][]byte{"sha1": oidSHA1, "sha224": oidSHA224, "sha256": oidSHA256, "sha384": oidSHA384, "sha512": oidSHA512}
	hmacs := map[string][]byte{"sha1": oidHMACSHA1, "sha224": oidHMACSHA224, "sha256": oidHMACSHA256, "sha384": oidHMACSHA384, "sha512": oidHMACSHA512}
	sizes := map[string]int{"sha1": 20, "sha224": 28, "sha256": 32, "sha384": 48, "sha512": 64}
	for name, size := range sizes {
		for kind, oid := range map[string][]byte{"digest": digests[name], "hmac": hmacs[name]} {
			look := digestSpec
			if kind == "hmac" {
				look = hmacSpec
			}
			spec, ok := look(oid)
			if !ok || spec.u != size || spec.new().Size() != size {
				t.Errorf("%s %s: %+v %v", kind, name, spec, ok)
			}
		}
	}
	if _, ok := digestSpec(mustOID(1, 2, 3)); ok {
		t.Error("unknown digest accepted")
	}
	if _, ok := hmacSpec(mustOID(1, 2, 3)); ok {
		t.Error("unknown HMAC accepted")
	}
}
