package pkcs12

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"hash"
	"strings"
	"testing"
)

const pw = "pw"

func mustDecode(t *testing.T, data []byte, password string, o *Options) *Bundle {
	t.Helper()
	b, err := Decode(data, password, o)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func checkKey(t *testing.T, b *Bundle) {
	t.Helper()
	k, ok := b.PrivateKey.(ed25519.PrivateKey)
	if !ok || !k.Equal(mat.priv) {
		t.Fatalf("wrong private key %T", b.PrivateKey)
	}
	if !bytes.Equal(b.Certificate.Raw, mat.cert) {
		t.Fatal("wrong certificate")
	}
}

func TestCraftedHappyPaths(t *testing.T) {
	material(t)
	safe := seq(dataCI(certBagDER(mat.cert), keyBagDER(mat.p8)))

	t.Run("plain bags", func(t *testing.T) {
		b := mustDecode(t, goodFile(t, pw), pw, nil)
		checkKey(t, b)
		if len(b.CACerts) != 0 {
			t.Fatal("unexpected CA certificates")
		}
	})
	t.Run("chain keeps file order and skips the leaf", func(t *testing.T) {
		f := fileOf(pw, dataCI(certBagDER(mat.other), certBagDER(mat.cert), keyBagDER(mat.p8), certBagDER(mat.other)))
		b := mustDecode(t, f, pw, nil)
		checkKey(t, b)
		if len(b.CACerts) != 2 || !bytes.Equal(b.CACerts[0].Raw, mat.other) || !bytes.Equal(b.CACerts[1].Raw, mat.other) {
			t.Fatalf("CACerts = %d", len(b.CACerts))
		}
	})
	t.Run("MAC digests", func(t *testing.T) {
		for name, m := range map[string]macSpecT{
			"sha224": {oid: oidSHA224, spec: specSHA224},
			"sha256": {oid: oidSHA256, spec: specSHA256},
			"sha384": {oid: oidSHA384, spec: specSHA384},
			"sha512": {oid: oidSHA512, spec: specSHA512},
		} {
			m.salt, m.iter, m.pw = []byte("s"), 2, pw
			mustDecode(t, pfxDER(3, oidData, safe, m.der(safe)), pw, nil)
			t.Log(name)
		}
	})
	t.Run("MAC iteration count defaults to 1", func(t *testing.T) {
		m := sha1MAC(pw)
		m.iter, m.defaultIter = 1, true
		mustDecode(t, pfxDER(3, oidData, safe, m.der(safe)), pw, nil)
	})
	t.Run("MAC with an empty salt", func(t *testing.T) {
		m := sha1MAC(pw)
		m.salt = nil
		mustDecode(t, pfxDER(3, oidData, safe, m.der(safe)), pw, nil)
	})
	t.Run("empty password, either reading", func(t *testing.T) {
		m := sha1MAC("")
		mustDecode(t, pfxDER(3, oidData, safe, m.der(safe)), "", nil) // BMPString terminator only
		m.absent = true
		mustDecode(t, pfxDER(3, oidData, safe, m.der(safe)), "", nil) // zero bytes
		mustDecode(t, pfxDER(3, oidData, safe, m.der(safe)), "", &Options{NoPassword: true})
		// NoPassword refuses the empty-BMPString reading.
		m.absent = false
		_, err := Decode(pfxDER(3, oidData, safe, m.der(safe)), "", &Options{NoPassword: true})
		wantErr(t, err, ErrIncorrectPassword, "")
	})
	t.Run("unknown bags, attributes and foreign certificates", func(t *testing.T) {
		attr := seq(oidDER(mustOID(1, 2, 840, 113549, 1, 9, 20)), set(tlv(0x1e, []byte{0, 'a'})))
		sdsi := bagDER(oidCertBag, seq(oidDER(mustOID(1, 2, 840, 113549, 1, 9, 22, 2)), ctx(0, oct([]byte("sdsi")))))
		crl := bagDER(with(bagID, 4), seq())
		secret := bagDER(with(bagID, 5), seq())
		nested := bagDER(with(bagID, 6), seq())
		f := fileOf(pw, dataCI(sdsi, crl, secret, nested,
			bagDER(oidCertBag, seq(oidDER(oidX509Certificate), ctx(0, oct(mat.cert))), attr),
			keyBagDER(mat.p8)))
		checkKey(t, mustDecode(t, f, pw, nil))
	})
	t.Run("several ContentInfos", func(t *testing.T) {
		f := fileOf(pw, dataCI(certBagDER(mat.cert)), dataCI(keyBagDER(mat.p8)), dataCI())
		checkKey(t, mustDecode(t, f, pw, nil))
	})
}

func TestShroudedKeys(t *testing.T) {
	material(t)
	for name, p := range map[string]p2{
		"aes128":            aesP2(16),
		"aes192":            aesP2(24),
		"aes256":            aesP2(32),
		"aes256 key length": func() p2 { p := aesP2(32); p.keyLen = 32; return p }(),
		"prf sha256":        func() p2 { p := aesP2(16); p.prf, p.prfHash = oidHMACSHA256, sha256.New; return p }(),
		"prf sha512":        func() p2 { p := aesP2(16); p.prf, p.prfHash = oidHMACSHA512, sha512.New; return p }(),
		"3des": func() p2 {
			p := aesP2(16)
			p.enc, p.iv = oidDESEDE3CBC, make([]byte, 8)
			return p
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			bs := len(p.iv)
			ct := p.seal(t, pw, pad(append([]byte{}, mat.p8...), bs))
			b := mustDecode(t, fileWithKeyBag(t, pw, shroudedBag(p.alg(), ct)), pw, nil)
			checkKey(t, b)
		})
	}
	t.Run("legacy 3DES", func(t *testing.T) {
		salt := []byte("legacysalt")
		ct := sealLegacy(pw, salt, 5, mat.p8)
		checkKey(t, mustDecode(t, fileWithKeyBag(t, pw, shroudedBag(legacyAlg(oidPBE3DES, salt, 5), ct)), pw, nil))
	})
	t.Run("EncryptedData with PBES2 and with legacy PBE", func(t *testing.T) {
		bags := seq(certBagDER(mat.cert), keyBagDER(mat.p8))
		p := aesP2(32)
		ci := encryptedDataCI(p.alg(), p.seal(t, pw, pad(append([]byte{}, bags...), 16)))
		checkKey(t, mustDecode(t, fileOf(pw, ci), pw, nil))
		salt := []byte("s")
		ci = encryptedDataCI(legacyAlg(oidPBE3DES, salt, 2), sealLegacy(pw, salt, 2, bags))
		checkKey(t, mustDecode(t, fileOf(pw, ci), pw, nil))
	})
}

// A file with no MAC: nothing vouches for the password, so a failed
// decryption is reported as a wrong password.
func TestNoMAC(t *testing.T) {
	material(t)
	p := aesP2(16)
	ct := p.seal(t, pw, pad(append([]byte{}, mat.p8...), 16))
	safe := seq(dataCI(certBagDER(mat.cert), shroudedBag(p.alg(), ct)))
	f := pfxDER(3, oidData, safe)

	_, err := Decode(f, pw, nil)
	if err != ErrNoMAC {
		t.Fatalf("got %v, want ErrNoMAC", err)
	}
	checkKey(t, mustDecode(t, f, pw, &Options{AllowNoMAC: true}))
	_, err = Decode(f, "wrong", &Options{AllowNoMAC: true})
	if err != ErrIncorrectPassword {
		t.Fatalf("got %v, want ErrIncorrectPassword", err)
	}
	// Plain bags and no MAC: nothing to decrypt, nothing to check.
	checkKey(t, mustDecode(t, pfxDER(3, oidData, seq(dataCI(certBagDER(mat.cert), keyBagDER(mat.p8)))), "x", &Options{AllowNoMAC: true}))
	// A malformed file with no MAC and nothing decrypted stays malformed.
	_, err = Decode(pfxDER(3, oidData, seq(dataCI(keyBagDER(oct(nil))))), "", &Options{AllowNoMAC: true})
	wantErr(t, err, ErrMalformed, "PrivateKeyInfo")
}

func TestPBMAC1(t *testing.T) {
	material(t)
	safe := seq(dataCI(certBagDER(mat.cert), keyBagDER(mat.p8)))
	build := func(m pbmac1T) []byte { return pfxDER(3, oidData, safe, m.der(t, pw, safe)) }

	for name, mut := range map[string]func(*pbmac1T){
		"sha256": func(*pbmac1T) {},
		"sha224": func(m *pbmac1T) {
			m.prf, m.msg, m.h, m.size, m.keyLen = oidHMACSHA224, oidHMACSHA224, sha256.New224, 28, 28
		},
		"sha384": func(m *pbmac1T) {
			m.prf, m.msg, m.h, m.size, m.keyLen = oidHMACSHA384, oidHMACSHA384, sha512.New384, 48, 48
		},
		"sha512": func(m *pbmac1T) {
			m.prf, m.msg, m.h, m.size, m.keyLen = oidHMACSHA512, oidHMACSHA512, sha512.New, 64, 64
		},
	} {
		t.Run("valid "+name, func(t *testing.T) {
			m := goodPBMAC1()
			mut(&m)
			checkKey(t, mustDecode(t, build(m), pw, nil))
		})
	}

	for _, tc := range []struct {
		name string
		mut  func(*pbmac1T)
		want error
		msg  string
	}{
		{"SHA-1 message authentication", func(m *pbmac1T) { m.msg = oidHMACSHA1 }, ErrUnsupported, "PBMAC1 message"},
		{"unknown message authentication", func(m *pbmac1T) { m.msg = mustOID(1, 2, 3) }, ErrUnsupported, "PBMAC1 message"},
		{"SHA-1 PRF", func(m *pbmac1T) { m.prf = oidHMACSHA1 }, ErrUnsupported, "SHA-1 PRF"},
		{"no key length", func(m *pbmac1T) { m.keyLen = 0 }, ErrMalformed, "no key length"},
		{"short key length", func(m *pbmac1T) { m.keyLen = 16 }, ErrMalformed, "key length 16"},
		{"iteration count over the limit", func(m *pbmac1T) { m.iter = 2_000_000 }, ErrLimit, "iteration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := goodPBMAC1()
			tc.mut(&m)
			// The digest is computed as the file's author would; the refusal
			// is the decoder's.
			f := pfxDER(3, oidData, safe, seq(seq(m.alg(), oct(make([]byte, 32))), oct(nil), integer(1)))
			_, err := Decode(f, pw, nil)
			wantErr(t, err, tc.want, tc.msg)
		})
	}

	t.Run("wrong password", func(t *testing.T) {
		_, err := Decode(build(goodPBMAC1()), "nope", nil)
		if err != ErrIncorrectPassword {
			t.Fatal(err)
		}
	})
	t.Run("tampered content", func(t *testing.T) {
		f := build(goodPBMAC1())
		i := bytes.Index(f, mat.p8[len(mat.p8)-8:])
		f[i]++
		_, err := Decode(f, pw, nil)
		if err != ErrIncorrectPassword {
			t.Fatal(err)
		}
	})

	m := goodPBMAC1()
	msg := algDER(oidHMACSHA256, null())
	kdf := algDER(oidPBKDF2, seq(oct(m.salt), integer(1), integer(32), algDER(oidHMACSHA256, null())))
	for _, tc := range []struct {
		name string
		alg  []byte
		want error
		msg  string
	}{
		{"no parameters", seq(oidDER(oidPBMAC1)), ErrMalformed, "parameters missing"},
		{"parameters not a SEQUENCE", algDER(oidPBMAC1, oct(nil)), ErrMalformed, "not a SEQUENCE"},
		{"trailing parameter", algDER(oidPBMAC1, seq(kdf, msg, null())), ErrMalformed, "PBMAC1 parameters"},
		{"key derivation is not PBKDF2", algDER(oidPBMAC1, seq(algDER(mustOID(1, 2, 3)), msg)), ErrUnsupported, "key derivation function"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := pfxDER(3, oidData, safe, seq(seq(tc.alg, oct(make([]byte, 32))), oct(nil), integer(1)))
			_, err := Decode(f, pw, nil)
			wantErr(t, err, tc.want, tc.msg)
		})
	}
}

func TestPBKDF2Failure(t *testing.T) {
	material(t)
	old := pbkdf2Key
	defer func() { pbkdf2Key = old }()
	p := aesP2(16)
	ct := p.seal(t, pw, pad(append([]byte{}, mat.p8...), 16)) // seal does not use the variable
	pbkdf2Key = func(func() hash.Hash, string, []byte, int, int) ([]byte, error) { return nil, errors.New("fips") }

	var err error
	safely(t, func() { _, err = Decode(fileWithKeyBag(t, pw, shroudedBag(p.alg(), ct)), pw, nil) })
	wantErr(t, err, ErrUnsupported, "PBKDF2: fips")

	safe := seq(dataCI(certBagDER(mat.cert), keyBagDER(mat.p8)))
	safely(t, func() { _, err = Decode(pfxDER(3, oidData, safe, goodPBMAC1().der(t, pw, safe)), pw, nil) })
	wantErr(t, err, ErrUnsupported, "PBKDF2: fips")
}

func TestKeyMatches(t *testing.T) {
	material(t)
	safely(t, func() {
		if _, err := keyMatches(struct{}{}, nil); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("no Public method: %v", err)
		}
	})
	safely(t, func() {
		if _, err := keyMatches(noEqual{}, nil); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("no Equal method: %v", err)
		}
	})
	cert, err := x509.ParseCertificate(mat.cert)
	if err != nil {
		t.Fatal(err)
	}
	s := &state{key: struct{}{}, certs: []*x509.Certificate{cert}}
	if _, err := s.bundle(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("bundle with an unusable key type: %v", err)
	}
}

type noEqual struct{}

func (noEqual) Public() crypto.PublicKey { return struct{}{} }

func TestIterationBounds(t *testing.T) {
	material(t)
	safe := seq(dataCI(certBagDER(mat.cert), keyBagDER(mat.p8)))
	m := sha1MAC(pw)
	build := func(iter int64) []byte {
		m.iter = iter
		return pfxDER(3, oidData, safe, m.der(safe))
	}
	if _, err := Decode(build(5), pw, &Options{MaxIterations: 5}); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	_, err := Decode(build(6), pw, &Options{MaxIterations: 5})
	wantErr(t, err, ErrLimit, "iteration count 6 exceeds the limit of 5")
	_, err = Decode(build(1_000_001), pw, nil)
	wantErr(t, err, ErrLimit, "iteration")
	_, err = Decode(build(0), pw, nil)
	wantErr(t, err, ErrMalformed, "iteration count 0")
	_, err = Decode(build(-3), pw, nil)
	wantErr(t, err, ErrMalformed, "iteration count -3")
	// Work: several derivations, each acceptable alone, add up.
	_, err = Decode(build(5), pw, &Options{MaxWork: 4})
	wantErr(t, err, ErrLimit, "work")
	// A 2^64 count does not even fit an int64.
	huge := seq(seq(algDER(oidSHA1, null()), oct(make([]byte, 20))), oct([]byte("s")), tlv(0x02, append([]byte{1}, make([]byte, 8)...)))
	_, err = Decode(pfxDER(3, oidData, safe, huge), pw, nil)
	wantErr(t, err, ErrLimit, "wider than 64 bits")
}

func TestInputBounds(t *testing.T) {
	f := goodFile(t, pw)
	_, err := Decode(f, pw, &Options{MaxInputSize: len(f) - 1})
	wantErr(t, err, ErrLimit, "input of")
	mustDecode(t, f, pw, &Options{MaxInputSize: len(f)})

	_, err = Decode(f, "\xff", nil)
	if err != ErrPassword {
		t.Fatal(err)
	}
	_, err = Decode(f, strings.Repeat("a", maxPasswordRunes+1), nil)
	if err != ErrPassword {
		t.Fatal(err)
	}
}

func TestBERFile(t *testing.T) {
	material(t)
	safe := seq(dataCI(certBagDER(mat.cert), keyBagDER(mat.p8)))
	m := sha1MAC(pw)
	k := len(safe) / 2
	// The authSafe's content is a constructed OCTET STRING in two chunks, and
	// every wrapper has an indefinite length; the MAC is over the flattened
	// content, so it is the same MAC.
	f := indef(0x30,
		integer(3),
		indef(0x30, oidDER(oidData), indef(0xa0, indef(0x24, oct(safe[:k]), oct(safe[k:])))),
		m.der(safe))
	checkKey(t, mustDecode(t, f, pw, nil))
}

func TestAuthSafeAndBagLimits(t *testing.T) {
	material(t)
	f := fileOf(pw, dataCI(), dataCI(), dataCI())
	_, err := Decode(f, pw, &Options{MaxAuthSafes: 2})
	wantErr(t, err, ErrLimit, "ContentInfos")

	f = fileOf(pw, dataCI(certBagDER(mat.cert), keyBagDER(mat.p8), certBagDER(mat.other)))
	_, err = Decode(f, pw, &Options{MaxBags: 2})
	wantErr(t, err, ErrLimit, "SafeBags")
	mustDecode(t, f, pw, &Options{MaxBags: 3})
}

func TestBundleErrors(t *testing.T) {
	material(t)
	other, err := encodeOtherKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		bags [][]byte
		want error
	}{
		{"no key", [][]byte{certBagDER(mat.cert)}, ErrNoPrivateKey},
		{"no matching certificate", [][]byte{keyBagDER(mat.p8), certBagDER(mat.other)}, ErrNoCertificate},
		{"no certificate", [][]byte{keyBagDER(mat.p8)}, ErrNoCertificate},
		{"two keys", [][]byte{keyBagDER(mat.p8), certBagDER(mat.cert), keyBagDER(other)}, ErrMultipleKeys},
		{"empty", nil, ErrNoPrivateKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(fileOf(pw, dataCI(tc.bags...)), pw, nil)
			if err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
