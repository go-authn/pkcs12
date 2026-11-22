package pkcs12

import (
	"bytes"
	"testing"
)

// Each bound is tested on BOTH sides of its edge: a value at the limit is
// accepted, one past it is refused. A test of only the refusal cannot tell
// "> limit" from ">= limit".

func TestChargeAtTheLimit(t *testing.T) {
	s := &state{opts: (&Options{MaxIterations: 10, MaxWork: 20}).resolve()}
	if err := s.charge(10, 2); err != nil {
		t.Fatalf("work of exactly MaxWork refused: %v", err)
	}
	wantErr(t, s.charge(1, 1), ErrLimit, "key derivation work")
}

func TestAuthSafesAtTheLimit(t *testing.T) {
	material(t)
	build := func(n int) []byte {
		cis := [][]byte{dataCI(certBagDER(mat.cert), keyBagDER(mat.p8))}
		for len(cis) < n {
			cis = append(cis, dataCI())
		}
		return fileOf(pw, cis...)
	}
	opts := &Options{MaxAuthSafes: 5}
	safely(t, func() {
		if _, err := Decode(build(5), pw, opts); err != nil {
			t.Fatalf("exactly MaxAuthSafes ContentInfos: %v", err)
		}
		_, err := Decode(build(6), pw, opts)
		wantErr(t, err, ErrLimit, "ContentInfos")
	})
}

func TestSaltsAtTheLimit(t *testing.T) {
	material(t)
	salt := bytes.Repeat([]byte{7}, maxSaltLen)
	safely(t, func() {
		// MAC salt.
		m := sha1MAC(pw)
		m.salt = salt
		safe := seq(dataCI(certBagDER(mat.cert), keyBagDER(mat.p8)))
		if _, err := Decode(pfxDER(3, oidData, safe, m.der(safe)), pw, nil); err != nil {
			t.Fatalf("MAC salt of %d bytes: %v", maxSaltLen, err)
		}
		// Legacy PBE salt.
		ct := sealLegacy(pw, salt, 2, mat.p8)
		file := fileWithKeyBag(t, pw, shroudedBag(legacyAlg(oidPBE3DES, salt, 2), ct))
		if _, err := Decode(file, pw, nil); err != nil {
			t.Fatalf("PBE salt of %d bytes: %v", maxSaltLen, err)
		}
		// PBKDF2 salt.
		p := aesP2(16)
		p.salt = salt
		file = fileWithKeyBag(t, pw, shroudedBag(p.alg(), p.seal(t, pw, pad(append([]byte{}, mat.p8...), 16))))
		if _, err := Decode(file, pw, nil); err != nil {
			t.Fatalf("PBKDF2 salt of %d bytes: %v", maxSaltLen, err)
		}
	})
}

// A PBE whose parameters are complete but followed by something else is
// refused before its iteration count is charged.
func TestLegacyPBEBooksNothingOnTrailingParameters(t *testing.T) {
	s := &state{opts: (&Options{}).resolve()}
	c, err := cur(algDER(oidPBE3DES, seq(oct([]byte("salt")), integer(900_000), null())))
	a := c.algID("alg")
	if *err != nil {
		t.Fatal(*err)
	}
	safely(t, func() { s.legacyPBE(a, passwordForm{}, c) })
	wantErr(t, *err, ErrMalformed, "PBE parameters")
	if s.work != 0 {
		t.Fatalf("%d units of work booked", s.work)
	}
}

// Truncating a valid file at every length is refused, never a panic: this is
// what holds the length checks of the BER reader.
func TestEveryTruncationIsRefused(t *testing.T) {
	for _, name := range []string{"rsa-default", "rsa-legacy", "rsa-pbmac1", "ec-default"} {
		data := readFixture(t, "openssl/"+name+".p12")
		for n := 0; n < len(data); n++ {
			safely(t, func() {
				if _, err := Decode(data[:n], "x", nil); err == nil {
					t.Fatalf("%s truncated to %d bytes was accepted", name, n)
				}
			})
		}
	}
}

// Things that went through an index of an empty slice when a guard was gone.
func TestEmptyElementsAreRefused(t *testing.T) {
	material(t)
	safe := seq(dataCI(certBagDER(mat.cert), keyBagDER(mat.p8)))
	m := sha1MAC(pw)
	empty := m
	empty.oid = []byte{}
	p := aesP2(16)
	ct := p.seal(t, pw, pad(append([]byte{}, mat.p8...), 16))
	withParams := func(kdfParams []byte) []byte {
		return fileWithKeyBag(t, pw, shroudedBag(algDER(oidPBES2, seq(algDER(oidPBKDF2, kdfParams), algDER(p.enc, oct(p.iv)))), ct))
	}
	runRefusals(t, []refusal{
		{"empty INTEGER version", seq(tlv(0x02, nil), seq(oidDER(oidData), ctx(0, oct(safe))), m.der(safe)), ErrMalformed, "empty INTEGER"},
		{"empty MAC digest OID", pfxDER(3, oidData, safe, empty.der(safe)), ErrUnsupported, "(empty)"},
		{"empty PBKDF2 parameters", withParams(seq()), ErrMalformed, "PBKDF2 salt"},
	})
}
