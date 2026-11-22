package pkcs12

import (
	"bytes"
	"testing"
)

type refusal struct {
	name string
	file []byte
	want error
	msg  string
}

func runRefusals(t *testing.T, cases []refusal) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			safely(t, func() { _, err = Decode(tc.file, pw, nil) })
			if err == nil {
				t.Fatal("accepted")
			}
			wantErr(t, err, tc.want, tc.msg)
		})
	}
}

// TestEnvelopeRefusals bends each field of the PFX and its MacData.
func TestEnvelopeRefusals(t *testing.T) {
	material(t)
	safe := seq(dataCI(certBagDER(mat.cert), keyBagDER(mat.p8)))
	m := sha1MAC(pw)
	mac := m.der(safe)
	auth := seq(oidDER(oidData), ctx(0, oct(safe)))
	digestInfo := seq(algDER(oidSHA1, null()), oct(m.digest(safe)))

	short := m
	short.salt = bytes.Repeat([]byte{1}, maxSaltLen+1)
	unknown := m
	unknown.oid = mustOID(1, 2, 3)

	runRefusals(t, []refusal{
		{"version 2", pfxDER(2, oidData, safe, mac), ErrUnsupported, "version 2"},
		{"version not an integer", seq(oct(nil), auth, mac), ErrMalformed, "PFX version"},
		{"signedData integrity mode", pfxDER(3, oidSignedData, safe, mac), ErrUnsupported, "signedData"},
		{"other authSafe type", pfxDER(3, oidEncryptedData, safe, mac), ErrUnsupported, "authSafe content type"},
		{"authSafe data not an OCTET STRING", seq(integer(3), seq(oidDER(oidData), ctx(0, integer(1))), mac), ErrMalformed, "authSafe data"},
		{"authSafe trailing", seq(integer(3), seq(oidDER(oidData), ctx(0, oct(safe)), null()), mac), ErrMalformed, "authSafe"},
		{"PFX trailing", seq(integer(3), auth, mac, null()), ErrMalformed, "PFX"},
		{"after the PFX", append(pfxDER(3, oidData, safe, mac), 0), ErrMalformed, "PFX"},
		{"MacData trailing", seq(integer(3), auth, seq(digestInfo, oct(m.salt), integer(3), null())), ErrMalformed, "MacData"},
		{"DigestInfo trailing", seq(integer(3), auth, seq(seq(algDER(oidSHA1, null()), oct(m.digest(safe)), null()), oct(m.salt), integer(3))), ErrMalformed, "DigestInfo"},
		{"MAC salt not an OCTET STRING", seq(integer(3), auth, seq(digestInfo, integer(1), integer(3))), ErrMalformed, "MAC salt"},
		{"MAC digest not an OCTET STRING", seq(integer(3), auth, seq(seq(algDER(oidSHA1, null()), integer(1)), oct(m.salt), integer(3))), ErrMalformed, "MAC digest"},
		{"unknown MAC digest", pfxDER(3, oidData, safe, unknown.der(safe)), ErrUnsupported, "MAC digest 1.2.3"},
		{"oversized MAC salt", pfxDER(3, oidData, safe, short.der(safe)), ErrLimit, "MAC salt"},
		{"empty", nil, ErrMalformed, "PFX: missing"},
		{"one byte", []byte{0x30}, ErrMalformed, "truncated"},
		{"not a SEQUENCE", oct(safe), ErrMalformed, "PFX"},
	})
}

// TestSafeRefusals bends the ContentInfos, the EncryptedData and the bags.
func TestSafeRefusals(t *testing.T) {
	material(t)
	cert, key := certBagDER(mat.cert), keyBagDER(mat.p8)
	good := dataCI(cert, key)
	p := aesP2(16)
	ct := p.seal(t, pw, pad([]byte("x"), 16))
	edBody := func(version, inner []byte, alg []byte, content []byte, tail ...[]byte) []byte {
		eci := seq(inner, alg, content, cat(tail...))
		return seq(oidDER(oidEncryptedData), ctx(0, seq(version, eci)))
	}
	data := oidDER(oidData)
	crt := certBagDER
	_ = crt

	runRefusals(t, []refusal{
		{"AuthenticatedSafe is not a SEQUENCE", func() []byte {
			s := integer(1)
			return pfxDER(3, oidData, s, sha1MAC(pw).der(s))
		}(), ErrMalformed, "AuthenticatedSafe"},
		{"ContentInfo is not a SEQUENCE", fileOf(pw, oct(nil)), ErrMalformed, "ContentInfo"},
		{"ContentInfo of an unknown type", fileOf(pw, seq(oidDER(mustOID(1, 2, 3)), ctx(0, oct(nil)))), ErrUnsupported, "ContentInfo type 1.2.3"},
		{"ContentInfo without content", fileOf(pw, seq(data)), ErrMalformed, "ContentInfo content"},
		{"ContentInfo trailing", fileOf(pw, seq(data, ctx(0, oct(seq())), null())), ErrMalformed, "ContentInfo"},
		{"data content not an OCTET STRING", fileOf(pw, seq(data, ctx(0, integer(1)))), ErrMalformed, "SafeContents data"},
		{"SafeContents is not a SEQUENCE", fileOf(pw, seq(data, ctx(0, oct(integer(1))))), ErrMalformed, "SafeContents"},
		{"SafeContents truncated", fileOf(pw, seq(data, ctx(0, oct([]byte{0x30, 0x05, 1})))), ErrMalformed, "exceeds"},
		{"ContentInfo content body trailing", fileOf(pw, seq(data, ctx(0, oct(seq()), null()))), ErrMalformed, "ContentInfo content"},

		{"EncryptedData version 1", fileOf(pw, edBody(integer(1), data, p.alg(), tlv(0x80, ct))), ErrUnsupported, "EncryptedData version 1"},
		{"EncryptedData version not an integer", fileOf(pw, edBody(oct(nil), data, p.alg(), tlv(0x80, ct))), ErrMalformed, "EncryptedData version"},
		{"EncryptedData content of another type", fileOf(pw, edBody(integer(0), oidDER(oidSignedData), p.alg(), tlv(0x80, ct))), ErrUnsupported, "encrypted content type"},
		{"EncryptedContentInfo trailing", fileOf(pw, edBody(integer(0), data, p.alg(), tlv(0x80, ct), null())), ErrMalformed, "EncryptedContentInfo"},
		{"EncryptedData trailing", fileOf(pw, seq(oidDER(oidEncryptedData), ctx(0, seq(integer(0), seq(data, p.alg(), tlv(0x80, ct)), null())))), ErrMalformed, "EncryptedData"},
		{"encrypted content with the wrong tag", fileOf(pw, edBody(integer(0), data, p.alg(), tlv(0x81, ct))), ErrMalformed, "encrypted content"},
		{"encrypted content missing", fileOf(pw, edBody(integer(0), data, p.alg(), nil)), ErrMalformed, "encrypted content"},

		{"bag is not a SEQUENCE", fileOf(pw, seq(data, ctx(0, oct(seq(oct(nil)))))), ErrMalformed, "SafeBag"},
		{"bag without a value", fileOf(pw, seq(data, ctx(0, oct(seq(seq(oidDER(oidCertBag))))))), ErrMalformed, "bag value"},
		{"bag attributes not a SET", fileOf(pw, dataCI(seq(oidDER(oidKeyBag), ctx(0, mustP8()), seq()))), ErrMalformed, "bag attributes"},
		{"bag trailing", fileOf(pw, dataCI(seq(oidDER(oidKeyBag), ctx(0, mustP8()), set(), null()))), ErrMalformed, "SafeBag"},
		{"CertBag trailing", fileOf(pw, dataCI(bagDER(oidCertBag, seq(oidDER(oidX509Certificate), ctx(0, oct(mat.cert)), null())))), ErrMalformed, "CertBag"},
		{"CertBag value not an OCTET STRING", fileOf(pw, dataCI(bagDER(oidCertBag, seq(oidDER(oidX509Certificate), ctx(0, integer(1)))))), ErrMalformed, "certificate"},
		{"CertBag not a SEQUENCE", fileOf(pw, dataCI(bagDER(oidCertBag, integer(1)))), ErrMalformed, "CertBag"},
		{"certificate is not DER", fileOf(pw, dataCI(bagDER(oidCertBag, seq(oidDER(oidX509Certificate), ctx(0, oct([]byte("junk"))))), key)), ErrMalformed, "certificate"},
		{"key bag is not a SEQUENCE", fileOf(pw, dataCI(bagDER(oidKeyBag, oct(nil)))), ErrMalformed, "PrivateKeyInfo"},
		{"key bag is not PKCS#8", fileOf(pw, dataCI(keyBagDER(seq(integer(1))), cert)), ErrMalformed, "private key"},
		{"shrouded key bag trailing", fileOf(pw, dataCI(bagDER(oidShroudedKeyBag, seq(p.alg(), oct(ct), null())))), ErrMalformed, "EncryptedPrivateKeyInfo"},
		{"shrouded key without ciphertext", fileOf(pw, dataCI(bagDER(oidShroudedKeyBag, seq(p.alg())))), ErrMalformed, "encrypted key"},
		{"shrouded key bag not a SEQUENCE", fileOf(pw, dataCI(bagDER(oidShroudedKeyBag, oct(nil)))), ErrMalformed, "EncryptedPrivateKeyInfo"},
		{"AlgorithmIdentifier trailing", fileOf(pw, dataCI(bagDER(oidShroudedKeyBag, seq(seq(oidDER(oidPBES2), null(), null()), oct(ct))))), ErrMalformed, "key encryption"},
		{"AlgorithmIdentifier without OID", fileOf(pw, dataCI(bagDER(oidShroudedKeyBag, seq(seq(), oct(ct))))), ErrMalformed, "algorithm"},
	})
	_ = good
}

func mustP8() []byte { return mat.p8 }

// TestNoMACKeepsTheRealError: in a file with no MAC, a ciphertext that fails
// to decrypt is reported as a wrong password. That mapping must never reach
// an error found BEFORE anything was decrypted, so a bag that is malformed
// must not be handed to a cipher at all.
func TestNoMACKeepsTheRealError(t *testing.T) {
	material(t)
	p := aesP2(16)
	ct := p.seal(t, pw, pad(append([]byte{}, mat.p8...), 16))
	noMAC := func(bags ...[]byte) []byte {
		return pfxDER(3, oidData, seq(dataCI(bags...)))
	}
	for _, tc := range []struct {
		name string
		file []byte
		msg  string
	}{
		{"attributes malformed, key valid", noMAC(seq(oidDER(oidShroudedKeyBag), ctx(0, shrouded(p.alg(), ct)), seq())), "bag attributes"},
		{"shrouded key without ciphertext", noMAC(bagDER(oidShroudedKeyBag, seq(p.alg()))), "encrypted key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			safely(t, func() { _, err = Decode(tc.file, pw, &Options{AllowNoMAC: true}) })
			if err == nil {
				t.Fatal("accepted")
			}
			wantErr(t, err, ErrMalformed, tc.msg)
		})
	}
}

// TestLegacyPBEBooksNothingOnBadParameters: a PBE whose salt is not an OCTET
// STRING must be refused before its iteration count is charged or any key is
// derived, however large that count is.
func TestLegacyPBEBooksNothingOnBadParameters(t *testing.T) {
	s := &state{opts: (&Options{}).resolve()}
	c, err := cur(algDER(oidPBE3DES, seq(integer(1), integer(900_000))))
	a := c.algID("alg")
	if *err != nil {
		t.Fatal(*err)
	}
	safely(t, func() { s.legacyPBE(a, passwordForm{}, c) })
	wantErr(t, *err, ErrMalformed, "PBE salt")
	if s.work != 0 {
		t.Fatalf("%d units of key derivation work booked for a refused algorithm", s.work)
	}
}

// TestEncryptionRefusals bends the PBES2 and PBES1 parameters of a shrouded
// key, inside an authenticated file, so the refusal is the cipher layer's.
func TestEncryptionRefusals(t *testing.T) {
	material(t)
	base := func() p2 { return aesP2(16) }
	body := pad(append([]byte{}, mat.p8...), 16)
	file := func(alg, ct []byte) []byte { return fileWithKeyBag(t, pw, shroudedBag(alg, ct)) }
	sealed := func(p p2) []byte { return p.seal(t, pw, body) }
	withParams := func(p p2, kdfParams []byte) []byte {
		return algDER(oidPBES2, seq(algDER(oidPBKDF2, kdfParams), algDER(p.enc, oct(p.iv))))
	}
	enc := func(p p2, encAlg []byte) []byte {
		return algDER(oidPBES2, seq(algDER(oidPBKDF2, p.kdfParams()), encAlg))
	}

	var cases []refusal
	add := func(name string, alg, ct []byte, want error, msg string) {
		cases = append(cases, refusal{name, file(alg, ct), want, msg})
	}
	p := base()
	ct := sealed(p)

	add("unknown algorithm", algDER(mustOID(1, 2, 3)), ct, ErrUnsupported, "encryption algorithm 1.2.3")
	add("RC4 (pbeWithSHAAnd128BitRC4)", legacyAlg(with(pbeID, 1), []byte("s"), 1), ct, ErrUnsupported, "encryption algorithm")
	add("PBES2 without parameters", seq(oidDER(oidPBES2)), ct, ErrMalformed, "parameters missing")
	add("PBES2 parameters not a SEQUENCE", algDER(oidPBES2, oct(nil)), ct, ErrMalformed, "not a SEQUENCE")
	add("PBES2 parameters trailing", algDER(oidPBES2, seq(algDER(oidPBKDF2, p.kdfParams()), algDER(p.enc, oct(p.iv)), null())), ct, ErrMalformed, "PBES2 parameters")
	add("PBES2 without encryption scheme", algDER(oidPBES2, seq(algDER(oidPBKDF2, p.kdfParams()))), ct, ErrMalformed, "PBES2 encryption scheme")
	add("scrypt", algDER(oidPBES2, seq(algDER(mustOID(1, 3, 6, 1, 4, 1, 11591, 4, 11), seq()), algDER(p.enc, oct(p.iv)))), ct, ErrUnsupported, "key derivation function")
	add("salt from another source", withParams(p, seq(seq(), integer(4))), ct, ErrUnsupported, "another source")
	add("salt not an OCTET STRING", withParams(p, seq(integer(1), integer(4))), ct, ErrMalformed, "PBKDF2 salt")
	add("PBKDF2 parameters trailing", withParams(p, seq(oct(p.salt), integer(4), algDER(oidHMACSHA1, null()), null())), ct, ErrMalformed, "PBKDF2 parameters")
	add("PBKDF2 parameters not a SEQUENCE", algDER(oidPBES2, seq(algDER(oidPBKDF2, oct(nil)), algDER(p.enc, oct(p.iv)))), ct, ErrMalformed, "not a SEQUENCE")
	add("PBKDF2 without parameters", algDER(oidPBES2, seq(seq(oidDER(oidPBKDF2)), algDER(p.enc, oct(p.iv)))), ct, ErrMalformed, "parameters missing")

	q := base()
	q.keyLen = -5
	add("negative key length", q.alg(), ct, ErrMalformed, "key length -5")
	q = base()
	q.keyLen = 32
	add("key length that is not the cipher's", q.alg(), ct, ErrMalformed, "key length 32")
	q = base()
	q.prf = mustOID(1, 2, 3)
	add("unknown PRF", q.alg(), ct, ErrUnsupported, "pseudorandom function 1.2.3")
	q = base()
	q.salt = bytes.Repeat([]byte{1}, maxSaltLen+1)
	add("oversized salt", q.alg(), ct, ErrLimit, "salt of")
	for name, tc := range map[string]struct {
		iter int64
		want error
		msg  string
	}{
		"zero iterations":     {0, ErrMalformed, "iteration count 0"},
		"negative iterations": {-1, ErrMalformed, "iteration count -1"},
		"too many iterations": {1_000_001, ErrLimit, "iteration count 1000001"},
	} {
		q = base()
		q.iter = tc.iter
		add(name, q.alg(), ct, tc.want, tc.msg)
	}
	q = base()
	q.enc = mustOID(1, 2, 3)
	add("unknown encryption scheme", q.alg(), ct, ErrUnsupported, "encryption scheme 1.2.3")
	add("no IV", enc(p, algDER(p.enc)), ct, ErrMalformed, "IV missing")
	add("IV of the wrong type", enc(p, algDER(p.enc, integer(1))), ct, ErrMalformed, "IV missing")
	add("IV constructed", enc(p, algDER(p.enc, tlv(0x24, oct(p.iv)))), ct, ErrMalformed, "IV missing")
	q = base()
	q.iv = make([]byte, 8)
	add("IV of 8 bytes for AES", q.alg(), ct, ErrMalformed, "IV of 8 bytes")
	add("ciphertext not a whole number of blocks", p.alg(), ct[:17], ErrMalformed, "whole number of blocks")
	add("empty ciphertext", p.alg(), nil, ErrMalformed, "whole number of blocks")

	// Padding: the plaintext is made to end wrongly.
	bad := func(last ...byte) []byte {
		pt := bytes.Repeat([]byte{0xaa}, 16)
		copy(pt[16-len(last):], last)
		return p.seal(t, pw, pt)
	}
	add("padding of 0", p.alg(), bad(0), ErrMalformed, "bad padding")
	add("padding longer than a block", p.alg(), bad(17), ErrMalformed, "bad padding")
	add("padding bytes disagree", p.alg(), bad(1, 2), ErrMalformed, "bad padding")

	// Legacy PBE.
	salt := []byte("salt")
	lct := sealLegacy(pw, salt, 2, mat.p8)
	add("legacy without parameters", seq(oidDER(oidPBE3DES)), lct, ErrMalformed, "parameters missing")
	add("legacy parameters trailing", algDER(oidPBE3DES, seq(oct(salt), integer(2), null())), lct, ErrMalformed, "PBE parameters")
	add("legacy salt not an OCTET STRING", algDER(oidPBE3DES, seq(integer(1), integer(2))), lct, ErrMalformed, "PBE salt")
	add("legacy oversized salt", legacyAlg(oidPBE3DES, bytes.Repeat([]byte{1}, maxSaltLen+1), 2), lct, ErrLimit, "salt of")
	add("legacy zero iterations", legacyAlg(oidPBE3DES, salt, 0), lct, ErrMalformed, "iteration count 0")
	add("legacy too many iterations", legacyAlg(oidPBE3DES, salt, 2_000_000), lct, ErrLimit, "iteration count")
	add("legacy ciphertext cut", legacyAlg(oidPBE3DES, salt, 2), lct[:len(lct)-1], ErrMalformed, "whole number of blocks")
	add("legacy bad padding", legacyAlg(oidPBE3DES, salt, 2), append([]byte{}, lct[:len(lct)-8]...), ErrMalformed, "padding")

	runRefusals(t, cases)
}
