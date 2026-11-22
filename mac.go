package pkcs12

import (
	"crypto/hmac"
)

// macData is the MacData of RFC 7292 section 4, or of RFC 9579 for PBMAC1.
type macData struct {
	alg    algID
	digest []byte
	salt   []byte
	iter   int64
}

// verifyMAC checks the MAC over content for each password form in turn and
// returns the form that verified. The comparison is constant-time, and it
// happens before anything is decrypted: a wrong password never reaches a
// cipher, so the MAC is the only oracle the file offers.
func (s *state) verifyMAC(m macData, content []byte, forms []passwordForm) (passwordForm, error) {
	for _, f := range forms {
		var want []byte
		var err error
		if oidIs(m.alg.oid, oidPBMAC1) {
			want, err = s.pbmac1(m, content, f)
		} else {
			want, err = s.pkcs12MAC(m, content, f)
		}
		if err != nil {
			return passwordForm{}, err
		}
		if hmac.Equal(want, m.digest) {
			return f, nil
		}
	}
	return passwordForm{}, ErrIncorrectPassword
}

// pkcs12MAC is the original password integrity mode: HMAC keyed by the B.2
// derivation with ID 3 (RFC 7292 Appendix A and B.4).
func (s *state) pkcs12MAC(m macData, content []byte, f passwordForm) ([]byte, error) {
	spec, ok := digestSpec(m.alg.oid)
	if !ok {
		return nil, unsupported("MAC digest %s", oidString(m.alg.oid))
	}
	if len(m.salt) > maxSaltLen {
		return nil, limit("MAC salt of %d bytes exceeds %d", len(m.salt), maxSaltLen)
	}
	if err := s.charge(m.iter, 1); err != nil {
		return nil, err
	}
	key := pkcs12KDF(spec.new, spec.u, spec.v, m.salt, f.bmp, int(m.iter), 3, spec.u)
	h := hmac.New(spec.new, key)
	h.Write(content)
	return h.Sum(nil), nil
}

// pbmac1 is RFC 9579: PBKDF2 then HMAC, with the parameters in the digest
// algorithm. macSalt and iterations are ignored (section 4 c and d).
//
// Stricter than the RFC where the RFC leaves room: the HMAC must be a SHA-2
// one (section 7 forbids digests of 160 bits or fewer), the PBKDF2 PRF must
// be one too, and the derived key must be exactly as long as the HMAC's
// output. A short derived key is the authentication bypass of OpenSSL's
// CVE-2026-34181, so a key length that is absent or short is refused
// (section 5), not defaulted.
func (s *state) pbmac1(m macData, content []byte, f passwordForm) ([]byte, error) {
	var err error
	c := newCursor(nil, s.opts.MaxDepth, &err)
	ps := paramSeq(m.alg, c, "PBMAC1 parameters")
	kdf := ps.algID("PBMAC1 key derivation")
	msg := ps.algID("PBMAC1 message authentication")
	ps.end("PBMAC1 parameters")
	p := s.parsePBKDF2(kdf, c)
	if err != nil {
		return nil, err
	}
	spec, ok := hmacSpec(msg.oid)
	if !ok || spec.u < 28 {
		return nil, unsupported("PBMAC1 message authentication %s", oidString(msg.oid))
	}
	if p.prf.u < 28 {
		return nil, unsupported("PBMAC1 with a SHA-1 PRF")
	}
	if p.keyLen == 0 {
		return nil, malformed("PBMAC1 PBKDF2 parameters have no key length")
	}
	if p.keyLen != spec.u {
		return nil, malformed("PBMAC1 key length %d, want the HMAC output size %d", p.keyLen, spec.u)
	}
	key, err := s.derive(p, f.utf8, p.keyLen)
	if err != nil {
		return nil, err
	}
	h := hmac.New(spec.new, key)
	h.Write(content)
	return h.Sum(nil), nil
}
