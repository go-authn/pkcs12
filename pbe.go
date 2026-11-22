package pkcs12

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/pbkdf2"
	"crypto/x509"
	"hash"
)

// state carries the bounds and the running cost of one Decode.
type state struct {
	opts          Options
	work          int64
	authenticated bool // a MAC verified
	decrypted     bool // something was handed to a cipher
	bags          int
	key           crypto.PrivateKey
	certs         []*x509.Certificate
}

// charge books iter x blocks of key derivation against the file's budget. It
// runs before any hashing, so a refusal costs nothing.
func (s *state) charge(iter int64, blocks int) error {
	if iter < 1 {
		return malformed("iteration count %d", iter)
	}
	if iter > int64(s.opts.MaxIterations) {
		return limit("iteration count %d exceeds the limit of %d", iter, s.opts.MaxIterations)
	}
	s.work += iter * int64(blocks)
	if s.work > s.opts.MaxWork {
		return limit("key derivation work exceeds the limit of %d", s.opts.MaxWork)
	}
	return nil
}

type algID struct {
	oid    []byte
	params elem
	has    bool
}

func (c *cursor) algID(what string) algID {
	s := c.seq(what)
	a := algID{oid: s.oid(what + " algorithm")}
	if s.more() {
		a.params, a.has = s.any(what), true
	}
	s.end(what)
	return a
}

// paramSeq returns a cursor over the parameters, which must be a SEQUENCE.
func paramSeq(a algID, c *cursor, what string) *cursor {
	if !a.has {
		c.fail(malformed("%s: parameters missing", what))
		return c.sub(elem{})
	}
	if a.params.class != classUniversal || a.params.tag != tagSequence || !a.params.cons {
		c.fail(malformed("%s: parameters are not a SEQUENCE", what))
		return c.sub(elem{})
	}
	return c.sub(a.params)
}

// decrypt reverses the encryption algorithm a over ct, with the password
// form pw. The caller has verified the MAC when there is one.
func (s *state) decrypt(a algID, ct []byte, pw passwordForm, c *cursor) []byte {
	var err error
	var block cipher.Block
	var iv []byte
	switch {
	case oidIs(a.oid, oidPBES2):
		block, iv = s.pbes2(a, pw, c)
	case oidIs(a.oid, oidPBE3DES), oidIs(a.oid, oidPBE2DES), oidIs(a.oid, oidPBERC2_128), oidIs(a.oid, oidPBERC2_40):
		block, iv = s.legacyPBE(a, pw, c)
	default:
		c.fail(unsupported("encryption algorithm %s", oidString(a.oid)))
	}
	if *c.err != nil {
		return nil
	}
	bs := block.BlockSize()
	if len(iv) != bs {
		c.fail(malformed("IV of %d bytes for a %d-byte block", len(iv), bs))
		return nil
	}
	if len(ct) == 0 || len(ct)%bs != 0 {
		c.fail(malformed("ciphertext of %d bytes is not a whole number of blocks", len(ct)))
		return nil
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	if pt, err = unpad(pt, bs); err != nil {
		c.fail(err)
		return nil
	}
	return pt
}

// unpad removes PKCS#7 padding.
func unpad(pt []byte, bs int) ([]byte, error) {
	n := int(pt[len(pt)-1])
	if n == 0 || n > bs {
		return nil, malformed("bad padding")
	}
	bad := byte(0)
	for _, b := range pt[len(pt)-n:] {
		bad |= b ^ byte(n)
	}
	if bad != 0 {
		return nil, malformed("bad padding")
	}
	return pt[:len(pt)-n], nil
}

// legacyPBE: the PKCS#12 password-based encryption of RFC 7292 Appendix C,
// keyed with the B.2 derivation over SHA-1.
func (s *state) legacyPBE(a algID, pw passwordForm, c *cursor) (cipher.Block, []byte) {
	ps := paramSeq(a, c, "PKCS#12 PBE parameters")
	salt := ps.octets(classUniversal, tagOctetString, "PBE salt")
	iter := ps.integer("PBE iteration count")
	ps.end("PBE parameters")
	if *c.err != nil {
		return nil, nil
	}
	if len(salt) > maxSaltLen {
		c.fail(limit("salt of %d bytes exceeds %d", len(salt), maxSaltLen))
		return nil, nil
	}

	var keyLen int
	var mk func(key []byte) (cipher.Block, error)
	switch {
	case oidIs(a.oid, oidPBE3DES):
		keyLen, mk = 24, des.NewTripleDESCipher
	case oidIs(a.oid, oidPBE2DES):
		keyLen, mk = 16, func(k []byte) (cipher.Block, error) {
			return des.NewTripleDESCipher(append(append([]byte{}, k...), k[:8]...))
		}
	case oidIs(a.oid, oidPBERC2_128):
		keyLen, mk = 16, func(k []byte) (cipher.Block, error) { return newRC2(k, 128) }
	default: // oidPBERC2_40
		keyLen, mk = 5, func(k []byte) (cipher.Block, error) { return newRC2(k, 40) }
	}
	// Key and IV are two derivations; each costs ceil(n/u) rounds of the hash.
	if err := s.charge(iter, (keyLen+19)/20+1); err != nil {
		c.fail(err)
		return nil, nil
	}
	key := pkcs12KDF(specSHA1.new, specSHA1.u, specSHA1.v, salt, pw.bmp, int(iter), 1, keyLen)
	iv := pkcs12KDF(specSHA1.new, specSHA1.u, specSHA1.v, salt, pw.bmp, int(iter), 2, 8)
	block, _ := mk(key) // the key length is fixed by the algorithm: it cannot fail
	return block, iv
}

// pbkdf2Params is PBKDF2-params of RFC 8018 Appendix A.2.
type pbkdf2Params struct {
	salt   []byte
	iter   int64
	keyLen int // 0 when absent
	prf    hashSpec
}

func (s *state) parsePBKDF2(a algID, c *cursor) pbkdf2Params {
	var p pbkdf2Params
	if !oidIs(a.oid, oidPBKDF2) {
		c.fail(unsupported("key derivation function %s", oidString(a.oid)))
		return p
	}
	ps := paramSeq(a, c, "PBKDF2 parameters")
	if cl, tg, ok := ps.peek(); ok && cl == classUniversal && tg == tagSequence {
		c.fail(unsupported("PBKDF2 salt from another source"))
		return p
	}
	p.salt = ps.octets(classUniversal, tagOctetString, "PBKDF2 salt")
	p.iter = ps.integer("PBKDF2 iteration count")
	if cl, tg, ok := ps.peek(); ok && cl == classUniversal && tg == tagInteger {
		p.keyLen = int(ps.integer("PBKDF2 key length"))
		if p.keyLen < 1 {
			c.fail(malformed("PBKDF2 key length %d", p.keyLen))
		}
	}
	p.prf = specSHA1 // the DEFAULT
	if ps.more() {
		prf := ps.algID("PBKDF2 prf")
		if *c.err == nil {
			var ok bool
			if p.prf, ok = hmacSpec(prf.oid); !ok {
				c.fail(unsupported("PBKDF2 pseudorandom function %s", oidString(prf.oid)))
			}
		}
	}
	ps.end("PBKDF2 parameters")
	if *c.err == nil && len(p.salt) > maxSaltLen {
		c.fail(limit("salt of %d bytes exceeds %d", len(p.salt), maxSaltLen))
	}
	return p
}

// pbkdf2Key is crypto/pbkdf2.Key. It is a variable so that a test can make it
// fail: it does so only under GODEBUG=fips140=only, for a short password or
// salt, and that refusal must come out as ErrUnsupported, not as a panic.
var pbkdf2Key = func(h func() hash.Hash, password string, salt []byte, iter, keyLen int) ([]byte, error) {
	return pbkdf2.Key(h, password, salt, iter, keyLen)
}

// derive runs PBKDF2 for keyLen bytes after charging its cost.
func (s *state) derive(p pbkdf2Params, password []byte, keyLen int) ([]byte, error) {
	if err := s.charge(p.iter, (keyLen+p.prf.u-1)/p.prf.u); err != nil {
		return nil, err
	}
	key, err := pbkdf2Key(p.prf.new, string(password), p.salt, int(p.iter), keyLen)
	if err != nil { // FIPS 140 mode refuses short passwords and salts
		return nil, unsupported("PBKDF2: %v", err)
	}
	return key, nil
}

// pbes2 is PBES2 of RFC 8018 section 6.2: PBKDF2, then CBC.
func (s *state) pbes2(a algID, pw passwordForm, c *cursor) (cipher.Block, []byte) {
	ps := paramSeq(a, c, "PBES2 parameters")
	kdf := ps.algID("PBES2 key derivation")
	enc := ps.algID("PBES2 encryption scheme")
	ps.end("PBES2 parameters")
	p := s.parsePBKDF2(kdf, c)

	var keyLen int
	var mk func(key []byte) (cipher.Block, error)
	switch {
	case oidIs(enc.oid, oidAES128CBC):
		keyLen, mk = 16, aes.NewCipher
	case oidIs(enc.oid, oidAES192CBC):
		keyLen, mk = 24, aes.NewCipher
	case oidIs(enc.oid, oidAES256CBC):
		keyLen, mk = 32, aes.NewCipher
	case oidIs(enc.oid, oidDESEDE3CBC):
		keyLen, mk = 24, des.NewTripleDESCipher
	default:
		c.fail(unsupported("PBES2 encryption scheme %s", oidString(enc.oid)))
	}
	if *c.err != nil {
		return nil, nil
	}
	if p.keyLen != 0 && p.keyLen != keyLen {
		c.fail(malformed("PBKDF2 key length %d for a %d-byte cipher key", p.keyLen, keyLen))
		return nil, nil
	}
	if !enc.has || enc.params.class != classUniversal || enc.params.tag != tagOctetString || enc.params.cons {
		c.fail(malformed("PBES2 encryption scheme IV missing"))
		return nil, nil
	}
	key, err := s.derive(p, pw.utf8, keyLen)
	if err != nil {
		c.fail(err)
		return nil, nil
	}
	// The key length is fixed by the scheme chosen above, so the cipher
	// constructors cannot fail.
	block, _ := mk(key)
	return block, enc.params.content
}
