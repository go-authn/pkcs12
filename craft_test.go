package pkcs12

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"hash"
	"testing"
)

// Encryption helpers for crafted files. They share no code with the decoder
// except the B.2 derivation (checked against independent vectors in
// primitives_test.go and against OpenSSL in fixtures_test.go).

func pad(pt []byte, bs int) []byte {
	n := bs - len(pt)%bs
	for i := 0; i < n; i++ {
		pt = append(pt, byte(n))
	}
	return pt
}

func cbc(block cipher.Block, iv, padded []byte) []byte {
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out
}

// p2 describes a PBES2 algorithm identifier.
type p2 struct {
	salt    []byte
	iter    int64
	keyLen  int64  // 0: omitted
	prf     []byte // HMAC OID; nil: omitted (the default, SHA-1)
	prfHash func() hash.Hash
	enc     []byte // encryption scheme OID
	iv      []byte
}

func aesP2(keyBytes int) p2 {
	enc := map[int][]byte{16: oidAES128CBC, 24: oidAES192CBC, 32: oidAES256CBC}[keyBytes]
	return p2{salt: []byte("pbkdf2-salt"), iter: 4, enc: enc, iv: make([]byte, 16), prfHash: sha1.New}
}

func (p p2) kdfParams() []byte {
	parts := [][]byte{oct(p.salt), integer(p.iter)}
	if p.keyLen != 0 {
		parts = append(parts, integer(p.keyLen))
	}
	if p.prf != nil {
		parts = append(parts, algDER(p.prf, null()))
	}
	return seq(parts...)
}

func (p p2) alg() []byte {
	return algDER(oidPBES2, seq(algDER(oidPBKDF2, p.kdfParams()), algDER(p.enc, oct(p.iv))))
}

// seal encrypts already-padded data with the scheme and password.
func (p p2) seal(t testing.TB, pw string, padded []byte) []byte {
	t.Helper()
	n := map[string]int{string(oidAES128CBC): 16, string(oidAES192CBC): 24, string(oidAES256CBC): 32, string(oidDESEDE3CBC): 24}[string(p.enc)]
	key, err := pbkdf2.Key(p.prfHash, pw, p.salt, int(p.iter), n)
	if err != nil {
		t.Fatal(err)
	}
	var block cipher.Block
	if n == 24 && string(p.enc) == string(oidDESEDE3CBC) {
		block, _ = des.NewTripleDESCipher(key)
	} else {
		block, _ = aes.NewCipher(key)
	}
	return cbc(block, p.iv, padded)
}

// shrouded is a PKCS8ShroudedKeyBag value: EncryptedPrivateKeyInfo.
func shrouded(alg, ct []byte) []byte { return seq(alg, oct(ct)) }

func shroudedBag(alg, ct []byte) []byte { return bagDER(oidShroudedKeyBag, shrouded(alg, ct)) }

// fileWithKeyBag is a MAC'd file: the certificate, and the given key bag.
func fileWithKeyBag(t testing.TB, pw string, keyBag []byte) []byte {
	material(t)
	return fileOf(pw, dataCI(certBagDER(mat.cert), keyBag))
}

// encryptedDataCI is an EncryptedData ContentInfo around ct.
func encryptedDataCI(alg, ct []byte) []byte {
	eci := seq(oidDER(oidData), alg, tlv(0x80, ct))
	return seq(oidDER(oidEncryptedData), ctx(0, seq(integer(0), eci)))
}

// legacyAlg is a PKCS#12 PBE algorithm identifier.
func legacyAlg(oid, salt []byte, iter int64) []byte {
	return algDER(oid, seq(oct(salt), integer(iter)))
}

// sealLegacy encrypts with pbeWithSHAAnd3-KeyTripleDES-CBC.
func sealLegacy(pw string, salt []byte, iter int, plain []byte) []byte {
	key := pkcs12KDF(sha1.New, 20, 64, salt, bmpPassword(pw), iter, 1, 24)
	iv := pkcs12KDF(sha1.New, 20, 64, salt, bmpPassword(pw), iter, 2, 8)
	block, _ := des.NewTripleDESCipher(key)
	return cbc(block, iv, pad(append([]byte{}, plain...), 8))
}

// pbmac1MAC is a MacData using PBMAC1 (RFC 9579).
type pbmac1T struct {
	salt   []byte
	iter   int64
	keyLen int64
	prf    []byte // HMAC OID of the PBKDF2 PRF
	msg    []byte // HMAC OID of the message authentication scheme
	h      func() hash.Hash
	size   int
}

func goodPBMAC1() pbmac1T {
	return pbmac1T{salt: []byte("pbmac1-salt"), iter: 5, keyLen: 32, prf: oidHMACSHA256, msg: oidHMACSHA256, h: specSHA256.new, size: 32}
}

func (m pbmac1T) alg() []byte {
	parts := [][]byte{oct(m.salt), integer(m.iter)}
	if m.keyLen != 0 {
		parts = append(parts, integer(m.keyLen))
	}
	parts = append(parts, algDER(m.prf, null()))
	kdf := algDER(oidPBKDF2, seq(parts...))
	return algDER(oidPBMAC1, seq(kdf, algDER(m.msg, null())))
}

func (m pbmac1T) der(t testing.TB, pw string, content []byte) []byte {
	key, err := pbkdf2.Key(m.h, pw, m.salt, int(m.iter), m.size)
	if err != nil {
		t.Fatal(err)
	}
	h := hmac.New(m.h, key)
	h.Write(content)
	return seq(seq(m.alg(), oct(h.Sum(nil))), oct([]byte("ignored")), integer(1))
}
