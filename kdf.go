package pkcs12

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"unicode/utf16"
	"unicode/utf8"
)

// pkcs12KDF is the key derivation of RFC 7292 Appendix B.2: u is the hash's
// output size in bytes and v its block size. id is 1 for a key, 2 for an IV,
// 3 for a MAC key (B.3). The caller has already bounded iter and the lengths.
func pkcs12KDF(newHash func() hash.Hash, u, v int, salt, password []byte, iter int, id byte, n int) []byte {
	// 1. D = v copies of ID.
	d := make([]byte, v)
	for i := range d {
		d[i] = id
	}
	// 2, 3, 4. I = S || P, each padded by repetition to a multiple of v bytes;
	// an empty S or P stays empty.
	i := append(stretch(salt, v), stretch(password, v)...)

	h := newHash()
	out := make([]byte, 0, n+u)
	a := make([]byte, 0, u)
	b := make([]byte, v)
	for { // 5. c = ceil(n/u) rounds; n >= 1, so the first round always runs
		// 6A. A = H^r(D || I)
		h.Reset()
		h.Write(d)
		h.Write(i)
		a = h.Sum(a[:0])
		for r := 1; r < iter; r++ {
			h.Reset()
			h.Write(a)
			a = h.Sum(a[:0])
		}
		out = append(out, a...)
		if len(out) >= n {
			break
		}
		// 6B. B = A repeated to v bytes.
		for j := range b {
			b[j] = a[j%u]
		}
		// 6C. every v-byte block of I becomes (I_j + B + 1) mod 2^v.
		for off := 0; off < len(i); off += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				s := int(i[off+k]) + int(b[k]) + carry
				i[off+k] = byte(s)
				carry = s >> 8
			}
		}
	}
	return out[:n]
}

// stretch repeats p to the next multiple of v bytes, the last copy truncated.
func stretch(p []byte, v int) []byte {
	if len(p) == 0 {
		return nil
	}
	out := make([]byte, v*((len(p)+v-1)/v))
	for k := range out {
		out[k] = p[k%len(p)]
	}
	return out
}

// bmpPassword is B.1: UTF-16 big-endian, no byte-order mark, followed by two
// zero bytes. (UTF-16, not UCS-2: a character outside the BMP becomes a
// surrogate pair, which is what OpenSSL and Windows write.)
func bmpPassword(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u))
	}
	return append(out, 0, 0)
}

// passwordForm is one way of turning the caller's password into bytes. bmp
// feeds the PKCS#12 B.2 derivation; utf8 feeds PBKDF2 (PBES2 and PBMAC1),
// which RFC 8018 leaves to the application and every PKCS#12 implementation
// answers with UTF-8.
type passwordForm struct {
	bmp  []byte
	utf8 []byte
}

// passwordForms lists the interpretations to try, in order. The password ""
// is ambiguous: the empty password (a lone terminator) and no password at all
// (zero bytes) derive different keys, and both exist in the wild.
func passwordForms(password string, o *Options) ([]passwordForm, error) {
	if o.NoPassword {
		if password != "" {
			return nil, ErrPassword
		}
		return []passwordForm{{}}, nil
	}
	if !utf8.ValidString(password) {
		return nil, ErrPassword
	}
	if utf8.RuneCountInString(password) > maxPasswordRunes {
		return nil, ErrPassword
	}
	forms := []passwordForm{{bmp: bmpPassword(password), utf8: []byte(password)}}
	if password == "" {
		forms = append(forms, passwordForm{})
	}
	return forms, nil
}

// hashes: the digests PKCS#12 names, with the sizes B.2 needs.
type hashSpec struct {
	new  func() hash.Hash
	u, v int
}

var (
	specSHA1   = hashSpec{sha1.New, 20, 64}
	specSHA224 = hashSpec{sha256.New224, 28, 64}
	specSHA256 = hashSpec{sha256.New, 32, 64}
	specSHA384 = hashSpec{sha512.New384, 48, 128}
	specSHA512 = hashSpec{sha512.New, 64, 128}
)
