package pkcs12

import (
	"bytes"
	"strconv"
)

// OIDs are held as their DER content octets and compared byte for byte, so
// matching one allocates nothing and an attacker-sized OID costs one memcmp.

func mustOID(arcs ...uint64) []byte {
	out := []byte{byte(arcs[0]*40 + arcs[1])}
	for _, a := range arcs[2:] {
		var tmp [10]byte
		i := len(tmp)
		i--
		tmp[i] = byte(a & 0x7f)
		for a >>= 7; a > 0; a >>= 7 {
			i--
			tmp[i] = byte(a&0x7f) | 0x80
		}
		out = append(out, tmp[i:]...)
	}
	return out
}

// oidString renders content octets as dotted decimal for error messages. It
// is bounded to the first 32 arcs so a hostile OID cannot make a long message.
func oidString(b []byte) string {
	if len(b) == 0 {
		return "(empty)"
	}
	s := strconv.Itoa(int(b[0]/40)) + "." + strconv.Itoa(int(b[0]%40))
	var v uint64
	arcs := 0
	for _, c := range b[1:] {
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			if arcs++; arcs > 32 {
				return s + ".…"
			}
			s += "." + strconv.FormatUint(v, 10)
			v = 0
		}
	}
	return s
}

func oidIs(got, want []byte) bool { return bytes.Equal(got, want) }

var (
	pkcs7  = []uint64{1, 2, 840, 113549, 1, 7}
	pkcs5  = []uint64{1, 2, 840, 113549, 1, 5}
	pbeID  = []uint64{1, 2, 840, 113549, 1, 12, 1}
	bagID  = []uint64{1, 2, 840, 113549, 1, 12, 10, 1}
	rsadsi = []uint64{1, 2, 840, 113549}
)

func with(base []uint64, tail ...uint64) []byte {
	return mustOID(append(append([]uint64{}, base...), tail...)...)
}

var (
	oidData          = with(pkcs7, 1)
	oidSignedData    = with(pkcs7, 2)
	oidEncryptedData = with(pkcs7, 6)

	oidKeyBag          = with(bagID, 1)
	oidShroudedKeyBag  = with(bagID, 2)
	oidCertBag         = with(bagID, 3)
	oidX509Certificate = mustOID(1, 2, 840, 113549, 1, 9, 22, 1)

	oidPBES2  = with(pkcs5, 13)
	oidPBKDF2 = with(pkcs5, 12)
	oidPBMAC1 = with(pkcs5, 14)

	oidPBE3DES    = with(pbeID, 3) // pbeWithSHAAnd3-KeyTripleDES-CBC
	oidPBE2DES    = with(pbeID, 4) // pbeWithSHAAnd2-KeyTripleDES-CBC
	oidPBERC2_128 = with(pbeID, 5)
	oidPBERC2_40  = with(pbeID, 6)

	oidAES128CBC  = mustOID(2, 16, 840, 1, 101, 3, 4, 1, 2)
	oidAES192CBC  = mustOID(2, 16, 840, 1, 101, 3, 4, 1, 22)
	oidAES256CBC  = mustOID(2, 16, 840, 1, 101, 3, 4, 1, 42)
	oidDESEDE3CBC = with(rsadsi, 3, 7)

	oidSHA1   = mustOID(1, 3, 14, 3, 2, 26)
	oidSHA224 = mustOID(2, 16, 840, 1, 101, 3, 4, 2, 4)
	oidSHA256 = mustOID(2, 16, 840, 1, 101, 3, 4, 2, 1)
	oidSHA384 = mustOID(2, 16, 840, 1, 101, 3, 4, 2, 2)
	oidSHA512 = mustOID(2, 16, 840, 1, 101, 3, 4, 2, 3)

	oidHMACSHA1   = with(rsadsi, 2, 7)
	oidHMACSHA224 = with(rsadsi, 2, 8)
	oidHMACSHA256 = with(rsadsi, 2, 9)
	oidHMACSHA384 = with(rsadsi, 2, 10)
	oidHMACSHA512 = with(rsadsi, 2, 11)
)

// digestSpec maps a digest OID (MacData) to its hash.
func digestSpec(oid []byte) (hashSpec, bool) {
	switch {
	case oidIs(oid, oidSHA1):
		return specSHA1, true
	case oidIs(oid, oidSHA224):
		return specSHA224, true
	case oidIs(oid, oidSHA256):
		return specSHA256, true
	case oidIs(oid, oidSHA384):
		return specSHA384, true
	case oidIs(oid, oidSHA512):
		return specSHA512, true
	}
	return hashSpec{}, false
}

// hmacSpec maps an HMAC OID (PBKDF2 prf, PBMAC1 messageAuthScheme) to its hash.
func hmacSpec(oid []byte) (hashSpec, bool) {
	switch {
	case oidIs(oid, oidHMACSHA1):
		return specSHA1, true
	case oidIs(oid, oidHMACSHA224):
		return specSHA224, true
	case oidIs(oid, oidHMACSHA256):
		return specSHA256, true
	case oidIs(oid, oidHMACSHA384):
		return specSHA384, true
	case oidIs(oid, oidHMACSHA512):
		return specSHA512, true
	}
	return hashSpec{}, false
}
