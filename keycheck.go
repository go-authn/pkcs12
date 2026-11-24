package pkcs12

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// preflightKey refuses a hostile PKCS#8 key BEFORE crypto/x509 sees it. The
// standard library validates an RSA key by arithmetic on the numbers it
// declares, so numbers far longer than the modulus allows (large non-prime
// "factors") cost it superlinear CPU: 32 KB factors took 7 s for a 295 KB
// input. Here the envelope and the RSAPrivateKey are read with encoding/asn1
// (linear in the input), and every number is bounded by the modulus.
//
// EC, Ed25519 and X25519 keys need no pre-check beyond maxKeyDER: their cost
// is one scalar multiplication on a named curve, whatever the declared
// length, and the input is capped.
func preflightKey(der []byte, maxBits int) error {
	if len(der) > maxKeyDER {
		return limit("private key of %d bytes exceeds the limit of %d", len(der), maxKeyDER)
	}
	var p8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		Attributes []asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &p8); err != nil {
		return malformed("private key: %v", err)
	}
	if !p8.Algo.Algorithm.Equal(oidRSAEncryption) {
		return nil
	}
	var k struct {
		Version int
		N       *big.Int
		E       int
		D       *big.Int
		P, Q    *big.Int
		Dp, Dq  *big.Int        `asn1:"optional"` // read, so that their absence is a typed
		Qinv    *big.Int        `asn1:"optional"` // refusal, not an ASN.1 error
		Extra   []asn1.RawValue `asn1:"optional,omitempty"`
	}
	if _, err := asn1.Unmarshal(p8.PrivateKey, &k); err != nil {
		return malformed("RSA private key: %v", err)
	}
	if len(k.Extra) > 0 {
		return unsupported("multi-prime RSA key")
	}
	// RFC 8017 requires Dp, Dq and Qinv, and every exporter writes them
	// (OpenSSL, Windows, Java keytool). crypto/x509 reads a key without them
	// but then derives them with big-number arithmetic: 16.4 MB and 21 744
	// allocations for 8192 bits, against 0.36 MB and 618 with them.
	if k.Dp == nil || k.Dq == nil || k.Qinv == nil {
		return unsupported("RSA key without CRT values (Dp, Dq, Qinv)")
	}
	for _, v := range []*big.Int{k.N, k.D, k.P, k.Q, k.Dp, k.Dq, k.Qinv} {
		if v.Sign() <= 0 {
			return malformed("RSA private key: a number is not positive")
		}
	}
	n := k.N.BitLen()
	if n > maxBits {
		return limit("RSA modulus of %d bits exceeds the limit of %d", n, maxBits)
	}
	// P x Q = N, so the two factors together are n or n+1 bits long, and every
	// other number is reduced modulo N, P or Q.
	if k.P.BitLen()+k.Q.BitLen() > n+1 || k.D.BitLen() > n ||
		k.Dp.BitLen() > k.P.BitLen() || k.Dq.BitLen() > k.Q.BitLen() || k.Qinv.BitLen() > k.P.BitLen() {
		return malformed("RSA private key: a number is longer than the modulus allows")
	}
	// The CRT values must be the ones RFC 8017 defines. With GODEBUG=x509rsacrt=0
	// crypto/x509 (pkcs1.go) drops wrong CRT values and re-derives them, the cost
	// the absence check above avoids; and the setting cannot be read reliably
	// (//go:debug directives). Checking them here makes the bound independent of
	// it: three reductions of at most n bits by n/2 bits, plus one product.
	one := big.NewInt(1)
	if k.P.Cmp(one) <= 0 || k.Q.Cmp(one) <= 0 {
		return malformed("RSA private key: a prime factor is 1")
	}
	pm1 := new(big.Int).Sub(k.P, one)
	qm1 := new(big.Int).Sub(k.Q, one)
	qinv := new(big.Int).Mul(k.Qinv, k.Q)
	qinv.Mod(qinv, k.P)
	if new(big.Int).Mod(k.D, pm1).Cmp(k.Dp) != 0 ||
		new(big.Int).Mod(k.D, qm1).Cmp(k.Dq) != 0 ||
		qinv.Cmp(one) != 0 {
		return malformed("RSA private key: CRT values do not match the key")
	}
	return nil
}

var oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
