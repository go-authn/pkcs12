// Package pkcs12 decodes PKCS#12 (.p12 / .pfx) files, RFC 7292, into a private
// key, its certificate and the rest of the chain. It reads what OpenSSL 3 and
// 4 and current Windows write (PBES2 with PBKDF2 and AES, HMAC-SHA-2 MACs,
// PBMAC1) and what older Windows and Java wrote (3DES and RC2, SHA-1 MACs).
//
// It decodes only, and it is built for untrusted uploads: every length is
// bounded before it is used, the MAC is checked in constant time before
// anything is decrypted, and the cost of key derivation is capped (Options).
package pkcs12

import (
	"crypto"
	"crypto/x509"
	"errors"
)

// Bundle is what a PKCS#12 file held.
type Bundle struct {
	// PrivateKey is *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey or
	// *ecdh.PrivateKey (X25519): whatever crypto/x509.ParsePKCS8PrivateKey
	// returns.
	PrivateKey crypto.PrivateKey
	// Certificate is the certificate whose public key is PrivateKey's.
	Certificate *x509.Certificate
	// CACerts are the other certificates, in file order.
	CACerts []*x509.Certificate
}

// Decode reads a PKCS#12 file. See Options for the bounds and for the two
// ambiguities of the format (a missing MAC, an empty password). Every error
// wraps one of ErrMalformed, ErrUnsupported, ErrLimit, ErrIncorrectPassword,
// ErrNoMAC, ErrNoPrivateKey, ErrMultipleKeys, ErrNoCertificate, ErrPassword.
//
// Not supported, and refused as ErrUnsupported: public-key integrity or
// privacy modes (signedData, envelopedData), RC4, scrypt, PBES1 other than
// the PKCS#12 ones, SHA-1 inside PBMAC1, and BER (rather than DER) inside a
// certificate or a PKCS#8 key.
func Decode(data []byte, password string, opts *Options) (*Bundle, error) {
	o := opts.resolve()
	if len(data) > o.MaxInputSize {
		return nil, limit("input of %d bytes exceeds the limit of %d", len(data), o.MaxInputSize)
	}
	forms, err := passwordForms(password, &o)
	if err != nil {
		return nil, err
	}
	s := &state{opts: o}
	b, err := s.decode(data, forms)
	if err != nil && !s.authenticated && s.decrypted && errors.Is(err, ErrMalformed) {
		// No MAC vouched for the file and something decrypted into garbage:
		// the password is the likeliest culprit, and nothing can say more.
		err = ErrIncorrectPassword
	}
	return b, err
}
