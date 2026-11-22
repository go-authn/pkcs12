package pkcs12

import (
	"errors"
	"fmt"
)

// Every refusal Decode returns wraps exactly one of these, so a caller can
// tell a wrong password from a hostile file from a format this package does
// not speak. The fuzz targets hold that as an invariant.
var (
	// ErrMalformed: the input is not a PKCS#12 file this package can read.
	ErrMalformed = errors.New("pkcs12: malformed input")

	// ErrUnsupported: a well-formed file that uses something not implemented
	// here (public-key integrity mode, RC4, scrypt, an unknown OID...).
	ErrUnsupported = errors.New("pkcs12: unsupported")

	// ErrLimit: a resource bound was exceeded (input size, nesting depth,
	// iteration count, bag count...). The bounds are Options.
	ErrLimit = errors.New("pkcs12: resource limit exceeded")

	// ErrIncorrectPassword: the integrity MAC did not verify. A wrong password
	// and a tampered file are indistinguishable here, by design: the MAC is
	// the only oracle this package offers. (When the file carries no MAC and
	// Options.AllowNoMAC is set, a failed decryption is reported the same
	// way, since nothing else can tell.)
	ErrIncorrectPassword = errors.New("pkcs12: incorrect password or corrupted file")

	// ErrNoMAC: the file has no integrity MAC and Options.AllowNoMAC is false.
	ErrNoMAC = errors.New("pkcs12: file has no MAC (set Options.AllowNoMAC to read it unauthenticated)")

	// ErrNoPrivateKey: the file holds no private key.
	ErrNoPrivateKey = errors.New("pkcs12: no private key in file")

	// ErrMultipleKeys: the file holds more than one private key; which one is
	// wanted is not guessed.
	ErrMultipleKeys = errors.New("pkcs12: more than one private key in file")

	// ErrNoCertificate: no certificate matches the private key.
	ErrNoCertificate = errors.New("pkcs12: no certificate matches the private key")

	// ErrPassword: the password cannot be used (invalid UTF-8, too long, or
	// contradicts Options.NoPassword).
	ErrPassword = errors.New("pkcs12: unusable password")
)

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

func unsupported(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, a...))
}

func limit(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrLimit, fmt.Sprintf(format, a...))
}
