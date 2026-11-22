package pkcs12

// Defaults for Options. A zero (or negative) field means "the default"; no
// field can switch a bound off.
const (
	DefaultMaxInputSize  = 8 << 20   // bytes of input
	DefaultMaxIterations = 1_000_000 // per key derivation
	DefaultMaxWork       = 5_000_000 // iterations x output blocks, over the whole file
	DefaultMaxDepth      = 16        // nested indefinite-length / constructed-string levels
	DefaultMaxBags       = 1024      // SafeBags, over the whole file
	DefaultMaxAuthSafes  = 32        // ContentInfos in the AuthenticatedSafe
	// DefaultMaxCertSize bounds one certificate's DER. Real certificates are
	// 1 to 4 KiB, a 100-name multi-domain one about 8 KiB, and the largest
	// seen in the wild 10 to 20 KiB; post-quantum ones (ML-DSA-87) are about
	// 8 KiB. 32 KiB leaves room for all of them. The bound exists because
	// crypto/x509 allocates 50 times the input for a certificate made of
	// thousands of tiny names, and that factor cannot be removed from outside.
	DefaultMaxCertSize = 32 << 10
	// DefaultMaxCertBytes bounds all certificate DER of one file together. A
	// leaf with its chain is 4 to 16 KiB; a bundle of every public root is
	// about 200 KiB. 512 KiB holds that, and bounds what x509 can allocate for
	// a hostile file to about 26 MB.
	DefaultMaxCertBytes = 512 << 10
	// DefaultMaxRSABits bounds an RSA modulus. Real keys are 2048 to 4096 bits.
	// crypto/rsa itself sets no upper limit (it only refuses fewer than 1024
	// bits unless GODEBUG says otherwise), and OpenSSL stops at 16384
	// (OPENSSL_RSA_MAX_MODULUS_BITS); 8192 is twice the largest key in use.
	DefaultMaxRSABits = 8192

	maxSaltLen = 512 // bytes, any KDF salt
	// maxKeyDER bounds a PKCS#8 private key of any type: an RSA key of 16384
	// bits is under 10 KiB, an EC or Ed25519 key under 200 bytes.
	maxKeyDER        = 32 << 10
	maxPasswordRunes = 1024
)

// Options tunes Decode. The zero value, or a nil *Options, is the safe default.
type Options struct {
	// MaxInputSize bounds len(data). Default 8 MiB.
	MaxInputSize int

	// MaxIterations bounds the iteration count of any one key derivation
	// (PKCS#12 B.2 or PBKDF2). A file asking for more is refused with
	// ErrLimit before any hashing. Default 1 000 000, about half a second of
	// PBKDF2-HMAC-SHA-256 on one modern core; real exports use 1 000 to
	// 600 000.
	MaxIterations int

	// MaxWork bounds the total cost of every key derivation of one Decode, in
	// iterations times output blocks, so that many individually acceptable
	// derivations cannot add up to a CPU bomb. Default 5 000 000.
	MaxWork int64

	// MaxDepth bounds BER nesting: indefinite-length elements inside one
	// another, and constructed OCTET STRING chunks. Default 16.
	MaxDepth int

	// MaxBags bounds the SafeBags in the whole file. Default 1024.
	MaxBags int

	// MaxAuthSafes bounds the ContentInfos of the AuthenticatedSafe. Default 32.
	MaxAuthSafes int

	// MaxCertSize bounds the DER of one certificate, checked before
	// crypto/x509 sees it. Default 32 KiB.
	MaxCertSize int

	// MaxCertBytes bounds the DER of all certificates of the file together,
	// checked before crypto/x509 sees them. Default 512 KiB.
	MaxCertBytes int

	// MaxRSABits bounds the modulus of an RSA private key, and with it every
	// number of the key, checked before crypto/x509 sees it. Default 8192.
	MaxRSABits int

	// AllowNoMAC lets Decode read a file that has no integrity MAC (made by
	// `openssl pkcs12 -nomac`). Nothing then authenticates the content, and a
	// wrong password is only noticed by a failed decryption. Default false:
	// such a file is refused with ErrNoMAC.
	AllowNoMAC bool

	// NoPassword says the file was exported with no password at all (a NULL
	// password, a zero-length byte string), as opposed to the empty password
	// "" (a BMPString holding only its terminator). The two derive different
	// keys. With the password "" and NoPassword false, Decode tries the empty
	// password first and then the absent one, because exporters disagree about
	// which they wrote; with NoPassword true only the absent one is tried, and
	// the password argument must be "".
	NoPassword bool
}

func (o *Options) resolve() Options {
	var r Options
	if o != nil {
		r = *o
	}
	if r.MaxInputSize <= 0 {
		r.MaxInputSize = DefaultMaxInputSize
	}
	if r.MaxIterations <= 0 {
		r.MaxIterations = DefaultMaxIterations
	}
	if r.MaxWork <= 0 {
		r.MaxWork = DefaultMaxWork
	}
	if r.MaxDepth <= 0 {
		r.MaxDepth = DefaultMaxDepth
	}
	if r.MaxBags <= 0 {
		r.MaxBags = DefaultMaxBags
	}
	if r.MaxAuthSafes <= 0 {
		r.MaxAuthSafes = DefaultMaxAuthSafes
	}
	if r.MaxCertSize <= 0 {
		r.MaxCertSize = DefaultMaxCertSize
	}
	if r.MaxCertBytes <= 0 {
		r.MaxCertBytes = DefaultMaxCertBytes
	}
	if r.MaxRSABits <= 0 {
		r.MaxRSABits = DefaultMaxRSABits
	}
	return r
}
