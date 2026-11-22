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
	maxSaltLen           = 512       // bytes, any KDF salt
	maxPasswordRunes     = 1024
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
	return r
}
