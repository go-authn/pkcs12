# pkcs12

Read **PKCS#12** (`.p12` / `.pfx`, [RFC 7292](https://www.rfc-editor.org/rfc/rfc7292))
files in pure Go, with no dependencies beyond the standard library: the private
key, its certificate and the rest of the chain. Built for **untrusted uploads**.
`CGO_ENABLED=0`.

```go
b, err := pkcs12.Decode(data, password, nil)
switch {
case errors.Is(err, pkcs12.ErrIncorrectPassword): // ask again
case err != nil:                                   // hostile, unsupported, too costly...
}
// b.PrivateKey   *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey or *ecdh.PrivateKey
// b.Certificate  the certificate holding the key's public half
// b.CACerts      every other certificate, in file order
```

It **decodes only**. Whether to trust the chain is `crypto/x509`'s `Verify`.

## Why not `golang.org/x/crypto/pkcs12`

It is deprecated and frozen: SHA-1 and 3DES/RC2 only, so it rejects what
OpenSSL 3 and 4 and current Windows write by default (PBES2, AES, SHA-2 MACs).
`software.sslmate.com/src/go-pkcs12` is maintained but refuses some files this
package reads (table below) and is not built around hostile input.

## What it reads

| layer | supported |
|---|---|
| encryption | PBES2 ([RFC 8018](https://www.rfc-editor.org/rfc/rfc8018)) with PBKDF2 over HMAC-SHA-1/224/256/384/512 and AES-128/192/256-CBC |
| legacy encryption | `pbeWithSHAAnd3-KeyTripleDES-CBC`, `pbeWithSHAAnd2-KeyTripleDES-CBC`, `pbeWithSHAAnd40BitRC2-CBC` and the 128-bit variant; RC2 is implemented in this module |
| integrity | HMAC MAC with SHA-1/224/256/384/512 (RFC 7292 Appendix B KDF), and **PBMAC1** ([RFC 9579](https://www.rfc-editor.org/rfc/rfc9579)), including its Appendix A vectors |
| passwords | BMPString per Appendix B.1, non-BMP characters as surrogate pairs; the **empty** password (`""`) and the **absent** password (`Options.NoPassword`) are different keys and both work |
| encoding | BER, including indefinite lengths and constructed OCTET STRINGs ([X.690](https://www.itu.int/rec/T-REC-X.690)), which Windows and Java write |
| bags | shrouded and plain key bags, certificate bags; CRL, secret and safe-contents bags are skipped |

**Refused as `ErrUnsupported`:** public-key integrity and privacy modes
(`signedData`, `envelopedData`), RC4, scrypt, PBES1 other than the PKCS#12
ones, SHA-1 inside PBMAC1, and BER (rather than DER) inside a certificate or a
PKCS#8 key. `ErrNoMAC` refuses a file with no MAC unless `Options.AllowNoMAC`.

## Resource bounds

Every bound is an `Options` field; a zero field means the default, and **no
field can switch a bound off**. A refusal wraps `ErrLimit`, before the work.

| field | default | bounds |
|---|---|---|
| `MaxInputSize` | 8 MiB | `len(data)` |
| `MaxIterations` | 1 000 000 | iterations of any one key derivation (2^31 is refused before any hashing) |
| `MaxWork` | 5 000 000 | iterations x output blocks over the whole file, so many acceptable derivations cannot add up |
| `MaxDepth` | 16 | BER nesting and constructed-string chunk nesting |
| `MaxBags` | 1024 | SafeBags in the file |
| `MaxAuthSafes` | 32 | ContentInfos in the AuthenticatedSafe |
| `MaxCertSize` | 32 KiB | DER of one certificate, checked before `crypto/x509` sees it (real ones: 1 to 4 KiB, 10 to 20 KiB at the very most) |
| `MaxCertBytes` | 512 KiB | DER of all certificates together (a chain is 4 to 16 KiB, a bundle of every public root about 200 KiB) |
| `MaxRSABits` | 8192 | RSA modulus, and with it every number of the key (`crypto/rsa` has no upper limit; OpenSSL stops at 16384; real keys are 2048 to 4096) |

`crypto/x509` allocates up to 43 to 52 times a certificate's size when it is
made of thousands of tiny names, and `crypto/rsa` validates a key by arithmetic
on the numbers it declares, so factors far longer than the modulus cost
superlinear CPU. Neither can be fixed from outside, so what reaches them is
bounded first: certificates by the two sizes above, and every PKCS#8 key (32 KiB
at most) is read with `encoding/asn1` and refused, typed, when its modulus
exceeds `MaxRSABits`, a factor or exponent is longer than the modulus allows, a
number is not positive, or it is multi-prime (`ErrUnsupported`). EC, Ed25519
and X25519 keys cost one scalar multiplication whatever they declare.

**Known limitation: RSA keys without CRT values.** An RSA key lacking `Dp`,
`Dq` and `Qinv` is refused (`ErrUnsupported`) before `crypto/x509` sees it.
RFC 8017 requires them and every exporter writes them (OpenSSL, Windows, Java
keytool), but `crypto/x509` reads such a key and derives them with big-number
arithmetic: 16.4 MB and 21 744 allocations at 8192 bits, against 0.36 MB and 618
with them, which with the worst certificates exceeds the bound asserted below.

**Memory per request.** With the default options, a hostile file makes one
`Decode` allocate about 25 MB (measured jointly, worst certificates and the
largest accepted key, 8192 bits: 25.1 MB, of which about 20 MB stay live until
it returns) for a file of 530 KB. A service decoding uploads should
cap the decodes in flight, for instance with a semaphore, and lower
`MaxCertBytes` if it expects only short chains.

Salts over 512 bytes and passwords over 1024 characters are refused. Every
length field is checked against the bytes actually present before anything is
allocated.

The MAC is verified, **in constant time, before anything is decrypted**. A
wrong password and a tampered file are the same answer by design,
`ErrIncorrectPassword`; with `AllowNoMAC` a file that decrypts to garbage is
reported the same way, since nothing else can tell.

## Errors

`ErrMalformed`, `ErrUnsupported`, `ErrLimit`, `ErrIncorrectPassword`,
`ErrNoMAC`, `ErrNoPrivateKey`, `ErrMultipleKeys`, `ErrNoCertificate` and
`ErrPassword`. Every refusal wraps exactly one; the fuzz target holds that as an
invariant.

## How it is checked

- **OpenSSL is the judge.** `testdata/openssl/` holds 23 files written by
  OpenSSL 4.1 (`gen/openssl_fixtures.go`): AES/PBES2, `-legacy` 3DES and RC2,
  `-nomac`, several certificates, RSA, EC and Ed25519, PBMAC1; the manifest
  records what OpenSSL itself says each holds. CI requires `openssl` on Ubuntu.
- **Amplification.** `TestAmplification` sweeps 4 KiB to 4 MiB over many tiny
  bags, many certificates, many ContentInfos, deep indefinite nesting, long and
  nested OCTET STRING chains, unauthenticated ciphertext and 4 GiB length
  claims, and bounds allocated bytes over input bytes: worst ratio 8.6 on
  those, which are refused. A second set **decodes successfully**: certificates
  of tiny names up to the cap, and sixteen of the densest (names of 2 bytes)
  filling `MaxCertBytes`, plain and inside an encrypted constructed authSafe
  (**worst ratio 43 of the file plain, 47 layered; joint with the largest
  accepted key, 8192 bits: 47.4 and 25.1 MB allocated for a 530 KB file**, the
  cost of `crypto/x509` itself), and real RSA keys of 2048 and 4096 bits (17
  at most, 63 KB). The tests assert the absolute bound too (64 x `MaxCertBytes`,
  32 MiB for any file) and that the refusals above happen **before**
  `crypto/x509` is called, by counting its calls.
- **Fuzzing** (`FuzzDecode`, corpus committed in `testdata/fuzz`), 100 % block
  coverage, `mutsweep` with no survivor and no panic-only catch, `-race`,
  `govulncheck`, and the suite on amd64, arm64, 386, arm, riscv64 and s390x.

### Against `software.sslmate.com/src/go-pkcs12` (`oracle/`, a separate module)

On the 23 OpenSSL files both can attempt, both read 18 with byte-identical
leaf, chain order and key. **Only this package reads 5**: RC2-128, a SHA-384
MAC, no MAC, and two files whose password has characters outside the BMP.
There is none the other reads and this one refuses.

Decoding one file, Apple M4 Max, single process, `go test -bench -benchmem`
(**allocation counts are exact; the timing run was made at a load above 8 and
is not quoted**):

| file | this package | sslmate |
|---|---|---|
| RSA, PBES2/AES-256 | 235 allocs, 29 KB | 2 359 allocs, 107 KB |
| RSA, legacy 3DES + RC2 | 239 allocs, 28 KB | 12 617 allocs, 336 KB |
| RSA, 100 000 iterations | 235 allocs, 29 KB | 100 311 allocs, 3.2 MB |
| EC P-256 | 196 allocs, 18 KB | 2 318 allocs, 94 KB |

## Install

```sh
go get github.com/go-authn/pkcs12
```

Pairs with [go-authn/cms](https://github.com/go-authn/cms): decode a `.p12`
here, sign there.
