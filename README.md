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
  claims, and bounds allocated bytes over input bytes. **Worst measured ratio:
  8.6** (many small certificates, each one a parsed `*x509.Certificate`); it
  does not grow with size.
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
