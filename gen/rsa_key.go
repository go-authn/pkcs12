//go:build ignore

// rsa_key writes testdata/rsa4096.p8 and testdata/rsa8192.p8: real RSA keys,
// PKCS#8 DER, the "large valid key" of the amplification tests (8192 bits is
// the largest MaxRSABits admits by default). Generating them in the test would
// cost seconds natively and minutes under qemu.
//
//	go run gen/rsa_key.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

func main() {
	for _, bits := range []int{4096, 8192} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			log.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(fmt.Sprintf("testdata/rsa%d.p8", bits), der, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
