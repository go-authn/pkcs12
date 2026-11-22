//go:build ignore

// rsa_key writes testdata/rsa4096.p8: one real 4096-bit RSA key, PKCS#8 DER,
// the "large valid key" of the amplification test. Generating it in the test
// would cost seconds natively and minutes under qemu.
//
//	go run gen/rsa_key.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"os"
)

func main() {
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("testdata/rsa4096.p8", der, 0o644); err != nil {
		log.Fatal(err)
	}
}
