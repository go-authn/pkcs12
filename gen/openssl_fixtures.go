//go:build ignore

// Command openssl_fixtures regenerates testdata/openssl/*.p12 and
// testdata/openssl/manifest.json with the local OpenSSL. Run from the
// repository root:
//
//	go run gen/openssl_fixtures.go -work <durable dir outside the repo>
//
// The private keys are made in -work and never committed (the .p12 files
// carry them, under the test passwords below, and are test-only material).
// The manifest records, for each file, what OpenSSL says it holds, so the
// package's tests compare this decoder with OpenSSL's reading, not with the
// writer's intentions.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type entry struct {
	Name       string   `json:"name"`
	Password   string   `json:"password"`
	NoPassword bool     `json:"no_password,omitempty"`
	AllowNoMAC bool     `json:"allow_no_mac,omitempty"`
	Key        string   `json:"key"`         // rsa | ecdsa | ed25519
	PubSHA256  string   `json:"pub_sha256"`  // SHA-256 of the SubjectPublicKeyInfo DER of the key
	Leaf       string   `json:"leaf_sha256"` // SHA-256 of the leaf certificate DER
	CA         []string `json:"ca_sha256"`   // SHA-256 of each other certificate DER, file order unspecified
	Flags      []string `json:"flags"`
	Needs      string   `json:"needs,omitempty"` // minimum OpenSSL for the live oracle, when not 3.0
}

func run(dir string, name string, args ...string) []byte {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s %v: %v\n%s", name, args, err, errb.String())
		os.Exit(1)
	}
	return out.Bytes()
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func derOfCert(dir, pem string) []byte {
	return run(dir, "openssl", "x509", "-in", pem, "-outform", "DER")
}

func main() {
	work := flag.String("work", "", "durable scratch directory")
	flag.Parse()
	if *work == "" {
		fmt.Fprintln(os.Stderr, "-work is required")
		os.Exit(2)
	}
	os.MkdirAll(*work, 0o700)
	out := "testdata/openssl"
	os.MkdirAll(out, 0o755)

	w := *work
	ext := filepath.Join(w, "ca.ext")
	os.WriteFile(ext, []byte("basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n"), 0o600)
	leafExt := filepath.Join(w, "leaf.ext")
	os.WriteFile(leafExt, []byte("basicConstraints=critical,CA:FALSE\n"), 0o600)

	run(w, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-keyout", "ca.key", "-out", "ca.crt",
		"-subj", "/CN=Fixture Root CA", "-days", "36500", "-addext", "basicConstraints=critical,CA:TRUE")
	run(w, "openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
		"-keyout", "int.key", "-out", "int.csr", "-subj", "/CN=Fixture Intermediate CA")
	run(w, "openssl", "x509", "-req", "-in", "int.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
		"-out", "int.crt", "-days", "36500", "-extfile", ext)
	intPEM, _ := os.ReadFile(filepath.Join(w, "int.crt"))
	caPEM, _ := os.ReadFile(filepath.Join(w, "ca.crt"))
	chain := append(intPEM, caPEM...)
	os.WriteFile(filepath.Join(w, "chain.pem"), chain, 0o600)

	type kt struct {
		name, kind string
		gen        []string
	}
	kts := []kt{
		{"rsa", "rsa", []string{"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "leaf-rsa.key"}},
		{"ec", "ecdsa", []string{"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "leaf-ec.key"}},
		{"ed25519", "ed25519", []string{"genpkey", "-algorithm", "ED25519", "-out", "leaf-ed25519.key"}},
	}
	for _, k := range kts {
		run(w, "openssl", k.gen...)
		run(w, "openssl", "req", "-new", "-key", "leaf-"+k.name+".key", "-subj", "/CN=leaf-"+k.name+".example",
			"-out", "leaf-"+k.name+".csr")
		run(w, "openssl", "x509", "-req", "-in", "leaf-"+k.name+".csr", "-CA", "int.crt", "-CAkey", "int.key",
			"-CAcreateserial", "-out", "leaf-"+k.name+".crt", "-days", "36500", "-extfile", leafExt)
	}
	caHashes := []string{sum(derOfCert(w, "int.crt")), sum(derOfCert(w, "ca.crt"))}

	const pw = "correct horse battery"
	type job struct {
		name, key, password    string
		noPassword, allowNoMAC bool
		flags                  []string
		needs                  string
		withChain              bool
	}
	jobs := []job{
		{name: "rsa-default", key: "rsa", password: pw, withChain: true},
		{name: "ec-default", key: "ec", password: pw, withChain: true},
		{name: "ed25519-default", key: "ed25519", password: pw, withChain: true},
		{name: "rsa-nochain", key: "rsa", password: pw},
		{name: "rsa-legacy", key: "rsa", password: pw, withChain: true, flags: []string{"-legacy"}},
		{name: "rsa-descert", key: "rsa", password: pw, withChain: true, flags: []string{"-descert"}},
		{name: "rsa-aes128", key: "rsa", password: pw, withChain: true, flags: []string{"-keypbe", "AES-128-CBC", "-certpbe", "AES-128-CBC"}},
		{name: "rsa-aes192", key: "rsa", password: pw, withChain: true, flags: []string{"-keypbe", "AES-192-CBC", "-certpbe", "AES-192-CBC"}},
		{name: "rsa-pbe-rc2-40", key: "rsa", password: pw, withChain: true, flags: []string{"-provider", "legacy", "-provider", "default", "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-RC2-40"}},
		{name: "rsa-pbe-rc2-128", key: "rsa", password: pw, withChain: true, flags: []string{"-provider", "legacy", "-provider", "default", "-keypbe", "PBE-SHA1-2DES", "-certpbe", "PBE-SHA1-RC2-128"}},
		{name: "rsa-mac-sha1", key: "rsa", password: pw, withChain: true, flags: []string{"-macalg", "sha1"}},
		{name: "rsa-mac-sha384", key: "rsa", password: pw, withChain: true, flags: []string{"-macalg", "sha384"}},
		{name: "rsa-mac-sha512", key: "rsa", password: pw, withChain: true, flags: []string{"-macalg", "sha512"}},
		{name: "rsa-nomac", key: "rsa", password: pw, withChain: true, allowNoMAC: true, flags: []string{"-nomac"}},
		{name: "rsa-pbmac1", key: "rsa", password: pw, withChain: true, flags: []string{"-pbmac1_pbkdf2"}, needs: "3.4"},
		{name: "rsa-pbmac1-sha512", key: "rsa", password: pw, withChain: true, flags: []string{"-pbmac1_pbkdf2", "-pbmac1_pbkdf2_md", "sha512"}, needs: "3.4"},
		{name: "rsa-iter-1", key: "rsa", password: pw, withChain: true, flags: []string{"-iter", "1", "-macalg", "sha256"}},
		{name: "rsa-iter-100000", key: "rsa", password: pw, withChain: true, flags: []string{"-iter", "100000"}},
		{name: "rsa-empty-password", key: "rsa", password: "", withChain: true},
		{name: "rsa-unicode-password", key: "rsa", password: "pässwörd-日本語-😀", withChain: true},
		{name: "rsa-unicode-password-legacy", key: "rsa", password: "pässwörd-日本語-😀", withChain: true, flags: []string{"-legacy"}},
		{name: "rsa-plain-mac", key: "rsa", password: pw, withChain: true, flags: []string{"-keypbe", "NONE", "-certpbe", "NONE"}},
		{name: "rsa-plain-nomac-nopassword", key: "rsa", password: "", noPassword: true, allowNoMAC: true, withChain: true, flags: []string{"-keypbe", "NONE", "-certpbe", "NONE", "-nomac"}},
	}

	var manifest []entry
	for _, j := range jobs {
		leaf := "leaf-" + j.key
		args := []string{"pkcs12", "-export", "-inkey", leaf + ".key", "-in", leaf + ".crt", "-out", filepath.Join(filepath.Join(os.Getenv("PWD"), out), j.name+".p12"), "-passout", "pass:" + j.password, "-name", "fixture"}
		if j.withChain {
			args = append(args, "-certfile", "chain.pem")
		}
		args = append(args, j.flags...)
		run(w, "openssl", args...)

		pub := run(w, "openssl", "pkey", "-in", leaf+".key", "-pubout", "-outform", "DER")
		kind := map[string]string{"rsa": "rsa", "ec": "ecdsa", "ed25519": "ed25519"}[j.key]
		e := entry{Name: j.name, Password: j.password, NoPassword: j.noPassword, AllowNoMAC: j.allowNoMAC,
			Key: kind, PubSHA256: sum(pub), Leaf: sum(derOfCert(w, leaf+".crt")), Flags: j.flags, Needs: j.needs}
		if j.withChain {
			e.CA = caHashes
		}
		manifest = append(manifest, e)
	}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(filepath.Join(out, "manifest.json"), append(b, '\n'), 0o644)
}
