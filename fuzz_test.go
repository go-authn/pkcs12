package pkcs12

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzDecode feeds arbitrary bytes to Decode with tight limits, so that one
// execution stays cheap, and asserts the contract: no panic, and every error
// wraps exactly one sentinel. A success must hold a usable bundle.
func FuzzDecode(f *testing.F) {
	for _, e := range loadManifest(f) {
		data := readFixture(f, "openssl/"+e.Name+".p12")
		f.Add(data, e.Password, e.AllowNoMAC, e.NoPassword)
	}
	for _, n := range []string{"a1", "a2", "a3", "a4", "a5", "a6"} {
		if b, err := os.ReadFile(filepath.Join("testdata", "rfc9579", n+".p12")); err == nil {
			f.Add(b, "1234", false, false)
		}
	}
	f.Add(goodFile(f, pw), pw, false, false)
	f.Add(fileOf(pw, dataCI(certBagDER(mat.cert), keyBagDER(mat.p8))), pw, true, false)
	for _, p8 := range wrongCRTKeys(f) { // pkcs12#2: all-one, wrong Qinv, Dp, Dq
		f.Add(fileOf(pw, dataCI(certBagDER(mat.cert), keyBagDER(p8))), pw, true, false)
	}
	f.Add([]byte{}, "", false, false)
	f.Add([]byte{0x30, 0x80, 0, 0}, "", true, true)

	f.Fuzz(func(t *testing.T, data []byte, password string, allowNoMAC, noPassword bool) {
		o := &Options{
			MaxInputSize:  1 << 20,
			MaxIterations: 2000,
			MaxWork:       20000,
			MaxDepth:      8,
			MaxBags:       64,
			MaxAuthSafes:  8,
			AllowNoMAC:    allowNoMAC,
			NoPassword:    noPassword,
		}
		b, err := Decode(data, password, o)
		if err != nil {
			if n := len(matching(err)); n != 1 {
				t.Fatalf("error wraps %d sentinels: %v", n, err)
			}
			return
		}
		if b == nil || b.PrivateKey == nil || b.Certificate == nil {
			t.Fatalf("success with an incomplete bundle: %+v", b)
		}
	})
}
