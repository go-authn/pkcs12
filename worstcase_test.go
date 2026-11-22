package pkcs12

import "testing"

// TestWorstCaseFamily is the most expensive input the defaults admit: copies
// of the densest certificate that fits MaxCertSize (names of 2 bytes), enough
// of them to fill MaxCertBytes, once as plain bags and once with the bags
// inside an encrypted, constructed (BER) authSafe, the layered form the
// external review measured at 47x. The suite's own measurement is what the
// README quotes.
func TestWorstCaseFamily(t *testing.T) {
	material(t)
	der := tinyCert(t, DefaultMaxCertSize)
	if len(der) < DefaultMaxCertSize-64 {
		t.Fatalf("certificate of %d bytes does not reach the cap %d", len(der), DefaultMaxCertSize)
	}
	copies := DefaultMaxCertBytes / len(der)
	plain := [][]byte{keyBagDER(mat.p8)}
	layered := [][]byte{keyBagDER(mat.p8)}
	for i := 0; i < copies; i++ {
		plain = append(plain, certBagDER(der))
		layered = append(layered, bagDER(oidCertBag, seq(oidDER(oidX509Certificate), ctx(0, tlv(0x24, oct(der))))))
	}
	p := aesP2(16)
	ct := p.seal(t, pw, pad(seq(layered...), 16))
	eci := seq(oidDER(oidData), p.alg(), tlv(0xa0, oct(ct)))
	safe := seq(seq(oidDER(oidEncryptedData), ctx(0, seq(integer(0), eci))))
	inputs := map[string][]byte{
		"plain":   fileOf(pw, dataCI(plain...)),
		"layered": seq(integer(3), seq(oidDER(oidData), ctx(0, tlv(0x24, oct(safe)))), sha1MAC(pw).der(safe)),
	}
	for _, name := range []string{"plain", "layered"} {
		in := inputs[name]
		b, err, a := decodeAlloc(t, in, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if kept := len(b.CACerts); b.Certificate != nil {
			kept++
		} else if kept != copies {
			t.Fatalf("%s: %d certificates kept, want %d", name, kept, copies)
		}
		r := float64(a) / float64(len(in))
		t.Logf("%s: %d certificates of %d B, file %d B: alloc %d B, ratio %.1f", name, copies, len(der), len(in), a, r)
		if a > absoluteBound {
			t.Errorf("%s: alloc %d exceeds the absolute bound %d", name, a, absoluteBound)
		}
		if r > maxCertRatio {
			t.Errorf("%s: ratio %.1f exceeds %.0f", name, r, maxCertRatio)
		}
	}
}
