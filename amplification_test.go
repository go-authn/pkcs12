package pkcs12

import (
	"bytes"
	"crypto/rand"
	"errors"
	"runtime"
	"testing"
)

// The amplification test: bytes allocated by Decode divided by bytes of
// input, for hostile inputs of growing size. A decoder that allocates in
// proportion to a length field instead of to the bytes it has actually seen
// shows up here as a ratio that grows with the input, or that is far above 1
// at every size.
//
// TotalAlloc is cumulative and exact under load (it counts bytes handed out,
// whatever the collector does), so this test does not depend on the machine.

const maxRatio = 40.0 // generous; the measured worst case is logged and quoted in the README

func allocOf(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

var sweep = []int{4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 4 << 20}

type family struct {
	name  string
	build func(t testing.TB, n int) []byte
	opts  *Options
	want  error // the sentinel every size must end in; nil: any one of them
}

func repeat(unit []byte, n int) []byte {
	return bytes.Repeat(unit, n/len(unit)+1)[:n/len(unit)*len(unit)]
}

func TestAmplification(t *testing.T) {
	material(t)
	crl := bagDER(with(bagID, 4), seq())

	families := []family{
		{"many tiny bags", func(t testing.TB, n int) []byte {
			return fileOf(pw, dataCI(repeat(crl, n)))
		}, nil, nil},
		{"many certificates", func(t testing.TB, n int) []byte {
			var bags [][]byte
			cb := certBagDER(mat.cert)
			for i := 0; i < n/len(cb); i++ {
				bags = append(bags, cb)
			}
			return fileOf(pw, dataCI(bags...))
		}, nil, nil},
		{"many ContentInfos", func(t testing.TB, n int) []byte {
			var cis [][]byte
			ci := dataCI()
			for i := 0; i < n/len(ci); i++ {
				cis = append(cis, ci)
			}
			return fileOf(pw, cis...)
		}, nil, ErrLimit},
		{"deep indefinite nesting", func(t testing.TB, n int) []byte {
			b := bytes.Repeat([]byte{0x30, 0x80}, n/4)
			b = append(b, integer(1)...)
			return append(b, bytes.Repeat([]byte{0, 0}, n/4)...)
		}, nil, ErrLimit},
		{"long OCTET STRING chain", func(t testing.TB, n int) []byte {
			chain := indef(0x24, repeat(oct([]byte{1}), n))
			return seq(integer(3), seq(oidDER(oidData), ctx(0, chain)))
		}, nil, ErrNoMAC},
		{"nested OCTET STRING chunks", func(t testing.TB, n int) []byte {
			leaf := indef(0x24, repeat(oct([]byte{1}), n))
			for i := 0; i < 15; i++ {
				leaf = tlv(0x24, leaf)
			}
			return seq(integer(3), seq(oidDER(oidData), ctx(0, leaf)))
		}, nil, nil},
		{"unauthenticated ciphertext", func(t testing.TB, n int) []byte {
			p := aesP2(16)
			ct := make([]byte, n/16*16)
			rand.Read(ct)
			safe := seq(dataCI(shroudedBag(p.alg(), ct)))
			return pfxDER(3, oidData, safe)
		}, &Options{AllowNoMAC: true}, nil},
		{"huge constructed length claims", func(t testing.TB, n int) []byte {
			// A 4 GiB claim on a tiny body, repeated: refused before any allocation.
			return bytes.Repeat([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, n/6)
		}, nil, ErrMalformed},
	}

	worst, worstName := 0.0, ""
	for _, f := range families {
		for _, n := range sweep {
			in := f.build(t, n)
			var err error
			a := allocOf(func() { _, err = Decode(in, pw, f.opts) })
			if err == nil {
				t.Fatalf("%s/%d: accepted", f.name, n)
			}
			if f.want != nil && !isOnly(err, f.want) {
				t.Fatalf("%s/%d: got %v, want %v", f.name, n, err, f.want)
			}
			r := float64(a) / float64(len(in))
			t.Logf("%-28s input %8d B  alloc %9d B  ratio %6.2f  (%v)", f.name, len(in), a, r, errKind(err))
			if len(in) >= 4<<10 && r > worst {
				worst, worstName = r, f.name
			}
			if r > maxRatio {
				t.Errorf("%s: %d bytes in, %d allocated: ratio %.1f exceeds %.0f", f.name, len(in), a, r, maxRatio)
			}
		}
	}
	t.Logf("worst ratio: %.2f (%s)", worst, worstName)
}

func isOnly(err, want error) bool {
	return err == want || (len(matching(err)) == 1 && matching(err)[0] == want)
}

var sentinels = []error{ErrMalformed, ErrUnsupported, ErrLimit, ErrIncorrectPassword, ErrNoMAC, ErrNoPrivateKey, ErrMultipleKeys, ErrNoCertificate, ErrPassword}

func matching(err error) []error {
	var m []error
	for _, s := range sentinels {
		if errors.Is(err, s) {
			m = append(m, s)
		}
	}
	return m
}

func errKind(err error) string {
	if m := matching(err); len(m) == 1 {
		return m[0].Error()
	}
	return "NOT EXACTLY ONE SENTINEL: " + err.Error()
}
