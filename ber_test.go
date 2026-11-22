package pkcs12

import (
	"bytes"
	"testing"
)

func TestReadElemRefusals(t *testing.T) {
	deep := func(n int) []byte { // n nested indefinite SEQUENCEs
		b := []byte{}
		for i := 0; i < n; i++ {
			b = append(b, 0x30, 0x80)
		}
		for i := 0; i < n; i++ {
			b = append(b, 0, 0)
		}
		return b
	}
	for _, tc := range []struct {
		name string
		in   []byte
		want error
		msg  string
	}{
		{"empty", nil, ErrMalformed, "truncated"},
		{"one byte", []byte{0x30}, ErrMalformed, "truncated"},
		{"high tag", []byte{0x1f, 0x00}, ErrUnsupported, "tag numbers"},
		{"0xff length", []byte{0x30, 0xff}, ErrMalformed, "0xff"},
		{"five length octets", []byte{0x30, 0x85, 1, 0, 0, 0, 0}, ErrMalformed, "5 octets"},
		{"length octets cut", []byte{0x30, 0x82, 0x01}, ErrMalformed, "2 octets"},
		{"length beyond input", []byte{0x04, 0x05, 1}, ErrMalformed, "exceeds"},
		{"4 GiB length", []byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xff}, ErrMalformed, "exceeds"},
		{"indefinite primitive", []byte{0x04, 0x80, 0, 0}, ErrMalformed, "primitive"},
		{"indefinite unterminated", []byte{0x30, 0x80, 0x04, 0x01, 0x41}, ErrMalformed, "truncated"},
		{"nesting too deep", deep(5), ErrLimit, "deeper than 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			safely(t, func() { _, _, err = readElem(tc.in, 0, 3) })
			wantErr(t, err, tc.want, tc.msg)
		})
	}
}

func TestReadElemForms(t *testing.T) {
	long := bytes.Repeat([]byte{7}, 300)
	for _, tc := range []struct {
		name          string
		in            []byte
		cons          bool
		content, rest []byte
	}{
		{"short", []byte{0x04, 0x02, 1, 2, 9}, false, []byte{1, 2}, []byte{9}},
		{"long form", append([]byte{0x04, 0x82, 0x01, 0x2c}, long...), false, long, []byte{}},
		{"indefinite", []byte{0x30, 0x80, 0x04, 0x01, 0x41, 0, 0, 9}, true, []byte{0x04, 0x01, 0x41}, []byte{9}},
		{"indefinite nested", []byte{0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0}, true, []byte{0x30, 0x80, 0, 0}, []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, rest, err := readElem(tc.in, 0, 3)
			if err != nil {
				t.Fatal(err)
			}
			if e.cons != tc.cons || !bytes.Equal(e.content, tc.content) || !bytes.Equal(rest, tc.rest) {
				t.Fatalf("got cons=%v content=%x rest=%x", e.cons, e.content, rest)
			}
			if !bytes.Equal(e.raw, tc.in[:len(tc.in)-len(rest)]) {
				t.Fatalf("raw %x", e.raw)
			}
		})
	}
}

func cur(b []byte) (*cursor, *error) {
	var err error
	return newCursor(b, 3, &err), &err
}

func TestCursorShape(t *testing.T) {
	t.Run("class or tag mismatch", func(t *testing.T) {
		c, err := cur(oct([]byte{1}))
		c.takeElem(classUniversal, tagSequence, "thing")
		wantErr(t, *err, ErrMalformed, "thing")
	})
	t.Run("form mismatch", func(t *testing.T) {
		c, err := cur([]byte{0x10, 0x00}) // a primitive SEQUENCE
		c.take(classUniversal, tagSequence, true, "thing")
		wantErr(t, *err, ErrMalformed, "primitive/constructed")
	})
	t.Run("trailing element", func(t *testing.T) {
		c, err := cur(cat(oct(nil), oct(nil)))
		c.oid("x") // fails: it is an OCTET STRING; the error sticks
		c.end("x")
		wantErr(t, *err, ErrMalformed, "x")
		c, err = cur(cat(oct(nil), oct(nil)))
		c.octets(classUniversal, tagOctetString, "a")
		c.end("a")
		wantErr(t, *err, ErrMalformed, "trailing")
	})
	t.Run("sticky error", func(t *testing.T) {
		c, err := cur(oct(nil))
		c.fail(ErrLimit)
		c.fail(ErrMalformed)
		if *err != ErrLimit {
			t.Fatalf("first error did not stick: %v", *err)
		}
		if c.more() {
			t.Fatal("more() after an error")
		}
		if _, _, ok := c.peek(); ok {
			t.Fatal("peek() after an error")
		}
		if e := c.any("x"); e.raw != nil {
			t.Fatal("any() after an error returned data")
		}
	})
	t.Run("peek", func(t *testing.T) {
		c, _ := cur(integer(5))
		cl, tg, ok := c.peek()
		if !ok || cl != classUniversal || tg != tagInteger {
			t.Fatalf("peek = %d %d %v", cl, tg, ok)
		}
		c, _ = cur(nil)
		safely(t, func() {
			if _, _, ok := c.peek(); ok {
				t.Fatal("peek on an empty cursor")
			}
		})
	})
	t.Run("any reports a bad element", func(t *testing.T) {
		c, err := cur([]byte{0x30, 0xff})
		c.any("x")
		wantErr(t, *err, ErrMalformed, "0xff")
	})
}

func TestCursorInteger(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want int64
		err  error
	}{
		{"zero", []byte{2, 1, 0}, 0, nil},
		{"128", []byte{2, 2, 0, 0x80}, 128, nil},
		{"minus one", []byte{2, 1, 0xff}, -1, nil},
		{"eight octets", []byte{2, 8, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 1<<63 - 1, nil},
		{"empty", []byte{2, 0}, 0, ErrMalformed},
		{"nine octets", []byte{2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0}, 0, ErrLimit},
		{"not an integer", oct(nil), 0, ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := cur(tc.in)
			var got int64
			safely(t, func() { got = c.integer("n") })
			if tc.err == nil {
				if *err != nil || got != tc.want {
					t.Fatalf("got %d, %v", got, *err)
				}
				return
			}
			wantErr(t, *err, tc.err, "")
		})
	}
}

func TestCursorOctets(t *testing.T) {
	cons := func(parts ...[]byte) []byte { return tlv(0x24, cat(parts...)) }
	for _, tc := range []struct {
		name string
		in   []byte
		want string
		err  error
	}{
		{"primitive", oct([]byte("abc")), "abc", nil},
		{"chunks", cons(oct([]byte("ab")), oct([]byte("c"))), "abc", nil},
		{"nested chunks", cons(oct([]byte("a")), cons(oct([]byte("b")), oct([]byte("c")))), "abc", nil},
		{"indefinite chunks", indef(0x24, oct([]byte("ab")), oct([]byte("c"))), "abc", nil},
		{"empty constructed", cons(), "", nil},
		{"foreign chunk", cons(integer(1)), "", ErrMalformed},
		{"truncated chunk", tlv(0x24, []byte{0x04, 0x09, 1}), "", ErrMalformed},
		{"too deep", cons(cons(cons(cons(oct([]byte("x")))))), "", ErrLimit},
		{"wrong tag", integer(1), "", ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := cur(tc.in)
			var got []byte
			safely(t, func() { got = c.octets(classUniversal, tagOctetString, "s") })
			if tc.err != nil {
				wantErr(t, *err, tc.err, "")
				return
			}
			if *err != nil || string(got) != tc.want {
				t.Fatalf("got %q, %v", got, *err)
			}
		})
	}
}
