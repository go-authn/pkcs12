package pkcs12

// A small BER reader: encoding/asn1 is DER-only, and PKCS#12 files written by
// Windows, Java and old OpenSSL use indefinite lengths and constructed OCTET
// STRINGs (X.690 8.1.3.6, 8.7.3). Nothing here allocates except flattening a
// constructed string, whose result is never larger than its input, so the
// reader adds no amplification of its own: it hands out sub-slices of the
// input and a position.
//
// Bounds: high tag numbers are refused (PKCS#12 uses none); a definite length
// must fit in the bytes that remain; the nesting of indefinite-length
// elements, and of constructed string chunks, is capped at maxDepth.

const (
	classUniversal = 0
	classContext   = 2

	tagInteger     = 2
	tagOctetString = 4
	tagOID         = 6
	tagSequence    = 16
	tagSet         = 17
)

type elem struct {
	class   int
	tag     int
	cons    bool
	content []byte // content octets; for an indefinite length, without the end-of-contents
	raw     []byte // identifier, length, content (and end-of-contents)
}

// readElem reads one element from the front of b. depth is the number of
// indefinite-length elements being scanned around it.
func readElem(b []byte, depth, maxDepth int) (e elem, rest []byte, err error) {
	if len(b) < 2 {
		return e, nil, malformed("truncated element")
	}
	id := b[0]
	if id&0x1f == 0x1f {
		return e, nil, unsupported("tag numbers of 31 and above")
	}
	e.class, e.cons, e.tag = int(id>>6), id&0x20 != 0, int(id&0x1f)

	hdr := 2
	indefinite := false
	var n uint64
	switch l := b[1]; {
	case l < 0x80:
		n = uint64(l)
	case l == 0x80:
		indefinite = true
	case l == 0xff:
		return e, nil, malformed("reserved length octet 0xff")
	default:
		k := int(l & 0x7f)
		if k > 4 || len(b) < 2+k {
			return e, nil, malformed("length of %d octets", k)
		}
		for _, c := range b[2 : 2+k] {
			n = n<<8 | uint64(c)
		}
		hdr += k
	}

	if !indefinite {
		if n > uint64(len(b)-hdr) {
			return e, nil, malformed("length %d exceeds the %d bytes left", n, len(b)-hdr)
		}
		end := hdr + int(n)
		e.content, e.raw = b[hdr:end], b[:end]
		return e, b[end:], nil
	}

	if !e.cons {
		return e, nil, malformed("indefinite length on a primitive element")
	}
	if depth >= maxDepth {
		return e, nil, limit("indefinite-length nesting deeper than %d", maxDepth)
	}
	p := b[hdr:]
	for len(p) >= 2 && (p[0] != 0 || p[1] != 0) {
		var cerr error
		if _, p, cerr = readElem(p, depth+1, maxDepth); cerr != nil {
			return e, nil, cerr
		}
	}
	if len(p) < 2 {
		return e, nil, malformed("truncated element: no end-of-contents")
	}
	e.content, e.raw = b[hdr:len(b)-len(p)], b[:len(b)-len(p)+2]
	return e, p[2:], nil
}

// cursor walks the elements of one constructed value. All cursors of one
// parse share an error slot: the first failure sticks, every later call is a
// no-op returning zero values, and the caller checks once at the end. That
// keeps the schema code linear.
type cursor struct {
	b   []byte
	max int
	err *error
}

func newCursor(b []byte, maxDepth int, err *error) *cursor {
	return &cursor{b: b, max: maxDepth, err: err}
}

func (c *cursor) fail(err error) {
	if *c.err == nil {
		*c.err = err
	}
}

func (c *cursor) more() bool { return *c.err == nil && len(c.b) > 0 }

func (c *cursor) sub(e elem) *cursor { return &cursor{b: e.content, max: c.max, err: c.err} }

// peek reports the identifier of the next element without consuming it.
func (c *cursor) peek() (class, tag int, ok bool) {
	if !c.more() {
		return 0, 0, false
	}
	return int(c.b[0] >> 6), int(c.b[0] & 0x1f), true
}

// takeElem consumes the next element, which must have the given class and tag
// (primitive or constructed).
func (c *cursor) takeElem(class, tag int, what string) elem {
	e := c.any(what)
	if *c.err == nil && (e.class != class || e.tag != tag) {
		c.fail(malformed("%s: unexpected element (class %d, tag %d)", what, e.class, e.tag))
		return elem{}
	}
	return e
}

// take is takeElem for an element whose constructed bit is known.
func (c *cursor) take(class, tag int, cons bool, what string) elem {
	e := c.takeElem(class, tag, what)
	if *c.err == nil && e.cons != cons {
		c.fail(malformed("%s: wrong primitive/constructed form", what))
		return elem{}
	}
	return e
}

func (c *cursor) seq(what string) *cursor {
	return c.sub(c.take(classUniversal, tagSequence, true, what))
}

func (c *cursor) explicit(tag int, what string) *cursor {
	return c.sub(c.take(classContext, tag, true, what))
}

func (c *cursor) oid(what string) []byte {
	return c.take(classUniversal, tagOID, false, what).content
}

// any consumes the next element whatever it is (an ANY, such as an
// AlgorithmIdentifier's parameters).
func (c *cursor) any(what string) elem {
	if *c.err != nil {
		return elem{}
	}
	if len(c.b) == 0 {
		c.fail(malformed("%s: missing", what))
		return elem{}
	}
	e, rest, err := readElem(c.b, 0, c.max)
	if err != nil {
		c.fail(err)
		return elem{}
	}
	c.b = rest
	return e
}

// end fails if elements remain.
func (c *cursor) end(what string) {
	if *c.err == nil && len(c.b) > 0 {
		c.fail(malformed("%s: unexpected trailing element", what))
	}
}

// integer reads an INTEGER that fits in int64; anything wider is a limit, not
// a malformation, because a 2^64 iteration count is a refusal to make.
func (c *cursor) integer(what string) int64 {
	e := c.take(classUniversal, tagInteger, false, what)
	if len(e.content) == 0 {
		c.fail(malformed("%s: empty INTEGER", what))
		return 0
	}
	if len(e.content) > 8 {
		c.fail(limit("%s: INTEGER wider than 64 bits", what))
		return 0
	}
	v := int64(int8(e.content[0]))
	for _, b := range e.content[1:] {
		v = v<<8 | int64(b)
	}
	return v
}

// octets reads an OCTET STRING, primitive or constructed (BER chunks), and
// returns its value. A primitive string is a sub-slice of the input; a
// constructed one is copied once, into a buffer as large as its content at
// most. asClass/asTag name the identifier the string carries, which is
// [0] IMPLICIT for EncryptedContent.
func (c *cursor) octets(asClass, asTag int, what string) []byte {
	e := c.takeElem(asClass, asTag, what)
	if !e.cons { // also a failed take: it returns the zero element
		return e.content
	}
	out, err := appendChunks(make([]byte, 0, len(e.content)), e, 0, c.max)
	if err != nil {
		c.fail(err)
		return nil
	}
	return out
}

func appendChunks(buf []byte, e elem, depth, maxDepth int) ([]byte, error) {
	if depth >= maxDepth {
		return nil, limit("constructed string nested deeper than %d", maxDepth)
	}
	rest := e.content
	for len(rest) > 0 {
		var ch elem
		var err error
		if ch, rest, err = readElem(rest, 0, maxDepth); err != nil {
			return nil, err
		}
		if ch.class != classUniversal || ch.tag != tagOctetString {
			return nil, malformed("constructed OCTET STRING holds a non-OCTET STRING chunk")
		}
		if !ch.cons {
			buf = append(buf, ch.content...)
			continue
		}
		if buf, err = appendChunks(buf, ch, depth+1, maxDepth); err != nil {
			return nil, err
		}
	}
	return buf, nil
}
