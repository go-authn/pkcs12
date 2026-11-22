package pkcs12

import (
	"crypto"
	"crypto/x509"
)

// decode is the structure of RFC 7292 section 4, top to bottom:
//
//	PFX ::= SEQUENCE { version INTEGER {v3(3)}, authSafe ContentInfo, macData MacData OPTIONAL }
//
// in that order of effects: parse the envelope, verify the MAC over the
// authSafe's content, and only then decrypt and read the bags.
func (s *state) decode(data []byte, forms []passwordForm) (*Bundle, error) {
	var err error
	top := newCursor(data, s.opts.MaxDepth, &err)
	pfx := top.seq("PFX")
	top.end("PFX")

	if v := pfx.integer("PFX version"); err == nil && v != 3 {
		return nil, unsupported("PFX version %d", v)
	}
	ci := pfx.seq("authSafe")
	ctype := ci.oid("authSafe content type")
	if err == nil && !oidIs(ctype, oidData) {
		if oidIs(ctype, oidSignedData) {
			return nil, unsupported("public-key integrity mode (signedData)")
		}
		return nil, unsupported("authSafe content type %s", oidString(ctype))
	}
	authSafe := ci.explicit(0, "authSafe content").octets(classUniversal, tagOctetString, "authSafe data")
	ci.end("authSafe")

	var mac macData
	hasMAC := pfx.more()
	if hasMAC {
		m := pfx.seq("MacData")
		di := m.seq("DigestInfo")
		mac.alg = di.algID("MAC algorithm")
		mac.digest = di.octets(classUniversal, tagOctetString, "MAC digest")
		di.end("DigestInfo")
		mac.salt = m.octets(classUniversal, tagOctetString, "MAC salt")
		mac.iter = 1 // DEFAULT 1
		if m.more() {
			mac.iter = m.integer("MAC iteration count")
		}
		m.end("MacData")
	}
	pfx.end("PFX")
	if err != nil {
		return nil, err
	}

	var pw passwordForm
	switch {
	case hasMAC:
		var merr error // not err: the cursors below share that one, and it would mask this check
		if pw, merr = s.verifyMAC(mac, authSafe, forms); merr != nil {
			return nil, merr
		}
		s.authenticated = true
	case s.opts.AllowNoMAC:
		pw = forms[0]
	default:
		return nil, ErrNoMAC
	}

	safe := newCursor(authSafe, s.opts.MaxDepth, &err).seq("AuthenticatedSafe")
	n := 0
	for safe.more() {
		if n++; n > s.opts.MaxAuthSafes {
			return nil, limit("more than %d ContentInfos in the AuthenticatedSafe", s.opts.MaxAuthSafes)
		}
		s.contentInfo(safe, pw)
	}
	if err != nil {
		return nil, err
	}
	return s.bundle()
}

// contentInfo reads one ContentInfo of the AuthenticatedSafe: plain data, or
// EncryptedData (RFC 5652 section 8) holding a SafeContents.
func (s *state) contentInfo(safe *cursor, pw passwordForm) {
	ci := safe.seq("ContentInfo")
	ctype := ci.oid("ContentInfo type")
	body := ci.explicit(0, "ContentInfo content")
	ci.end("ContentInfo")

	var contents []byte
	switch {
	case *safe.err != nil:
		return
	case oidIs(ctype, oidData):
		contents = body.octets(classUniversal, tagOctetString, "SafeContents data")
	case oidIs(ctype, oidEncryptedData):
		ed := body.seq("EncryptedData")
		if v := ed.integer("EncryptedData version"); *safe.err == nil && v != 0 {
			safe.fail(unsupported("EncryptedData version %d", v))
			return
		}
		eci := ed.seq("EncryptedContentInfo")
		ed.end("EncryptedData")
		inner := eci.oid("EncryptedContentInfo type")
		alg := eci.algID("content encryption")
		ct := eci.octets(classContext, 0, "encrypted content")
		eci.end("EncryptedContentInfo")
		if *safe.err == nil && !oidIs(inner, oidData) {
			safe.fail(unsupported("encrypted content type %s", oidString(inner)))
			return
		}
		s.decrypted = true
		contents = s.decrypt(alg, ct, pw, safe)
	default:
		safe.fail(unsupported("ContentInfo type %s", oidString(ctype)))
	}
	body.end("ContentInfo content")
	bags := newCursor(contents, s.opts.MaxDepth, safe.err).seq("SafeContents")
	for bags.more() {
		s.safeBag(bags, pw)
	}
}

// safeBag reads one SafeBag (section 4.2). Key and certificate bags are
// kept; CRL, secret and nested SafeContents bags, and every attribute, are
// skipped unread. Which certificate belongs to the key is decided by the
// keys themselves, not by the localKeyId attribute.
func (s *state) safeBag(bags *cursor, pw passwordForm) {
	if s.bags++; s.bags > s.opts.MaxBags {
		bags.fail(limit("more than %d SafeBags", s.opts.MaxBags))
		return
	}
	bag := bags.seq("SafeBag")
	id := bag.oid("bag type")
	val := bag.explicit(0, "bag value")
	if bag.more() {
		bag.take(classUniversal, tagSet, true, "bag attributes")
	}
	bag.end("SafeBag")

	// The error slot is shared and sticky: a bag that failed above fills it,
	// every cursor call below is then a no-op, and no case can add to s.
	switch {
	case oidIs(id, oidCertBag):
		cb := val.seq("CertBag")
		cid := cb.oid("certificate type")
		der := cb.explicit(0, "certificate value").octets(classUniversal, tagOctetString, "certificate")
		cb.end("CertBag")
		if *bags.err != nil || !oidIs(cid, oidX509Certificate) {
			return // an SDSI certificate is not an X.509 one: skipped
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			bags.fail(malformed("certificate: %v", err))
			return
		}
		s.certs = append(s.certs, cert)
	case oidIs(id, oidKeyBag):
		pki := val.take(classUniversal, tagSequence, true, "PrivateKeyInfo")
		if *bags.err == nil {
			s.setKey(pki.raw, bags)
		}
	case oidIs(id, oidShroudedKeyBag):
		epki := val.seq("EncryptedPrivateKeyInfo")
		alg := epki.algID("key encryption")
		ct := epki.octets(classUniversal, tagOctetString, "encrypted key")
		epki.end("EncryptedPrivateKeyInfo")
		if *bags.err != nil {
			return
		}
		s.decrypted = true
		if der := s.decrypt(alg, ct, pw, bags); *bags.err == nil {
			s.setKey(der, bags)
		}
	}
}

func (s *state) setKey(der []byte, c *cursor) {
	if s.key != nil {
		c.fail(ErrMultipleKeys)
		return
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		c.fail(malformed("private key: %v", err))
		return
	}
	s.key = key
}

// bundle picks the certificate that belongs to the key, and returns the rest
// as the chain.
func (s *state) bundle() (*Bundle, error) {
	if s.key == nil {
		return nil, ErrNoPrivateKey
	}
	for i, cert := range s.certs {
		match, err := keyMatches(s.key, cert.PublicKey)
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}
		var ca []*x509.Certificate
		ca = append(ca, s.certs[:i]...)
		ca = append(ca, s.certs[i+1:]...)
		return &Bundle{PrivateKey: s.key, Certificate: cert, CACerts: ca}, nil
	}
	return nil, ErrNoCertificate
}

// keyMatches reports whether pub is the public half of priv.
func keyMatches(priv crypto.PrivateKey, pub crypto.PublicKey) (bool, error) {
	p, ok := priv.(interface{ Public() crypto.PublicKey })
	if !ok {
		return false, unsupported("private key type %T", priv)
	}
	q, ok := p.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false, unsupported("private key type %T", priv)
	}
	return q.Equal(pub), nil
}
