package acme

import (
	"github.com/wirekit/tlsfs"
	"github.com/xenolf/lego/acme"
)

// tlsSNISolver is a type that can solve TLS-SNI challenges using
// an existing listener and our custom, in-memory certificate cache.
type tlsSNISolver struct {
	certCache tlsfs.CertCache
}

// Present adds the challenge certificate to the cache.
func (s tlsSNISolver) Present(domain, token, keyAuth string) error {
	cert, acmeDomain, err := acme.TLSSNI01ChallengeCert(keyAuth)
	if err != nil {
		return err
	}

	s.certCache.Save(acmeDomain, cert)
	return nil
}

// CleanUp removes the challenge certificate from the cache.
func (s tlsSNISolver) CleanUp(domain, token, keyAuth string) error {
	_, acmeDomain, err := acme.TLSSNI01ChallengeCert(keyAuth)
	if err != nil {
		return err
	}

	return s.certCache.Delete(acmeDomain)
}
