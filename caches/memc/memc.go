// Package memc provides an implements for the tlsfs.CertCache interface.
package memc

import (
	"crypto/tls"
	"errors"
	"sync"
)

// MemCache implements the tlsfs.CertCache interface.
// The cache is safe for concurrent use in multiple
// goroutine.
type MemCache struct {
	cl    sync.Mutex
	certs map[string]tls.Certificate
}

// New returns a new MemCache instance.
// You can instantiate the Memcache without this function.
func New() *MemCache {
	return new(MemCache)
}

// Delete attempts to remove giving cert keyed by domain string.
func (mmc *MemCache) Delete(domain string) error {
	mmc.cl.Lock()
	defer mmc.cl.Unlock()
	if mmc.certs == nil {
		return notExists{err: errors.New("not found")}
	}

	delete(mmc.certs, domain)
	return nil
}

// Get returns the certificate if found for giving domain.
func (mmc *MemCache) Get(domain string) (tls.Certificate, error) {
	mmc.cl.Lock()
	defer mmc.cl.Unlock()
	if mmc.certs == nil {
		mmc.certs = map[string]tls.Certificate{}
		return tls.Certificate{}, notExists{err: errors.New("not found")}
	}

	if cert, ok := mmc.certs[domain]; ok {
		return cert, nil
	}

	return tls.Certificate{}, notExists{err: errors.New("not found")}
}

// Save attempts to save certificate into cache with domain string.
func (mmc *MemCache) Save(domain string, cert tls.Certificate) error {
	mmc.cl.Lock()
	defer mmc.cl.Unlock()
	if mmc.certs == nil {
		mmc.certs = map[string]tls.Certificate{}
	}
	mmc.certs[domain] = cert
	return nil
}

type notExists struct {
	err error
}

func (n notExists) Error() string {
	return n.err.Error()
}

func (n notExists) NotExists() {
}
