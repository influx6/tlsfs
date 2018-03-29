package memstore

import (
	"errors"

	"sync"

	"github.com/wirekit/tlsfs"
	"github.com/wirekit/tlsfs/encoding"
	"github.com/wirekit/tlsfs/fs/memfs"
)

var (
	_              tlsfs.CertStore = &MemStore{}
	accountEncoder encoding.AccountZapEncoder
	accountDecoder encoding.AccountZapDecoder
	domainEncoder  encoding.TLSDomainZapEncoder
	domainDecoder  encoding.TLSDomainZapDecoder
)

// MemStore implements the tslfs.CacheStore.
type MemStore struct {
	dl   sync.RWMutex
	dirs map[string]*memfs.MemFS
}

// New returns a new instance of a MemStore.
func New() *MemStore {
	return &MemStore{
		dirs: map[string]*memfs.MemFS{},
	}
}

// RemoveUser removes all certificates and user data associated
// with email.
func (sys *MemStore) RemoveUser(email string) error {
	userFS, err := sys.loadFS(email)
	if err != nil {
		return err
	}

	sys.dl.Lock()
	delete(sys.dirs, encoding.GetUserSignature(email))
	sys.dl.Unlock()
	return userFS.RemoveAll()
}

// RemoveDomain removes associated domain from domains stored
// for giving user.
func (sys *MemStore) RemoveDomain(email string, domain string) error {
	userFS, err := sys.loadFS(email)
	if err != nil {
		return err
	}

	userDomain := encoding.GetDomainSignature(email, domain)
	return userFS.Remove(userDomain)
}

// GetUser returns a tlsfs.DomainAccount that contains a user with associated
// certificates.
func (sys *MemStore) GetUser(email string) (tlsfs.DomainAccount, error) {
	var acct tlsfs.DomainAccount

	userFS, err := sys.loadFS(email)
	if err != nil {
		return acct, err
	}

	userSignature := encoding.GetUserSignature(email)

	zapps, err := userFS.ReadAll()
	if err != nil {
		return acct, err
	}

	var userLoaded bool

	for _, zapped := range zapps {
		if zapped.Name != userSignature {
			cert, err := domainDecoder.Decode(zapped)
			if err != nil {
				return acct, err
			}

			acct.Domains = append(acct.Domains, cert)
			continue
		}

		if userLoaded {
			return acct, errors.New("multi-user data in zapped dir")
		}

		userAcct, err := accountDecoder.Decode(zapped)
		if err != nil {
			return acct, err
		}

		acct.Acct = userAcct
		userLoaded = true
	}

	return acct, nil
}

// AddDomain attempts to add certificate into associated domain if it does not exists but
// will override if replaceIfExists is true.
func (sys *MemStore) AddDomain(email string, cert tlsfs.TLSDomainCertificate, replaceIfExists bool) error {
	if cert.User != email {
		return errors.New("certificate user does not match email")
	}

	userFS, err := sys.loadFS(email)
	if err != nil {
		return err
	}

	domainSignature := encoding.GetDomainSignature(email, cert.Domain)
	if _, err := userFS.Read(domainSignature); err == nil && !replaceIfExists {
		return errors.New("acct already with certificate")
	}

	zapped, err := domainEncoder.Encode(cert)
	if err != nil {
		return err
	}

	return userFS.WriteFile(zapped)
}

// AddUser adds the giving user into the underline filesystem.
func (sys *MemStore) AddUser(acct tlsfs.Account) error {
	userFS, err := sys.loadFS(acct.GetEmail())
	if err != nil {
		return err
	}

	zapped, err := accountEncoder.Encode(acct)
	if err != nil {
		return err
	}

	return userFS.WriteFile(zapped)
}

// GetCertificate returns the TLSDomainCertificate for the giving user through it's email
// and domain name if it exists, else an error is returned.
func (sys *MemStore) GetCertificate(email string, domain string) (tlsfs.TLSDomainCertificate, error) {
	var cert tlsfs.TLSDomainCertificate

	userFS, err := sys.loadFS(email)
	if err != nil {
		return cert, err
	}

	domainSignature := encoding.GetDomainSignature(email, cert.Domain)
	zapped, err := userFS.Read(domainSignature)
	if err != nil {
		return cert, err
	}

	cert, err = domainDecoder.Decode(zapped)
	if err != nil {
		return cert, err
	}

	return cert, nil
}

func (sys *MemStore) loadFS(email string) (*memfs.MemFS, error) {
	sys.dl.Lock()
	defer sys.dl.Unlock()

	user := encoding.GetUserSignature(email)
	if fs, ok := sys.dirs[user]; ok {
		return fs, nil
	}

	userFS := memfs.NewMemFS()
	sys.dirs[user] = userFS
	return userFS, nil
}
