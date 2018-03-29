package sysstore

import (
	"errors"
	"path/filepath"

	"sync"

	"github.com/wirekit/tlsfs"
	"github.com/wirekit/tlsfs/encoding"
	"github.com/wirekit/tlsfs/fs/sysfs"
)

var (
	_              tlsfs.CertStore = &SysStore{}
	accountEncoder encoding.AccountZapEncoder
	accountDecoder encoding.AccountZapDecoder
	domainEncoder  encoding.TLSDomainZapEncoder
	domainDecoder  encoding.TLSDomainZapDecoder
)

// SysStore implements the tslfs.CacheStore.
type SysStore struct {
	dir  string
	dl   sync.RWMutex
	dirs map[string]*sysfs.SystemZapFS
}

// New returns a new instance of a SysStore.
func New(dir string) *SysStore {
	return &SysStore{
		dir:  dir,
		dirs: map[string]*sysfs.SystemZapFS{},
	}
}

// RemoveUser removes all certificates and user data associated
// with email.
func (sys *SysStore) RemoveUser(email string) error {
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
func (sys *SysStore) RemoveDomain(email string, domain string) error {
	userFS, err := sys.loadFS(email)
	if err != nil {
		return err
	}

	userDomain := encoding.GetDomainSignature(email, domain)
	return userFS.Remove(userDomain)
}

// AddUser adds the giving user into the underline filesystem.
func (sys *SysStore) AddUser(acct tlsfs.Account) error {
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

// GetUser returns a tlsfs.DomainAccount that contains a user with associated
// certificates.
func (sys *SysStore) GetUser(email string) (tlsfs.DomainAccount, error) {
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
			return acct, errors.New("multiuser data in zapped dir")
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
func (sys *SysStore) AddDomain(email string, cert tlsfs.TLSDomainCertificate, replaceIfExists bool) error {
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

// GetCertificate returns the TLSDomainCertificate for the giving user through it's email
// and domain name if it exists, else an error is returned.
func (sys *SysStore) GetCertificate(email string, domain string) (tlsfs.TLSDomainCertificate, error) {
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

func (sys *SysStore) loadFS(email string) (*sysfs.SystemZapFS, error) {
	sys.dl.Lock()
	defer sys.dl.Unlock()

	user := encoding.GetUserSignature(email)
	if fs, ok := sys.dirs[user]; ok {
		return fs, nil
	}

	userDir := filepath.Join(sys.dir, user)
	userFS := sysfs.NewSystemZapFS(userDir)

	sys.dirs[user] = userFS
	return userFS, nil
}
