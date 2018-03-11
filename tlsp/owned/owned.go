package owned

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"strings"

	"crypto/x509"

	"crypto/md5"

	"crypto/elliptic"

	"github.com/wirekit/tlsfs"
	"github.com/wirekit/tlsfs/certificates"
	"github.com/wirekit/tlsfs/fs/sysfs"
	"github.com/wirekit/tlsfs/tlsp"
)

var (
	// do this to ensure CustomFS implements tlsfs.TLSFS interface.
	_ tlsfs.TLSFS = &CustomFS{}
)

//*************************************************************************
// CustomFS implementation of tlsfs.TLSFS
//*************************************************************************

// Config defines a configuration used for CustomFS.
type Config struct {
	// CertificatesFileSystem is the filesystem to use for storing certificate zap files
	// for given domain and users. It must be different from the file system for storing
	// user data.
	CertificatesFileSystem tlsfs.ZapFS

	// UsersFileSystem is the filesystem to use for storing user records zap files
	// for registered users. It must be different from the file system for storing
	// user data.
	UsersFileSystem tlsfs.ZapFS

	// RootFileSystem is the filesystem to use for both storing and retrieving saved
	// ca certificates and configuration files for the CustomFS CA. This filesystem
	// path must exists as a means to persist it's internal state and data files.
	RootFilesystem tlsfs.ZapFS

	// SigningLifeTime sets the expected lifetime to be issued to all signed
	// certificate requests received.
	SigningLifeTime time.Duration

	// Profile specifies the profile to be used to create the root CA certificate
	// which will be used to sign all certificate requests and will be used.
	Profile certificates.CertificateAuthorityProfile

	// rootCA contains the loaded or generated CA certificate which is used for
	// all signing process for the generation of certificates.
	rootCA *certificates.CertificateAuthority
}

// init initializes the internal configuration of the
// config struct, setting the important default fields
// with default values.
func (c *Config) init() error {
	// If not root filesystem is not provided, we will
	// utilize a os based filesystem storage.
	if c.RootFilesystem == nil {
		c.RootFilesystem = sysfs.NewSystemZapFS("./custom/roots")
	}

	// If not certificate filesystem is not provided, we will
	// utilize a os based filesystem storage.
	if c.CertificatesFileSystem == nil {
		c.CertificatesFileSystem = sysfs.NewSystemZapFS("./custom/certs")
	}

	// If not user filesystem is not provided, we will
	// utilize a os based filesystem storage.
	if c.UsersFileSystem == nil {
		c.UsersFileSystem = sysfs.NewSystemZapFS("./custom/users")
	}

	// If we have not be assigned a default lifetime for certificate
	// request signing, then allocate 1 year.
	if c.SigningLifeTime <= 0 {
		c.SigningLifeTime = tlsfs.ThreeMonths
	}

	if c.Profile.ECCurve == nil {
		c.Profile.ECCurve = elliptic.P384()
	}

	if c.Profile.RSAKeyStrength < 2048 {
		c.Profile.RSAKeyStrength = 4096
	}

	if c.Profile.CommonName == "" {
		c.Profile.CommonName = "*"
	}

	// if a configuration file exists, then read it and ensure CA has not
	// expired.
	if configZap, err := c.RootFilesystem.Read("ca-config"); err == nil {
		certZap, err := configZap.Find("root-ca")
		if err != nil {
			return err
		}

		decodedCA, err := certificates.DecodeCertificate(certZap.Data)
		if err != nil {
			return err
		}

		// if loaded certificate is still valid, then attempt to load certificate
		// key into configuration.
		today := time.Now()
		if today.After(decodedCA.NotAfter) {
			keyZap, err := configZap.Find("root-key")
			if err != nil {
				return err
			}

			_, decodedKey, err := certificates.DecodePrivateKey(keyZap.Data)
			if err != nil {
				return err
			}

			if c.rootCA == nil {
				c.rootCA = new(certificates.CertificateAuthority)
			}

			c.rootCA.Certificate = decodedCA
			c.rootCA.PrivateKey = decodedKey
			return nil
		}
	}

	// generate CA certificate for configuration, as it provides the issuer
	// certificate to be used for signing others.
	rootCA, err := certificates.CreateCertificateAuthority(c.Profile)
	if err != nil {
		return err
	}

	configWriter, err := c.RootFilesystem.Write("ca-config")
	if err != nil {
		return err
	}

	// Save certificate and private-key as zap file.
	encodedCA, err := rootCA.CertificateRaw()
	if err != nil {
		return err
	}

	configWriter.Add("root-ca", encodedCA)

	encodedKey, err := rootCA.PrivateKeyRaw()
	if err != nil {
		return err
	}

	configWriter.Add("root-key", encodedKey)

	if err = configWriter.Flush(); err != nil {
		return err
	}

	c.rootCA = &rootCA

	return nil
}

// CustomFS implements the tlsfs.TlsFS interface, providing
// a tls certificate acquisition, renewal and management
// implementation for working with Let's Encrypt CA based
// certificates.
type CustomFS struct {
	config Config

	ucl        sync.RWMutex
	usersCache map[string]*userAcct

	ccl       sync.RWMutex
	certCache map[string]tlsfs.ZapFile

	rcl          sync.RWMutex
	renewedCache map[string]chan struct{}
}

// NewCustomFS returns a new instance of the CustomFS.
func NewCustomFS(config Config) (*CustomFS, error) {
	if err := config.init(); err != nil {
		return nil, err
	}

	var fs CustomFS
	fs.config = config
	fs.certCache = make(map[string]tlsfs.ZapFile)
	fs.usersCache = make(map[string]*userAcct)
	fs.renewedCache = make(map[string]chan struct{})
	return &fs, nil
}

// GetUser returns an existing user account asocited with the provided
// email.
func (cm *CustomFS) GetUser(email string) (tlsfs.Account, error) {
	return cm.readUserFrom(email)
}

// Revoke attempts to revoke the existing certificate associated with
// the user's email and domain. If certificate is pending renewal then
// it will wait until the end of the renewal before making an attempt
// to revoke certificate. This is a custom lightweight CA, that has
// no revoked db that stores certificates that have being revoked.
// Hence a revoke call simply removes the certificate from the
// filesystem and cache, which ensures no other can gain access to it,
// but those who had access before the call to revoke will still
// be able to use certificate till expiry.
func (cm *CustomFS) Revoke(email string, domain string) error {
	signature := getSignature(email, domain)

	// ensure we are not working on a renewal for this domain certificate.
	cm.rcl.Lock()
	renewedChan, renewedFound := cm.renewedCache[signature]
	cm.rcl.Unlock()

	// Await for the ending of certificate renewal.
	if renewedFound {
		<-renewedChan
	}

	// Remove domain from cache.
	cm.ccl.Lock()
	delete(cm.certCache, signature)
	cm.ccl.Unlock()

	// Remove domain certificate from filesystem.
	if err := cm.config.CertificatesFileSystem.Remove(signature); err != nil {
		if _, ok := err.(tlsfs.NotExists); !ok {
			return err
		}
	}

	return nil
}

// All returns all existing certificates within the CustomFS regardless of renewal status
// allowing all state preserved to caller.
func (cm *CustomFS) All() ([]tlsfs.DomainAccount, error) {
	zappers, err := cm.config.CertificatesFileSystem.ReadAll()
	if err != nil {
		return nil, err
	}

	accounts := make([]tlsfs.DomainAccount, 0)
	userToAccount := map[string]int{}

	for _, zapp := range zappers {
		zapped, err := cm.readDomain(zapp)
		if err != nil {
			// if this error is due to corruption then remove.
			if _, ok := err.(*tlsfs.ZapCorruptedError); ok {
				cm.config.CertificatesFileSystem.Remove(zapp.Name)
			}

			continue
		}

		if user, err := cm.readUserFrom(zapped.User); err == nil {
			if index, ok := userToAccount[user.Email]; ok {
				acct := accounts[index]
				acct.Domains = append(acct.Domains, zapped)
				continue
			}

			var dm tlsfs.DomainAccount
			dm.Acct = user
			dm.Domains = append(dm.Domains, zapped)
			userToAccount[user.Email] = len(accounts)
			accounts = append(accounts, dm)
		}
	}

	sort.Sort(tlsfs.DomainAccounts(accounts))

	return accounts, nil
}

// Create attempts to create a given TLSDomainCertificate for the giving account.
// If a certificate already exists for the giving accounts.Domain, then the old
// TLSDomainCertificate is returned if its has not pass the accepted expiration time
// yet of 30 days. If it has then a renewal is initiated for the certificate and if
// successfully will return the new TLSDomainCertificate after replacing the old one.
// If a renewal failed and the certificate is less than two weeks to expiry or within the
// 30-days expiration, then the certificate is returned with an appropriate status to
// indicate non-critical but important reason of failure.
func (cm *CustomFS) Create(acct tlsfs.NewDomain, tos tlsfs.TOSAction) (tlsfs.TLSDomainCertificate, tlsfs.Status, error) {
	// We need to ensure that the common name to be provided has a value else
	// provide it a "*" asterick to allow use with any domain.
	if acct.CommonName == "" {
		acct.CommonName = "*"
	}

	// Ensure all domain is in lowercase.
	acct.Domain = strings.ToLower(acct.Domain)

	// Ensure domain qualifies and is not containing a scheme
	// or invalid values.
	if !tlsp.HostQualifies(acct.Domain) {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, tlsfs.ErrInvalidDomain),
			tlsfs.ErrInvalidDomain
	}

	// We need to attempt to load the user related to the giving email if he exists,
	// if we do not have such a user, then create one.
	user, err := cm.readUserFrom(acct.Email)
	if err != nil {
		if _, ok := err.(tlsfs.NotExists); !ok {
			return tlsfs.TLSDomainCertificate{},
				tlsfs.WithStatus(tlsfs.OPFailed, tlsfs.ErrInvalidDomain),
				tlsfs.ErrInvalidDomain
		}

		user = new(userAcct)
		user.Email = acct.Email

		switch acct.KeyType {
		case tlsfs.RSA2048:
			if user.PrivateKey, _, err = certificates.CreateRSAKey(2048); err != nil {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}
		case tlsfs.RSA4096:
			if user.PrivateKey, _, err = certificates.CreateRSAKey(4096); err != nil {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}
		case tlsfs.RSA8192:
			if user.PrivateKey, _, err = certificates.CreateRSAKey(8192); err != nil {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}
		case tlsfs.ECKey256:
			if user.PrivateKey, _, err = certificates.CreateECKey(elliptic.P256()); err != nil {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}
		case tlsfs.ECKey384:
			if user.PrivateKey, _, err = certificates.CreateECKey(elliptic.P384()); err != nil {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}
		case tlsfs.ECKey512:
			if user.PrivateKey, _, err = certificates.CreateECKey(elliptic.P521()); err != nil {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}
		default:
			return tlsfs.TLSDomainCertificate{},
				tlsfs.WithStatus(tlsfs.OPFailed, certificates.ErrUnknownPrivateKeyType),
				certificates.ErrUnknownPrivateKeyType
		}

		// Attempt to save the user immediately.
		if err := cm.saveUser(acct.Email, user.PrivateKey); err != nil {
			return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		}
	}

	// If there exists a already signed certificate for this domain by this user, then
	// retrieve certificate, validate it is not yet expired by it's status and return
	// else renew certificate if about to expire or revoke if it has expired and move to
	// create new one.
	if existingDomain, err := cm.readDomainFrom(acct.Email, acct.Domain); err == nil {
		currentStatus := cm.getDomainStatus(existingDomain.Certificate)

		switch currentStatus.Flag() {
		case tlsfs.CARenewedRequired, tlsfs.CACriticalRenewedRequired:
			return cm.Renew(acct.Email, acct.Domain)
		case tlsfs.CACExpired:
			if err := cm.Revoke(acct.Email, acct.Domain); err != nil {
				return tlsfs.TLSDomainCertificate{},
					tlsfs.WithStatus(tlsfs.OPFailed, errors.New("expired certificate")), err
			}
		default:
			return existingDomain, currentStatus, nil
		}
	}

	// Create certificate request for this domain, add the common name
	// and dns names to the ceriticate request.
	var profile certificates.CertificateRequestProfile
	profile.Local = acct.Local
	profile.Postal = acct.Postal
	profile.Version = acct.Version
	profile.Address = acct.Address
	profile.Country = acct.Country
	profile.Province = acct.Province
	profile.CommonName = acct.CommonName
	profile.Organization = acct.CommonName
	profile.PrivateKey = user.GetPrivateKey()
	profile.Emails = []string{"mailto://" + acct.Email}
	profile.DNSNames = append(profile.DNSNames, acct.DNSNames...)

	// Sign and create official x509.CertificateRequest from profile.
	request, err := certificates.CreateCertificateRequest(profile)
	if err != nil {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, errors.New("failed to generate certificate request")), err
	}

	// Approve requests for client and server usage, so user can use it in either way.
	if err := cm.config.rootCA.ApproveServerClientCertificateSigningRequest(&request, cm.config.SigningLifeTime); err != nil {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, errors.New("failed to sign client certificate")), err
	}

	var doma tlsfs.TLSDomainCertificate
	doma.Bundle = acct
	doma.User = acct.Email
	doma.Domain = acct.Domain
	doma.Request = request.Request
	doma.Certificate = request.SecondaryCA.Certificate
	doma.IssuerCertificate = request.SecondaryCA.RootCA

	if err := cm.saveDomain(doma); err != nil {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, errors.New("failed to save client certificate")), err
	}

	return doma, tlsfs.WithStatus(tlsfs.Created, nil), nil
}

// Renew attempts to renew a existing TLSDomainCertificate for the giving domain.
// If a certificate does not exists exists then the operation is returned with an
// error.
// A TLSDomainCertificate is returned if its has not pass the accepted expiration time
// yet of 30 days. If it has then the renewal is initiated for the certificate and if
// successfully will return the new TLSDomainCertificate after replacing the old one.
// If a renewal failed and the certificate is less than two weeks to expiry or within the
// 30-days expiration, then the certificate is returned with an appropriate status to
// indicate non-critical but important reason of failure.
func (cm *CustomFS) Renew(email string, domain string) (tlsfs.TLSDomainCertificate, tlsfs.Status, error) {
	mysignature := getSignature(email, domain)

	// We first must validate that no previous renewal is
	// not already underway for giving domain. If there is:
	// then we just read from that when it's done instead.
	cm.rcl.Lock()
	if _, ok := cm.renewedCache[mysignature]; ok {
		cm.rcl.Unlock()

		// We simply call readDomainFrom which handles gracefully
		// waiting for the finishing of an existing renewal and
		// returns the renewed domain or error when done.
		domain, err := cm.readDomainFrom(email, domain)
		if err != nil {
			return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		}

		return domain, cm.getDomainStatus(domain.Certificate), nil
	}
	cm.rcl.Unlock()

	user, err := cm.readUserFrom(email)
	if err != nil {
		return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	existingDomain, err := cm.readDomainFrom(email, domain)
	if err != nil {
		return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	acct := existingDomain.Bundle.(tlsfs.NewDomain)

	// We need to allocate a renew channel for others to be aware of the fact
	// that the domain certificate is being renewed.
	renewal := make(chan struct{})

	// Ensure to added renewed channel into existing channel.
	cm.rcl.Lock()
	cm.renewedCache[mysignature] = renewal
	cm.rcl.Unlock()

	// We need to ensure the renewed channel is closed and removed from
	// the renewed channel map after all operations are done, regardless of
	// failure.
	defer func() {
		close(renewal)

		cm.rcl.Lock()
		delete(cm.renewedCache, mysignature)
		cm.rcl.Unlock()
	}()

	// Create certificate request for this domain, add the common name
	// and dns names to the ceriticate request.
	var profile certificates.CertificateRequestProfile
	profile.Local = acct.Local
	profile.Postal = acct.Postal
	profile.Version = acct.Version
	profile.Address = acct.Address
	profile.Country = acct.Country
	profile.Province = acct.Province
	profile.PrivateKey = user.PrivateKey
	profile.CommonName = acct.CommonName
	profile.Organization = acct.CommonName
	profile.Emails = []string{"mailto://" + acct.Email}
	profile.DNSNames = append(profile.DNSNames, acct.DNSNames...)

	// Sign and recreate official x509.CertificateRequest from profile.
	request, err := certificates.CreateCertificateRequest(profile)
	if err != nil {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, errors.New("failed to generate certificate request")), err
	}

	// Approve requests for client and server usage, so user can use it in either way.
	if err := cm.config.rootCA.ApproveServerClientCertificateSigningRequest(&request, cm.config.SigningLifeTime); err != nil {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, errors.New("failed to sign client certificate")), err
	}

	// Generate new TLSDomainCertificate and replace old certificat.
	var doma tlsfs.TLSDomainCertificate
	doma.Bundle = acct
	doma.User = acct.Email
	doma.Domain = acct.Domain
	doma.Request = request.Request
	doma.Certificate = request.SecondaryCA.Certificate
	doma.IssuerCertificate = request.SecondaryCA.RootCA

	if err := cm.saveDomain(doma); err != nil {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, errors.New("failed to save client certificate")), err
	}

	return existingDomain, tlsfs.WithStatus(tlsfs.Renewed, nil), nil
}

// Get attempts to retrieve a existing certificate from the underline store, if such certificate
// is requiring renewal then the renewal process is called for the certificate with appropriate
// response returned as stated for the CustomFS.Renew method.
// It returns a status appropriate for the certificate returned to indicate to the caller
// the state and needed action if any to be done.
func (cm *CustomFS) Get(email string, domain string) (tlsfs.TLSDomainCertificate, tlsfs.Status, error) {
	existingDomain, err := cm.readDomainFrom(email, domain)
	if err != nil {
		return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	currentStatus := cm.getDomainStatus(existingDomain.Certificate)

	switch currentStatus.Flag() {
	case tlsfs.CACExpired:
		if err := cm.Revoke(email, domain); err != nil {
			return tlsfs.TLSDomainCertificate{},
				tlsfs.WithStatus(tlsfs.OPFailed, errors.New("expired certificate")), err
		}
	case tlsfs.CARenewedRequired, tlsfs.CACriticalRenewedRequired:
		return cm.Renew(email, domain)
	}

	return existingDomain, currentStatus, nil
}

func (cm *CustomFS) getDomainStatus(cert *x509.Certificate) tlsfs.Status {
	today := time.Now()

	// if we have surpassed expiration time then return CACExpired.
	expires := cert.NotAfter
	if today.After(expires) {
		return tlsfs.WithStatus(tlsfs.CACExpired, tlsfs.ErrExpired)
	}

	left := expires.Sub(today)

	// if we are around 30 or 40 days then signal renewal required.
	if left <= tlsfs.Live30Days && left <= tlsfs.Live40Days {
		return tlsfs.WithStatus(tlsfs.CARenewedRequired, nil)
	}

	// If we are below 30 days and are just within a 3 weeks duration, then return
	// early renew.
	if left <= tlsfs.Live30Days && left > tlsfs.Live2Weeks {
		return tlsfs.WithStatus(tlsfs.CARenewalEarlyExpiration, nil)
	}

	// if we are below 30 days and have crossed the 2 weeks limit then
	// return critical renew.
	if left <= tlsfs.Live2Weeks {
		return tlsfs.WithStatus(tlsfs.CARenewalCriticalExpiration, nil)
	}

	return tlsfs.WithStatus(tlsfs.Live, nil)
}

func (cm *CustomFS) readDomainFrom(email string, domain string) (tlsfs.TLSDomainCertificate, error) {
	signature := getSignature(email, domain)

	// We first need to validate we are not in a renewal state where
	// the giving domain is being attempted for renewal.
	cm.rcl.Lock()
	renewedChan, ok := cm.renewedCache[signature]
	cm.rcl.Unlock()

	// the current domain is already being renewed or is facing a renewal attempt
	// hence we must await the end of the renewal before attempting to read.
	if ok {
		// Renewal is finished by this area, so we must first validate that the cache has
		// no domain record of giving TLSDomainCertificate, has the renewal will remove all traces of
		// certificate from the cache before closing the channel.
		<-renewedChan

		// Ensure we don't have anything in cache else its probably in an invalid state
		// and if invalid, then remove from cache first.
		cm.ccl.Lock()
		if _, ok := cm.certCache[signature]; ok {
			delete(cm.certCache, signature)
		}
		cm.ccl.Unlock()

		// After removal, attempt to read form file system, if successfully, load response into
		// cache and return to user, if we failed, then we know renewal failed and a fs error must
		// have occured.
		zapp, err := cm.config.CertificatesFileSystem.Read(signature)
		if err != nil {
			return tlsfs.TLSDomainCertificate{}, err
		}

		// A zap file should never face an issue where we fail to pass it,
		// we automatically see it has corrupted so, delete and return an
		// error.
		rec, err := cm.readDomain(zapp)
		if err != nil {
			// A zap file must never be corrupted and be unreadable, so if
			// something happens during it's conversion, then delete it.
			if _, ok := err.(*tlsfs.ZapCorruptedError); ok {
				cm.config.CertificatesFileSystem.Remove(signature)
			}
			return tlsfs.TLSDomainCertificate{}, err
		}

		// Save domain zapp file into cache for quick access.
		cm.ccl.Lock()
		cm.certCache[signature] = zapp
		cm.ccl.Unlock()

		return rec, nil
	}

	cm.ccl.Lock()
	if zapp, ok := cm.certCache[signature]; ok {
		cm.ccl.Unlock()

		// A zap file should never face an issue where we fail to parse it,
		// we automatically see it has corrupted so, delete and return an
		// error.
		rec, err := cm.readDomain(zapp)
		if err != nil {
			// A zap file must never be corrupted and be unreadable, so if
			// something happens during it's conversion, then delete it.
			if _, ok := err.(*tlsfs.ZapCorruptedError); ok {
				cm.config.CertificatesFileSystem.Remove(signature)
			}
			return tlsfs.TLSDomainCertificate{}, err
		}

		return rec, nil
	}
	cm.ccl.Unlock()

	// Read the zap file for the domain from the filesystem, if it exists.
	zapp, err := cm.config.CertificatesFileSystem.Read(signature)
	if err != nil {
		return tlsfs.TLSDomainCertificate{}, err
	}

	// A zap file should never face an issue where we fail to parse it,
	// we automatically see it has corrupted so, delete and return an
	// error.
	rec, err := cm.readDomain(zapp)
	if err != nil {
		// A zap file must never be corrupted and be unreadable, so if
		// something happens during it's conversion, then delete it.
		if _, ok := err.(*tlsfs.ZapCorruptedError); ok {
			cm.config.CertificatesFileSystem.Remove(signature)
		}
		return tlsfs.TLSDomainCertificate{}, err
	}

	if rec.Domain != domain {
		cm.config.CertificatesFileSystem.Remove(signature)
		return tlsfs.TLSDomainCertificate{}, tlsfs.ErrZapFileDomainMismatched
	}

	// Save domain zapp file into cache for quick access.
	cm.ccl.Lock()
	cm.certCache[signature] = zapp
	cm.ccl.Unlock()

	return rec, nil
}

func (cm *CustomFS) saveDomain(cert tlsfs.TLSDomainCertificate) error {
	es := getSignature(cert.User, cert.Domain)
	writer, err := cm.config.CertificatesFileSystem.Write(es)
	if err != nil {
		return err
	}

	if err := writer.Add(tlsfs.DomainUserDataZapName, []byte(cert.User)); err != nil {
		return err
	}

	if err := writer.Add(tlsfs.DomainNameDataZapName, []byte(cert.Domain)); err != nil {
		return err
	}

	issuerData, err := certificates.EncodeCertificate(cert.IssuerCertificate)
	if err != nil {
		return err
	}

	if err := writer.Add(tlsfs.IssuerDomainCertificateZapName, issuerData); err != nil {
		return err
	}

	certData, err := certificates.EncodeCertificate(cert.Certificate)
	if err != nil {
		return err
	}

	if err := writer.Add(tlsfs.DomainCertificateZapName, certData); err != nil {
		return err
	}

	reqData, err := certificates.EncodeCertificateRequest(cert.Request)
	if err != nil {
		return err
	}

	if err := writer.Add(tlsfs.DomainCertificateRequestZapName, reqData); err != nil {
		return err
	}

	bundleJSON, err := json.Marshal(cert.Bundle)
	if err != nil {
		return err
	}

	if err := writer.Add(tlsfs.DomainBundleDataZapName, bundleJSON); err != nil {
		return err
	}

	// Flush all data into filesystem.
	if err := writer.Flush(); err != nil {
		return err
	}

	// Delete cached domain.
	cm.ccl.Lock()
	delete(cm.certCache, es)
	cm.ccl.Unlock()
	return nil
}

func (cm *CustomFS) readDomain(zapFile tlsfs.ZapFile) (tlsfs.TLSDomainCertificate, error) {
	var tacc tlsfs.TLSDomainCertificate

	domain, err := zapFile.Find(tlsfs.DomainNameDataZapName)
	if err != nil {
		return tacc, tlsfs.ErrZapFileHasNoAcctData
	}

	tacc.Domain = string(domain.Data)

	user, err := zapFile.Find(tlsfs.DomainUserDataZapName)
	if err != nil {
		return tacc, tlsfs.ErrZapFileHasNoAcctData
	}

	tacc.User = string(user.Data)

	domainCert, err := zapFile.Find(tlsfs.DomainCertificateZapName)
	if err != nil {
		return tacc, tlsfs.ErrZapFileHasNoCertificate
	}

	cert, err := certificates.DecodeCertificate(domainCert.Data)
	if err != nil {
		return tacc, err
	}

	tacc.Certificate = cert

	domainIssuerCert, err := zapFile.Find(tlsfs.IssuerDomainCertificateZapName)
	if err != nil {
		return tacc, tlsfs.ErrZapFileHasNoIssuerCertificate
	}

	issuercert, err := certificates.DecodeCertificate(domainIssuerCert.Data)
	if err != nil {
		return tacc, err
	}

	tacc.IssuerCertificate = issuercert

	domainCertReq, err := zapFile.Find(tlsfs.DomainCertificateRequestZapName)
	if err != nil {
		return tacc, tlsfs.ErrZapFileHasNoCertificateRequest
	}

	certReq, err := certificates.DecodeCertificateRequest(domainCertReq.Data)
	if err != nil {
		return tacc, err
	}

	tacc.Request = certReq

	bundleCert, err := zapFile.Find(tlsfs.DomainBundleDataZapName)
	if err != nil {
		return tacc, tlsfs.ErrErrCertificateHasNoBundle
	}

	var bundle tlsfs.NewDomain
	if err := json.Unmarshal(bundleCert.Data, &bundle); err != nil {
		return tacc, err
	}

	tacc.Bundle = bundle

	return tacc, nil
}

func (cm *CustomFS) readUserFrom(email string) (*userAcct, error) {
	es := getSignature(email, "")

	cm.rcl.RLock()
	if cached, ok := cm.usersCache[es]; ok {
		cm.rcl.RUnlock()
		return cached, nil
	}
	cm.rcl.RUnlock()

	zapp, err := cm.config.UsersFileSystem.Read(es)
	if err != nil {
		return nil, err
	}

	// Parse the zap file format into *userAcct type.
	user, err := cm.readUser(zapp)
	if err != nil {
		// A zap file must never be corrupted and be unreadable, so if
		// something happens during it's conversion, then delete it.
		if _, ok := err.(*tlsfs.ZapCorruptedError); ok {
			cm.config.UsersFileSystem.Remove(es)
		}

		return nil, err
	}

	cm.rcl.Lock()
	cm.usersCache[es] = user
	cm.rcl.Unlock()

	return user, nil
}

func (cm *CustomFS) readUser(zapFile tlsfs.ZapFile) (*userAcct, error) {
	var user userAcct

	userData, err := zapFile.Find(tlsfs.DomainUserDataZapName)
	if err != nil {
		return nil, tlsfs.ErrZapFileHasNoAcctData
	}

	user.Email = string(userData.Data)

	domainPKey, err := zapFile.Find(tlsfs.DomainPrivateKeyZapName)
	if err != nil {
		return nil, tlsfs.ErrZapFileHasNoPKeyData
	}

	_, pkey, err := certificates.DecodePrivateKey(domainPKey.Data)
	if err != nil {
		return nil, err
	}

	user.PrivateKey = pkey

	return &user, nil
}

func (cm *CustomFS) saveUser(email string, privateKey crypto.PrivateKey) error {
	es := getSignature(email, "")
	writer, err := cm.config.UsersFileSystem.Write(es)
	if err != nil {
		return err
	}

	if err := writer.Add(tlsfs.DomainUserDataZapName, []byte(email)); err != nil {
		return err
	}

	pkeyData, err := certificates.EncodePrivateKey(privateKey)
	if err != nil {
		return err
	}

	if err := writer.Add(tlsfs.DomainPrivateKeyZapName, pkeyData); err != nil {
		return err
	}

	return writer.Flush()
}

//*************************************************************************
// User struct
//*************************************************************************

// userAcct implements the acme.userAcct acct for registering users for
// a desired domain.
type userAcct struct {
	Email      string
	PrivateKey crypto.PrivateKey
}

// GetPrivateKey returns the private key associated with user.
func (u userAcct) GetPrivateKey() crypto.PrivateKey {
	return u.PrivateKey
}

// GetEmail returns the email for the user.
func (u userAcct) GetEmail() string {
	return u.Email
}

//***************************************************************************
// Utility Functions
//***************************************************************************

func joinError(domain string, errs ...error) error {
	var ex []string
	for _, err := range errs {
		ex = append(ex, "failed to obtain certificate as "+err.Error()+" for '"+domain+"'")
	}
	return errors.New(strings.Join(ex, ";"))
}

func getSignature(email, domain string) string {
	mod := md5.New()
	mod.Write([]byte(email))
	mod.Write([]byte(domain))
	return base64.StdEncoding.EncodeToString(mod.Sum(nil))
}
