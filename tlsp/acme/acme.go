package acme

import (
	"crypto"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"strings"

	"crypto/elliptic"
	"crypto/x509"

	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/wirekit/tlsfs"
	"github.com/wirekit/tlsfs/caches/memc"
	"github.com/wirekit/tlsfs/certificates"
	"github.com/wirekit/tlsfs/encoding"
	"github.com/wirekit/tlsfs/fs/sysfs"
	"github.com/wirekit/tlsfs/tlsp"
	"github.com/xenolf/lego/acme"
)

const (
	acmeChallengeSubPath = "/.well-known/acme-challenge/"
	letsEncryptTermsURL  = "https://acme-v01.api.letsencrypt.org/terms"
	letsEncryptDirURL    = "https://acme-v01.api.letsencrypt.org/directory"
)

var (
	// do this to ensure AcmeFS implements tlsfs.TLSFS interface.
	_ tlsfs.TLSFS = &AcmeFS{}

	accountEncoder encoding.AccountZapEncoder
	accountDecoder encoding.AccountZapDecoder
	domainEncoder  encoding.TLSDomainZapEncoder
	domainDecoder  encoding.TLSDomainZapDecoder
)

//*************************************************************************
// AcmeFS implementation of tlsfs.TLSFS
//*************************************************************************

// constants of supported challenge types.
const (
	TLSSNI = string(acme.TLSSNI01)
	HTTP01 = string(acme.HTTP01)
)

// Config defines a configuration used for AcmeFS.
type Config struct {
	// CAURL to set the CA url to be used to register and generate
	// certificates from a valid acme Certificate Authority.
	// Defaults to Lets Encrypt's CA.
	CAURL string

	// ListenerAddr sets the preferred address, only the hostname/ip
	// no port, which will be used for working out the HTTP/TLS-SNI
	// challenges.
	ListenerAddr string

	// MustStable sets the requirement that all acme clients must
	// run stable checks against retrieved certificates to ensure
	// validity and correctness.
	MustStaple bool

	// HTTPChallengePort sets the alternate port, only port and not
	// hostname/ip and port. Which should be used for HTTP challenge
	// instead of port 80. Defaults to 80 if non is provided.
	HTTPChallengePort int

	// TLSSNIChallengePort sets the alternate port, only port and not
	// hostname/ip and port. Which should be used for TLS-SNI challenge
	// instead of port 443. Defaults to 443 if non is provided.
	TLSSNIChallengePort int

	// EnableHTTP01Challenge enables the usage of the HTTP01 challenge for
	// handling acme challenge solving process. Set this to add HTTP01 has
	// a possible means to solve the acme challenge.
	// Enabling any other challenge won't disable this challenge has it
	// allows us test all challenges if another failed before returning
	// failure if all failed.
	EnableHTTP01Challenge bool

	// EnableTLSSNI01Challenge enables the usage of the TLS-SNI01 challenge for
	// handling acme challenge solving process. Set this to add TLS-SNI01 has
	// a possible means to solve the acme challenge.
	// Enabling any other challenge won't disable this challenge has it
	// allows us test all challenges if another failed before returning
	// failure if all failed.
	EnableTLSSNI01Challenge bool

	// EnableDNS01Challenge enables the usage of the DNS-01 challenge for
	// handling acme challenge solving process. Set this to add DNS-01 has
	// a possible means to solve the acme challenge. But the DNS-01 will
	// require the setting of the DNSChallengeProvider field to power up
	// the usage of the given challenge.
	// Enabling any other challenge won't disable this challenge has it
	// allows us test all challenges if another failed before returning
	// failure if all failed.
	EnableDNS01Challenge bool

	// DNSProvider accompanies the EnableDNS01Challenge field which must
	// exists to allow the usage of dns has a means of resolving the acme
	// certificate challenge. If this is not set then the DNS challenge will
	// be disabled.
	DNSProvider acme.ChallengeProvider

	//// HTTPProvider accompanies the EnabledHTTP01Challenge but is optional,
	//// if not set the acme client will use it's default provider else use
	//// this if provided for the http-01 challenge.
	//HTTPProvider acme.ChallengeProvider
	//
	//// TLSSNIProvider accompanies the EnabledTLSSNI01Challenge but is optional,
	//// if not set the acme client will use it's default provider else use
	//// this if provided for the tls-sni-01 challenge.
	//TLSSNIProvider acme.ChallengeProvider

	// TLSCertCache holds certificates cache retrieved through tls-sni-01
	// challenges, it caches them till removal.
	TLSCertCache tlsfs.CertCache

	// excludedChallenges is an internal set used to initialize the given
	// challenges to be excluded if not enabled. We require that atleast one
	// challenge must be enabled, else HTTP-01 challenge is set enabled by
	// default.
	excludedChallenges []acme.Challenge

	// CertificatesFileSystem is the filesystem to use for storing certificate zap files
	// for given domain and users. It must be different from the file system for storing
	// user data.
	CertificatesFileSystem tlsfs.ZapFS

	// UsersFileSystem is the filesystem to use for storing user records zap files
	// for registered users. It must be different from the file system for storing
	// user data.
	UsersFileSystem tlsfs.ZapFS
}

// init initializes the internal configuration of the
// config struct, setting the important default fields
// with default values.
func (c *Config) init() {
	if c.CAURL == "" {
		c.CAURL = letsEncryptDirURL
	}

	// Validate and reset state as needed for when dns is enabled
	// as a challenge option the DNSChallengeProvider.
	if c.EnableDNS01Challenge {
		if c.DNSProvider == nil {
			c.EnableDNS01Challenge = false
			c.excludedChallenges = []acme.Challenge{acme.DNS01}
		}
	} else {
		c.excludedChallenges = append(c.excludedChallenges, acme.DNS01)
	}

	// if tls-sni-01 challenge is not enabled, then add into exclusion
	// list.
	if !c.EnableTLSSNI01Challenge {
		c.excludedChallenges = append(c.excludedChallenges, acme.TLSSNI01)
	}

	// If http-01 challenge is not enabled, then validate that atleast one
	// challenge is enabled, then add http-01 into excluded list, else we must enable
	// http-01 has default challenge.
	if !c.EnableHTTP01Challenge {
		if !c.EnableTLSSNI01Challenge && !c.EnableDNS01Challenge {
			c.EnableHTTP01Challenge = true
			c.excludedChallenges = []acme.Challenge{acme.TLSSNI01, acme.DNS01}
		} else {
			c.excludedChallenges = append(c.excludedChallenges, acme.HTTP01)
		}
	}

	// if we have no ip/hostname set for the http/tls server then
	// set to default systems ip.
	if c.ListenerAddr == "" {
		c.ListenerAddr = "0.0.0.0"
	}

	if c.HTTPChallengePort == 0 {
		c.HTTPChallengePort = 80
	}

	if c.TLSSNIChallengePort == 0 {
		c.HTTPChallengePort = 443
	}

	// If not certificate filesystem is not provided, we will
	// utilize a os based filesystem storage.
	if c.CertificatesFileSystem == nil {
		c.CertificatesFileSystem = sysfs.NewSystemZapFS("./acme/certs")
	}

	// If not user filesystem is not provided, we will
	// utilize a os based filesystem storage.
	if c.UsersFileSystem == nil {
		c.UsersFileSystem = sysfs.NewSystemZapFS("./acme/users")
	}

	// if no tlscache is set then we need to provide one
	// ourselves.
	if c.TLSCertCache == nil {
		c.TLSCertCache = memc.New()
	}
}

// AcmeFS implements the tlsfs.TlsFS interface, providing
// a tls certificate acquisition, renewal and management
// implementation for working with Let's Encrypt CA based
// certificates.
type AcmeFS struct {
	config Config

	ucl        sync.RWMutex
	usersCache map[string]*encoding.UserAcct

	ccl       sync.RWMutex
	certCache map[string]tlsfs.ZapFile

	rcl          sync.RWMutex
	renewedCache map[string]chan struct{}
}

// NewAcmeFS returns a new instance of the AcmeFS.
func NewAcmeFS(config Config) *AcmeFS {
	config.init()

	var fs AcmeFS
	fs.config = config
	fs.certCache = make(map[string]tlsfs.ZapFile)
	fs.usersCache = make(map[string]*encoding.UserAcct)
	fs.renewedCache = make(map[string]chan struct{})
	return &fs
}

// GetCertificate returns a tlsfs.GetCertificateFunc which should be assigned
// to a tls.Config.GetCertificate field to handle automatic loading and retrieval
// of tls.Certificates through this filesystem.
// NOTE: Your are required to provide an
// email which will reference the account/user who signs for these certificates
// generated by the returned function.
func (acm *AcmeFS) GetCertificate(email string) tlsfs.CertificateFunc {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		hname := hello.ServerName
		if hname == "" {
			return nil, errors.New("acme/acmefs: missing server name")
		}

		// if the requests is for a acme temporary certificate then we just need
		// to check the cache and return that one instead.
		if strings.HasSuffix(hname, ".acme.invalid") {
			if cert, err := acm.config.TLSCertCache.Get(hname); err == nil {
				return &cert, nil
			}

			if cert, err := acm.config.TLSCertCache.Get(strings.TrimSuffix(hname, ".acme.invalid")); err == nil {
				return &cert, nil
			}

			return nil, fmt.Errorf("acme/acmefs: no cert for %q", hname)
		}

		var wanted tls.CurveID
		var found bool
		for _, curves := range []tls.CurveID{tls.CurveP384, tls.CurveP256} {
			for _, wanted = range hello.SupportedCurves {
				if wanted == curves {
					found = true
					break
				}
			}
			if found {
				break
			}
		}

		curve := tlsfs.ECKey384
		switch wanted {
		case tls.CurveP256:
			curve = tlsfs.ECKey256
		case tls.CurveP384:
			curve = tlsfs.ECKey384
		case tls.CurveP521:
			curve = tlsfs.ECKey512
		}

		var acct tlsfs.NewDomain
		acct.Domain = hname
		acct.Email = email
		acct.KeyType = curve
		acct.CommonName = hname

		cert, _, err := acm.Create(acct, tlsfs.AgreeToTOS)
		if err != nil {
			return nil, err
		}

		user, err := acm.GetUser(cert.User)
		if err != nil {
			return nil, err
		}

		certbundle, err := certificates.EncodeCertificate(cert.Certificate)
		if err != nil {
			return nil, err
		}

		keybundle, err := certificates.EncodePrivateKey(user.GetPrivateKey())
		if err != nil {
			return nil, err
		}

		obtained, err := tls.X509KeyPair(certbundle, keybundle)
		if err != nil {
			return nil, err
		}

		return &obtained, nil
	}

}

//Serve returns a http.Handler which will cater for requests targeting
// the `/.well-known/acme-challenge/` which responds to acme challenges
// for http-01, else passes the request to be handled by provided handler.
// Serve will proxy all requests for the acme challenge to the ip address
// and port provided in the Config.ListenAddr and Config.HTTPChallengePort.
func (acm *AcmeFS) Serve(def http.Handler) http.Handler {
	return handler{func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, acmeChallengeSubPath) {
			def.ServeHTTP(w, r)
			return
		}

		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}

		upstream, err := url.Parse(fmt.Sprintf("%s://%s:%d", scheme, acm.config.ListenerAddr, acm.config.HTTPChallengePort))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(upstream)
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		proxy.ServeHTTP(w, r)
	}}
}

type handler struct{ fn http.HandlerFunc }

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.fn(w, r) }

// GetUser returns an existing user account asocited with the provided
// email.
func (acm *AcmeFS) GetUser(email string) (tlsfs.Account, error) {
	return acm.readUserFrom(email)
}

// Revoke attempts to revoke the existing certificate associated with
// the user's email and domain. If certificate is pending renewal then
// it will wait until the end of the renewal before making an attempt
// to revoke certificate. Once revoked, then certificate is deleted.
// If revokation fails, the certificate is kept in the filesystem, till
// a revoke is successfully through the CA.
func (acm *AcmeFS) Revoke(email string, domain string) error {
	signature := encoding.GetDomainSignature(email, domain)

	// ensure we are not working on a renewal for this domain certificate.
	acm.rcl.Lock()
	renewedChan, renewedFound := acm.renewedCache[signature]
	acm.rcl.Unlock()

	// Await for the ending of certificate renewal.
	if renewedFound {
		<-renewedChan
	}

	user, err := acm.readUserFrom(email)
	if err != nil {
		return err
	}

	existingDomain, err := acm.readDomainFrom(email, domain)
	if err != nil {
		return err
	}

	client, err := acme.NewClient(acm.config.CAURL, user, acme.EC384)
	if err != nil {
		return err
	}

	certbundle, ok := existingDomain.Bundle.(acme.CertificateResource)
	if !ok {
		return err
	}

	var tErrs []error

	for attempts := 0; attempts > 3; attempts++ {
		err = client.RevokeCertificate(certbundle.Certificate)
		if err != nil {
			tErrs = append(tErrs, err)
			if _, ok := err.(acme.TOSError); ok {
				// Immediately agree to CA Terms of Aggrement.
				if err := client.AgreeToTOS(); err != nil {
					return err
				}
			}
			continue
		}

		tErrs = nil
		break
	}

	if len(tErrs) != 0 {
		return joinError(existingDomain.Domain, tErrs...)
	}

	// Remove domain from cache.
	acm.ccl.Lock()
	delete(acm.certCache, signature)
	acm.ccl.Unlock()

	return acm.config.CertificatesFileSystem.Remove(signature)
}

// All returns all existing certificates within the AcmeFS regardless of renewal status
// allowing all state preserved to caller.
func (acm *AcmeFS) All() ([]tlsfs.DomainAccount, error) {
	zappers, err := acm.config.CertificatesFileSystem.ReadAll()
	if err != nil {
		return nil, err
	}

	accounts := make([]tlsfs.DomainAccount, 0)
	userToAccount := map[string]int{}

	for _, zapp := range zappers {
		zapped, err := domainDecoder.Decode(zapp)
		if err != nil {
			// if this error is due to corruption then remove.
			if _, ok := err.(*encoding.ZapCorruptedError); ok {
				acm.config.CertificatesFileSystem.Remove(zapp.Name)
			}

			continue
		}

		if user, err := acm.readUserFrom(zapped.User); err == nil {
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

// CreateWithCSR attempts to returns a new tlsfs.TLSDOmainCertificate for giving certificate
// request. It creates a temporary user without a private key and uses this user to create
// a acme client to serve said certificate requests.
func (acm *AcmeFS) CreateWithCSR(req x509.CertificateRequest, tos tlsfs.TOSAction) (tlsfs.TLSDomainCertificate, tlsfs.Status, error) {
	var email string

	if len(req.EmailAddresses) != 0 {
		email = strings.TrimPrefix(req.EmailAddresses[0], "mailto://")
	}

	if email == "" {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, tlsfs.ErrNoEmailProvided),
			tlsfs.ErrNoEmailProvided
	}

	domain := req.Subject.CommonName

	var acct tlsfs.NewDomain
	acct.Domain = domain
	acct.Email = email

	for _, dns := range req.DNSNames {
		acct.DNSNames = append(acct.DNSNames, dns)
	}

	// Ensure domain qualifies and is not containing a scheme
	// or invalid values.
	if !hostQualifies(acct.Domain) {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, tlsfs.ErrInvalidDomain),
			tlsfs.ErrInvalidDomain
	}

	var domainClient *acme.Client

	// We need to attempt to load the user related to the giving email if he exists,
	// if we do not have such a user, then create one.
	user, err := acm.readUserFrom(acct.Email)
	if err != nil {
		if _, ok := err.(tlsfs.NotExists); !ok {
			return tlsfs.TLSDomainCertificate{},
				tlsfs.WithStatus(tlsfs.OPFailed, tlsfs.ErrInvalidDomain),
				tlsfs.ErrInvalidDomain
		}

		user = new(encoding.UserAcct)
		user.Email = acct.Email

		domainClient, err = acme.NewClient(acm.config.CAURL, user, acme.EC384)
		if err != nil {
			return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		}

		// Attempt to retrieve registration of users before we attempt to register.
		// If we dont have one or an error occured, attempt to register.
		resource, err := domainClient.QueryRegistration()
		if err != nil {
			resource, err = domainClient.Register()
		}

		if err != nil {
			return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		}

		user.Resource = resource

		if tos != nil {
			if !tos(resource.TosURL) {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}

			// Immediately agree to CA Terms of Aggrement.
			if err := domainClient.AgreeToTOS(); err != nil {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}
		} else {
			// Immediately agree to CA Terms of Aggrement.
			if err := domainClient.AgreeToTOS(); err != nil {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}
		}
	}

	// If there exists a already signed certificate for this domain by this user, then
	// retrieve certificate, validate it is not yet expired by it's status and return
	// else renew certificate if about to expire or revoke if it has expired and move to
	// create new one.
	if existingDomain, err := acm.readDomainFrom(acct.Email, acct.Domain); err == nil {
		currentStatus := acm.getDomainStatus(existingDomain.Certificate)

		switch currentStatus.Flag() {
		case tlsfs.CARenewedRequired, tlsfs.CACriticalRenewedRequired:
			//return acm.Renew(acct.Email, acct.Domain)
			return existingDomain, currentStatus, nil
		case tlsfs.CACExpired:
			if err := acm.Revoke(acct.Email, acct.Domain); err != nil {
				return tlsfs.TLSDomainCertificate{},
					tlsfs.WithStatus(tlsfs.OPFailed, errors.New("expired certificate")), err
			}
		default:
			return existingDomain, currentStatus, nil
		}
	}

	if domainClient == nil {
		domainClient, err = acme.NewClient(acm.config.CAURL, user, acme.EC384)
		if err != nil {
			return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		}
	}

	// Set the dns-01 port information for dns challenges.
	if acm.config.DNSProvider != nil && acm.config.EnableDNS01Challenge {
		domainClient.SetChallengeProvider(acme.DNS01, acm.config.DNSProvider)
	}

	// Set the HTTP-01 port information for http challenges.
	if acm.config.EnableHTTP01Challenge {
		domainClient.SetHTTPAddress(
			net.JoinHostPort(
				acm.config.ListenerAddr,
				strconv.Itoa(acm.config.HTTPChallengePort),
			),
		)

		// Replace default http provider to be used for challenge.
		//if acm.config.HTTPProvider != nil {
		//	domainClient.SetChallengeProvider(acme.HTTP01, acm.config.HTTPProvider)
		//}
	}

	// Set the TLS-SNI-01 port information for tls challenges.
	if acm.config.EnableTLSSNI01Challenge {
		domainClient.SetTLSAddress(
			net.JoinHostPort(
				acm.config.ListenerAddr,
				strconv.Itoa(acm.config.TLSSNIChallengePort),
			),
		)

		// Replace default tls-sni provider to be used for challenge.
		//if acm.config.TLSSNIProvider != nil {
		//	domainClient.SetChallengeProvider(acme.TLSSNI01, acm.config.TLSSNIProvider)
		//}
		domainClient.SetChallengeProvider(acme.TLSSNI01, tlsSNISolver{certCache: acm.config.TLSCertCache})
	}

	// Add the exclusion set generated from the configuration.
	domainClient.ExcludeChallenges(acm.config.excludedChallenges)

	var doma tlsfs.TLSDomainCertificate
	doma.User = acct.Email
	doma.Domain = acct.Domain

	// Attempt to retrieve certificate at most 3 times, combine all errors
	// if we fail to get a valid response from server.
	var tErrs []error
	var bundled acme.CertificateResource

	// Attempt 5 times to get certificate bundle response.
	for attempts := 3; attempts > 0; attempts-- {
		bundle, failures := domainClient.ObtainCertificateForCSR(req, true)

		// if failure occured then evaluate if giving certificate domain has
		// an error, if so validate it's not a TOS error and try again.
		if len(failures) != 0 {
			if err, ok := failures[acct.Domain]; ok {
				tErrs = append(tErrs, err)
				if _, ok := err.(acme.TOSError); ok {
					if tos != nil {
						if !tos(user.Resource.TosURL) {
							return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
						}

						// Immediately agree to CA Terms of Aggrement.
						if err := domainClient.AgreeToTOS(); err != nil {
							return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
						}
					} else {
						// Immediately agree to CA Terms of Aggrement.
						if err := domainClient.AgreeToTOS(); err != nil {
							return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
						}
					}
				}
			}
			continue
		}
		bundled = bundle
		doma.Bundle = bundle
		tErrs = nil
		break
	}

	if len(tErrs) != 0 {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, errors.New("CA error")),
			joinError(acct.Domain, tErrs...)
	}

	doma.Certificate, err = certificates.DecodeCertificate(bundled.Certificate)
	if err != nil {
		return doma, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	doma.IssuerCertificate, err = certificates.DecodeCertificate(bundled.IssuerCertificate)
	if err != nil {
		return doma, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	doma.Request, err = certificates.DecodeCertificateRequest(bundled.CSR)
	if err != nil {
		return doma, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	if err := acm.saveDomain(doma); err != nil {
		return doma, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	return doma, tlsfs.WithStatus(tlsfs.Created, nil), nil
}

// CreateCA is not supported by this acme implementation. It's purpose is to
// allowing signing certificate requests for sub-CAs.
func (acm *AcmeFS) CreateCA(acct tlsfs.NewDomain, tos tlsfs.TOSAction) (tlsfs.TLSDomainCertificate, tlsfs.Status, error) {
	return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, tlsfs.ErrNotSupported), tlsfs.ErrNotSupported
}

// Create attempts to create a given TLSDomainCertificate for the giving account.
// If a certificate already exists for the giving accounts.Domain, then the old
// TLSDomainCertificate is returned if its has not pass the accepted expiration time
// yet of 30 days. If it has then a renewal is initiated for the certificate and if
// successfully will return the new TLSDomainCertificate after replacing the old one.
// If a renewal failed and the certificate is less than two weeks to expiry or within the
// 30-days expiration, then the certificate is returned with an appropriate status to
// indicate non-critical but important reason of failure.
// NOTE: With Lets Encrypt, we do not have control over the value of the common name passed
// to the certificate request on the CA side, so the tlsfs.NewDomian.CommonName and
// tlsfs.NewDomian.DNSNames is ignored.
func (acm *AcmeFS) Create(acct tlsfs.NewDomain, tos tlsfs.TOSAction) (tlsfs.TLSDomainCertificate, tlsfs.Status, error) {
	if acct.CommonName == "" {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, tlsfs.ErrNoCommonName),
			tlsfs.ErrNoCommonName
	}

	// Ensure all domain is in lowercase.
	acct.Domain = strings.ToLower(acct.Domain)

	// Ensure domain qualifies and is not containing a scheme
	// or invalid values.
	if !hostQualifies(acct.Domain) {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, tlsfs.ErrInvalidDomain),
			tlsfs.ErrInvalidDomain
	}

	var domainClient *acme.Client

	// We need to attempt to load the user related to the giving email if he exists,
	// if we do not have such a user, then create one.
	user, err := acm.readUserFrom(acct.Email)
	if err != nil {
		if _, ok := err.(tlsfs.NotExists); !ok {
			return tlsfs.TLSDomainCertificate{},
				tlsfs.WithStatus(tlsfs.OPFailed, tlsfs.ErrInvalidDomain),
				tlsfs.ErrInvalidDomain
		}

		user = new(encoding.UserAcct)
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
		// Wait to xenolf/lego supports EC512.
		//case tlsfs.ECKey512:
		//	if user.PrivateKey, _, err = certificates.CreateECKey(elliptic.P521()); err != nil {
		//		return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		//	}
		default:
			return tlsfs.TLSDomainCertificate{},
				tlsfs.WithStatus(tlsfs.OPFailed, certificates.ErrUnknownPrivateKeyType),
				certificates.ErrUnknownPrivateKeyType
		}

		domainClient, err = acme.NewClient(acm.config.CAURL, user, acme.EC384)
		if err != nil {
			return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		}

		// Attempt to retrieve registration of users before we attempt to register.
		// If we dont have one or an error occured, attempt to register.
		resource, err := domainClient.QueryRegistration()
		if err != nil {
			resource, err = domainClient.Register()
		}

		if err != nil {
			return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		}

		user.Resource = resource

		if tos != nil {
			if !tos(resource.TosURL) {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}

			// Immediately agree to CA Terms of Aggrement.
			if err := domainClient.AgreeToTOS(); err != nil {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}
		} else {
			// Immediately agree to CA Terms of Aggrement.
			if err := domainClient.AgreeToTOS(); err != nil {
				return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
			}
		}

		// Attempt to save the user immediately.
		if err := acm.saveUser(acct.Email, user.PrivateKey, user.Resource); err != nil {
			return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		}
	}

	// If there exists a already signed certificate for this domain by this user, then
	// retrieve certificate, validate it is not yet expired by it's status and return
	// else renew certificate if about to expire or revoke if it has expired and move to
	// create new one.
	if existingDomain, err := acm.readDomainFrom(acct.Email, acct.Domain); err == nil {
		currentStatus := acm.getDomainStatus(existingDomain.Certificate)

		switch currentStatus.Flag() {
		case tlsfs.CARenewedRequired, tlsfs.CACriticalRenewedRequired:
			return acm.Renew(acct.Email, acct.Domain)
		case tlsfs.CACExpired:
			if err := acm.Revoke(acct.Email, acct.Domain); err != nil {
				return tlsfs.TLSDomainCertificate{},
					tlsfs.WithStatus(tlsfs.OPFailed, errors.New("expired certificate")), err
			}
		default:
			return existingDomain, currentStatus, nil
		}
	}

	if domainClient == nil {
		domainClient, err = acme.NewClient(acm.config.CAURL, user, acme.EC384)
		if err != nil {
			return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		}
	}

	// Set the dns-01 port information for dns challenges.
	if acm.config.DNSProvider != nil && acm.config.EnableDNS01Challenge {
		domainClient.SetChallengeProvider(acme.DNS01, acm.config.DNSProvider)
	}

	// Set the HTTP-01 port information for http challenges.
	if acm.config.EnableHTTP01Challenge {
		domainClient.SetHTTPAddress(
			net.JoinHostPort(
				acm.config.ListenerAddr,
				strconv.Itoa(acm.config.HTTPChallengePort),
			),
		)

		// Replace default http provider to be used for challenge.
		//if acm.config.HTTPProvider != nil {
		//	domainClient.SetChallengeProvider(acme.HTTP01, acm.config.HTTPProvider)
		//}
	}

	// Set the TLS-SNI-01 port information for tls challenges.
	if acm.config.EnableTLSSNI01Challenge {
		domainClient.SetTLSAddress(
			net.JoinHostPort(
				acm.config.ListenerAddr,
				strconv.Itoa(acm.config.TLSSNIChallengePort),
			),
		)

		// Replace default tls-sni provider to be used for challenge.
		//if acm.config.TLSSNIProvider != nil {
		//	domainClient.SetChallengeProvider(acme.TLSSNI01, acm.config.TLSSNIProvider)
		//}
		domainClient.SetChallengeProvider(acme.TLSSNI01, tlsSNISolver{certCache: acm.config.TLSCertCache})
	}

	// Add the exclusion set generated from the configuration.
	domainClient.ExcludeChallenges(acm.config.excludedChallenges)

	var doma tlsfs.TLSDomainCertificate
	doma.User = acct.Email
	doma.Domain = acct.Domain

	// Attempt to retrieve certificate at most 3 times, combine all errors
	// if we fail to get a valid response from server.
	var tErrs []error
	var bundled acme.CertificateResource

	// Attempt 5 times to get certificate bundle response.
	for attempts := 3; attempts > 0; attempts-- {
		bundle, failures := domainClient.ObtainCertificate(
			[]string{acct.Domain},
			true,
			user.PrivateKey,
			acm.config.MustStaple,
		)

		// if failure occured then evaluate if giving certificate domain has
		// an error, if so validate it's not a TOS error and try again.
		if len(failures) != 0 {
			if err, ok := failures[acct.Domain]; ok {
				tErrs = append(tErrs, err)
				if _, ok := err.(acme.TOSError); ok {
					if tos != nil {
						if !tos(user.Resource.TosURL) {
							return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
						}

						// Immediately agree to CA Terms of Aggrement.
						if err := domainClient.AgreeToTOS(); err != nil {
							return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
						}
					} else {
						// Immediately agree to CA Terms of Aggrement.
						if err := domainClient.AgreeToTOS(); err != nil {
							return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
						}
					}
				}
			}
			continue
		}
		bundled = bundle
		doma.Bundle = bundle
		tErrs = nil
		break
	}

	if len(tErrs) != 0 {
		return tlsfs.TLSDomainCertificate{},
			tlsfs.WithStatus(tlsfs.OPFailed, errors.New("CA error")),
			joinError(acct.Domain, tErrs...)
	}

	doma.Certificate, err = certificates.DecodeCertificate(bundled.Certificate)
	if err != nil {
		return doma, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	doma.IssuerCertificate, err = certificates.DecodeCertificate(bundled.IssuerCertificate)
	if err != nil {
		return doma, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	doma.Request, err = certificates.DecodeCertificateRequest(bundled.CSR)
	if err != nil {
		return doma, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	if err := acm.saveDomain(doma); err != nil {
		return doma, tlsfs.WithStatus(tlsfs.OPFailed, err), err
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
func (acm *AcmeFS) Renew(email string, domain string) (tlsfs.TLSDomainCertificate, tlsfs.Status, error) {
	signature := encoding.GetDomainSignature(email, domain)

	// We first must validate that no previous renewal is
	// not already underway for giving domain. If there is:
	// then we just read from that when it's done instead.
	acm.rcl.Lock()
	if _, ok := acm.renewedCache[signature]; ok {
		acm.rcl.Unlock()

		// We simply call readDomainFrom which handles gracefully
		// waiting for the finishing of an existing renewal and
		// returns the renewed domain or error when done.
		domain, err := acm.readDomainFrom(email, domain)
		if err != nil {
			return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
		}

		return domain, acm.getDomainStatus(domain.Certificate), nil
	}
	acm.rcl.Unlock()

	user, err := acm.readUserFrom(email)
	if err != nil {
		return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	existingDomain, err := acm.readDomainFrom(email, domain)
	if err != nil {
		return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	// We need to allocate a renew channel for others to be aware of the fact
	// that the domain certificate is being renewed.
	renewal := make(chan struct{})

	// Ensure to added renewed channel into existing channel.
	acm.rcl.Lock()
	acm.renewedCache[signature] = renewal
	acm.rcl.Unlock()

	// We need to ensure the renewed channel is closed and removed from
	// the renewed channel map after all operations are done, regardless of
	// failure.
	defer func() {
		close(renewal)

		acm.rcl.Lock()
		delete(acm.renewedCache, signature)
		acm.rcl.Unlock()
	}()

	client, err := acme.NewClient(acm.config.CAURL, user, acme.EC384)
	if err != nil {
		return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	certbundle, ok := existingDomain.Bundle.(acme.CertificateResource)
	if !ok {
		return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	var tErrs []error
	var bundled acme.CertificateResource

	// Attempt 5 times to renew domain certificate.
	for attempts := 3; attempts > 0; attempts-- {
		bundled, err = client.RenewCertificate(certbundle, true, acm.config.MustStaple)
		if err != nil {
			tErrs = append(tErrs, err)
			if _, ok := err.(acme.TOSError); ok {
				// Immediately agree to CA Terms of Aggrement.
				if err := client.AgreeToTOS(); err != nil {
					return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
				}
			}
			continue
		}

		tErrs = nil
		break
	}

	if len(tErrs) != 0 {
		jerr := joinError(existingDomain.Domain, tErrs...)
		return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, jerr), jerr
	}

	existingDomain.Bundle = bundled

	existingDomain.Certificate, err = certificates.DecodeCertificate(bundled.Certificate)
	if err != nil {
		return existingDomain, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	existingDomain.IssuerCertificate, err = certificates.DecodeCertificate(bundled.IssuerCertificate)
	if err != nil {
		return existingDomain, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	existingDomain.Request, err = certificates.DecodeCertificateRequest(bundled.CSR)
	if err != nil {
		return existingDomain, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	if err := acm.saveDomain(existingDomain); err != nil {
		return existingDomain, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	return existingDomain, tlsfs.WithStatus(tlsfs.Renewed, nil), nil
}

// Get attempts to retrieve a existing certificate from the underline store, if such certificate
// is requiring renewal then the renewal process is called for the certificate with appropriate
// response returned as stated for the AcmeFS.Renew method.
// It returns a status appropriate for the certificate returned to indicate to the caller
// the state and needed action if any to be done.
func (acm *AcmeFS) Get(email string, domain string) (tlsfs.TLSDomainCertificate, tlsfs.Status, error) {
	existingDomain, err := acm.readDomainFrom(email, domain)
	if err != nil {
		return tlsfs.TLSDomainCertificate{}, tlsfs.WithStatus(tlsfs.OPFailed, err), err
	}

	currentStatus := acm.getDomainStatus(existingDomain.Certificate)

	switch currentStatus.Flag() {
	case tlsfs.CACExpired:
		if err := acm.Revoke(email, domain); err != nil {
			return tlsfs.TLSDomainCertificate{},
				tlsfs.WithStatus(tlsfs.OPFailed, errors.New("expired certificate")), err
		}
	case tlsfs.CARenewedRequired, tlsfs.CACriticalRenewedRequired:
		return acm.Renew(email, domain)
	}

	return existingDomain, currentStatus, nil
}

func (acm *AcmeFS) getDomainStatus(cert *x509.Certificate) tlsfs.Status {
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

func (acm *AcmeFS) readDomainFrom(email string, domain string) (tlsfs.TLSDomainCertificate, error) {
	signature := encoding.GetDomainSignature(email, domain)

	// We first need to validate we are not in a renewal state where
	// the giving domain is being attempted for renewal.
	acm.rcl.Lock()
	renewedChan, ok := acm.renewedCache[signature]
	acm.rcl.Unlock()

	// the current domain is already being renewed or is facing a renewal attempt
	// hence we must await the end of the renewal before attempting to read.
	if ok {
		// Renewal is finished by this area, so we must first validate that the cache has
		// no domain record of giving TLSDomainCertificate, has the renewal will remove all traces of
		// certificate from the cache before closing the channel.
		<-renewedChan

		// Ensure we don't have anything in cache else its probably in an invalid state
		// and if invalid, then remove from cache first.
		acm.ccl.Lock()
		if _, ok := acm.certCache[signature]; ok {
			delete(acm.certCache, signature)
		}
		acm.ccl.Unlock()

		// After removal, attempt to read form file system, if successfully, load response into
		// cache and return to user, if we failed, then we know renewal failed and a fs error must
		// have occured.
		zapp, err := acm.config.CertificatesFileSystem.Read(signature)
		if err != nil {
			return tlsfs.TLSDomainCertificate{}, err
		}

		// A zap file should never face an issue where we fail to pass it,
		// we automatically see it has corrupted so, delete and return an
		// error.
		rec, err := domainDecoder.Decode(zapp)
		if err != nil {
			// A zap file must never be corrupted and be unreadable, so if
			// something happens during it's conversion, then delete it.
			if _, ok := err.(*encoding.ZapCorruptedError); ok {
				acm.config.CertificatesFileSystem.Remove(signature)
			}
			return tlsfs.TLSDomainCertificate{}, err
		}

		// Save domain zapp file into cache for quick access.
		acm.ccl.Lock()
		acm.certCache[signature] = zapp
		acm.ccl.Unlock()

		return rec, nil
	}

	acm.ccl.Lock()
	if zapp, ok := acm.certCache[signature]; ok {
		acm.ccl.Unlock()

		// A zap file should never face an issue where we fail to parse it,
		// we automatically see it has corrupted so, delete and return an
		// error.
		rec, err := domainDecoder.Decode(zapp)
		if err != nil {
			// A zap file must never be corrupted and be unreadable, so if
			// something happens during it's conversion, then delete it.
			if _, ok := err.(*encoding.ZapCorruptedError); ok {
				acm.config.CertificatesFileSystem.Remove(signature)
			}
			return tlsfs.TLSDomainCertificate{}, err
		}

		return rec, nil
	}
	acm.ccl.Unlock()

	// Read the zap file for the domain from the filesystem, if it exists.
	zapp, err := acm.config.CertificatesFileSystem.Read(signature)
	if err != nil {
		return tlsfs.TLSDomainCertificate{}, err
	}

	// A zap file should never face an issue where we fail to parse it,
	// we automatically see it has corrupted so, delete and return an
	// error.
	rec, err := domainDecoder.Decode(zapp)
	if err != nil {
		// A zap file must never be corrupted and be unreadable, so if
		// something happens during it's conversion, then delete it.
		if _, ok := err.(*encoding.ZapCorruptedError); ok {
			acm.config.CertificatesFileSystem.Remove(signature)
		}
		return tlsfs.TLSDomainCertificate{}, err
	}

	// Save domain zapp file into cache for quick access.
	acm.ccl.Lock()
	acm.certCache[signature] = zapp
	acm.ccl.Unlock()

	return rec, nil
}

func (acm *AcmeFS) readUserFrom(email string) (*encoding.UserAcct, error) {
	es := encoding.GetUserSignature(email)

	acm.rcl.RLock()
	if cached, ok := acm.usersCache[es]; ok {
		acm.rcl.RUnlock()
		return cached, nil
	}
	acm.rcl.RUnlock()

	zapp, err := acm.config.UsersFileSystem.Read(es)
	if err != nil {
		return nil, err
	}

	// Parse the zap file format into *userAcct type.
	user, err := accountDecoder.Decode(zapp)
	if err != nil {
		// A zap file must never be corrupted and be unreadable, so if
		// something happens during it's conversion, then delete it.
		if _, ok := err.(*encoding.ZapCorruptedError); ok {
			acm.config.UsersFileSystem.Remove(es)
		}

		return nil, err
	}

	acm.rcl.Lock()
	acm.usersCache[es] = user
	acm.rcl.Unlock()

	return user, nil
}

func (acm *AcmeFS) saveUser(email string, privateKey crypto.PrivateKey, res *acme.RegistrationResource) error {
	encoded, err := accountEncoder.Encode(encoding.NewUserAcct(email, privateKey, res))
	if err != nil {
		return err
	}

	return acm.config.UsersFileSystem.WriteFile(encoded)
}

func (acm *AcmeFS) saveDomain(domain tlsfs.TLSDomainCertificate) error {
	encoded, err := domainEncoder.Encode(domain)
	if err != nil {
		return err
	}

	return acm.config.CertificatesFileSystem.WriteFile(encoded)
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

func hostQualifies(hostname string) bool {
	return tlsp.HostQualifies(hostname) &&
		// cannot be an IP address, see
		// https://community.letsencrypt.org/t/certificate-for-static-ip/84/2?u=mholt
		net.ParseIP(hostname) == nil
}
