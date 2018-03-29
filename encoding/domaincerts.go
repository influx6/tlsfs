package encoding

import (
	"crypto"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/wirekit/tlsfs"
	"github.com/wirekit/tlsfs/certificates"
	"github.com/xenolf/lego/acme"
)

const (
	// domainNameDataZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	domainNameDataZapName = "domain-uri-name"

	// domainUserDataZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	domainUserDataZapName = "domain-user-email"

	// domainBundleDataZapName sets the name used to store the zap track for the domain
	// certificate bundle zap file
	domainBundleDataZapName = "domain-bundle-data"

	// domainPrivateKeyZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	domainPrivateKeyZapName = "domain-private-key"

	// domainCertificateZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	domainCertificateZapName = "domain-certificate"

	// domainUserRegistrationDataZapName sets the name used to store the zap track for the domain
	// user registration data in a zap file.
	domainUserRegistrationDataZapName = "domain-user-registration-data"

	// issuerDomainCertificateZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	issuerDomainCertificateZapName = "domain-issuer-certificate"

	// domainCertificateRequestZapName sets the name used to store the zap track for the domain
	// account in a zap file.
	domainCertificateRequestZapName = "domain-certificate-request"
)

var (
	// ErrZapFileDomainMismatched is returned when given domain does not match data in file.
	ErrZapFileDomainMismatched = errors.New("ZapFile domain-account.Domain does not match expected")

	// ErrZapFileHasNoAcctData is returned when a zapfile contains no acct data for a domain.
	ErrZapFileHasNoAcctData = WithZapCorrupted(errors.New("ZapFile contains no domain-account data"))

	// ErrZapFileHasNoPKeyData is returned when a zapfile contains no private key data for a domain.
	ErrZapFileHasNoPKeyData = WithZapCorrupted(errors.New("ZapFile contains no domain-private-key data"))

	// ErrZapFileHasNoUserRegistrationData is returned when a zapfile contains no user registration data for a domain.
	ErrZapFileHasNoUserRegistrationData = WithZapCorrupted(errors.New("ZapFile contains no domain-user-registration-data data"))

	// ErrZapFileHasNoCertificate is returned when a zapfile contains no domain certificate for a domain.
	ErrZapFileHasNoCertificate = WithZapCorrupted(errors.New("ZapFile contains no domain-certificate data"))

	// ErrZapFileHasNoIssuerCertificate is returned when a zapfile contains no domain issuer certificate
	// from the CA for a domain.
	ErrZapFileHasNoIssuerCertificate = WithZapCorrupted(errors.New("ZapFile contains no domain-issuer-certificate data"))

	// ErrZapFileHasNoCertificateRequest is returned when a zapfile contains no domain certificate
	// request or CRS, that was used to generate the domain certificate for a domain.
	ErrZapFileHasNoCertificateRequest = WithZapCorrupted(errors.New("ZapFile contains no domain-certificate-request data"))
)

//*********************************************************
// AccountZap Encoder and Decoder
//*********************************************************

// AccountZapDecoder implements a decoder which transforms a provided
// zap file track content into a tlsfs.Account.
type AccountZapDecoder struct{}

// Decode attempts to decode the contents of the zap file as a tlsfs.Account,
// returning an error if the it failed.
func (enc AccountZapDecoder) Decode(zapFile tlsfs.ZapFile) (*UserAcct, error) {
	user := new(UserAcct)

	userData, err := zapFile.Find(domainUserDataZapName)
	if err != nil {
		return nil, ErrZapFileHasNoAcctData
	}

	user.Email = string(userData.Data)

	domainPKey, err := zapFile.Find(domainPrivateKeyZapName)
	if err != nil {
		return nil, ErrZapFileHasNoPKeyData
	}

	_, pkey, err := certificates.DecodePrivateKey(domainPKey.Data)
	if err != nil {
		return nil, err
	}

	// If we have an associated registration data then attached that as well.
	if registration, err := zapFile.Find(domainUserRegistrationDataZapName); err == nil {
		if err := json.Unmarshal(registration.Data, &user.Resource); err != nil {
			return nil, err
		}
	}

	user.PrivateKey = pkey
	return user, nil
}

// AccountZapEncoder implements a tls.ZapFile encoder which
// transforms a giving tls.TLSDomainCertificate into a ZapFile.
type AccountZapEncoder struct{}

// Encode implements the procedure to transform a tlsfs.TLSDomainCertificate
// to transform a tlsfs.TLSDomainCertificate into a tlsfs.ZapFile.
func (enc AccountZapEncoder) Encode(acct tlsfs.Account) (tlsfs.ZapFile, error) {
	var zapped tlsfs.ZapFile
	zapped.Name = GetUserSignature(acct.GetEmail())

	keyData, err := certificates.EncodePrivateKey(acct.GetPrivateKey())
	if err != nil {
		return zapped, err
	}

	if regr, ok := acct.(Registration); ok {
		if reg := regr.GetRegistration(); reg != nil {
			regJSON, err := json.Marshal(reg)
			if err != nil {
				return zapped, err
			}

			zapped.Add(domainUserRegistrationDataZapName, regJSON)
		}
	}

	zapped.Add(domainPrivateKeyZapName, keyData)
	zapped.Add(domainUserDataZapName, []byte(acct.GetEmail()))
	return zapped, nil
}

//*********************************************************
// TLSDomain ZapEncoder and ZapDecoder
//*********************************************************

// TLSDomainZapDecoder implements a decoder which transforms a provided
// zap file track content into a tlsfs.TLSDomainCertificate.
type TLSDomainZapDecoder struct{}

// Decode attempts to decode the contents of the zap file as a tlsfs.Account,
// returning an error if the it failed.
func (enc TLSDomainZapDecoder) Decode(zapFile tlsfs.ZapFile) (tlsfs.TLSDomainCertificate, error) {
	var tacc tlsfs.TLSDomainCertificate

	domain, err := zapFile.Find(domainNameDataZapName)
	if err != nil {
		return tacc, ErrZapFileHasNoAcctData
	}

	tacc.Domain = string(domain.Data)

	user, err := zapFile.Find(domainUserDataZapName)
	if err != nil {
		return tacc, ErrZapFileHasNoAcctData
	}

	tacc.User = string(user.Data)

	domainCert, err := zapFile.Find(domainCertificateZapName)
	if err != nil {
		return tacc, ErrZapFileHasNoCertificate
	}

	cert, err := certificates.DecodeCertificate(domainCert.Data)
	if err != nil {
		return tacc, err
	}

	tacc.Certificate = cert
	tacc.IsSubCA = cert.IsCA

	domainIssuerCert, err := zapFile.Find(issuerDomainCertificateZapName)
	if err != nil {
		return tacc, ErrZapFileHasNoIssuerCertificate
	}

	issuerCert, err := certificates.DecodeCertificate(domainIssuerCert.Data)
	if err != nil {
		return tacc, err
	}

	tacc.IssuerCertificate = issuerCert

	if domainCertReq, err := zapFile.Find(domainCertificateRequestZapName); err == nil {
		certReq, err := certificates.DecodeCertificateRequest(domainCertReq.Data)
		if err != nil {
			return tacc, err
		}

		tacc.Request = certReq
	} else {
		if !tacc.IsSubCA {
			return tacc, ErrZapFileHasNoCertificateRequest
		}
	}

	bundleCert, err := zapFile.Find(domainBundleDataZapName)
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

// TLSDomainZapEncoder implements a tls.ZapFile encoder which
// transforms a giving tls.TLSDomainCertificate into a ZapFile.
type TLSDomainZapEncoder struct{}

// Encode implements the procedure to transform a tlsfs.TLSDomainCertificate
// to transform a tlsfs.TLSDomainCertificate into a tlsfs.ZapFile.
func (enc TLSDomainZapEncoder) Encode(cert tlsfs.TLSDomainCertificate) (tlsfs.ZapFile, error) {
	var zapped tlsfs.ZapFile
	zapped.Name = GetDomainSignature(cert.User, cert.Domain)

	issuerData, err := certificates.EncodeCertificate(cert.IssuerCertificate)
	if err != nil {
		return zapped, err
	}

	certData, err := certificates.EncodeCertificate(cert.Certificate)
	if err != nil {
		return zapped, err
	}

	bundleJSON, err := json.Marshal(cert.Bundle)
	if err != nil {
		return zapped, err
	}

	if cert.Request != nil {
		reqData, err := certificates.EncodeCertificateRequest(cert.Request)
		if err != nil {
			return zapped, err
		}

		zapped.Add(domainCertificateRequestZapName, reqData)
	}

	zapped.Add(domainUserDataZapName, []byte(cert.User))
	zapped.Add(domainNameDataZapName, []byte(cert.Domain))
	zapped.Add(issuerDomainCertificateZapName, issuerData)
	zapped.Add(domainCertificateZapName, certData)
	zapped.Add(domainBundleDataZapName, bundleJSON)
	return zapped, nil
}

//*************************************************************************
// user struct
//*************************************************************************

// Registration defines an interface that exposes method to retrieve
// an associated acme.RegistrationResource.
type Registration interface {
	GetRegistration() *acme.RegistrationResource
}

// NewUserAcct returns a new UserAcct type which implements both the tlsfs.Account and Registration
// interface.
func NewUserAcct(email string, key crypto.PrivateKey, reg *acme.RegistrationResource) *UserAcct {
	return &UserAcct{
		Email:      email,
		PrivateKey: key,
		Resource:   reg,
	}
}

// UserAcct implements the tlsfs.Account acct for registering users for
// a desired domain.
type UserAcct struct {
	Email      string
	PrivateKey crypto.PrivateKey
	Resource   *acme.RegistrationResource
}

// GetPrivateKey returns the private key associated with user.
func (u UserAcct) GetPrivateKey() crypto.PrivateKey {
	return u.PrivateKey
}

// GetEmail returns the email for the user.
func (u UserAcct) GetEmail() string {
	return u.Email
}

// GetRegistration returns the acme.RegistrationResource associated
// with the user account.
func (u UserAcct) GetRegistration() *acme.RegistrationResource {
	return u.Resource
}

//*************************************************************
// CorruptedError
//*************************************************************

var _ error = ZapCorruptedError{}

// ZapCorruptedError defines an zap error which contain a given reason
// for the case of a corrupted zap file.
type ZapCorruptedError struct {
	Reason error
	File   string
}

// WithZapCorrupted error returns a new instance of ZapCorruptedError.
func WithZapCorrupted(err error) *ZapCorruptedError {
	return &ZapCorruptedError{Reason: err}
}

// Error implements the error interface.
func (zc ZapCorruptedError) Error() string {
	msg := "ZapFile Corrupted: " + zc.Reason.Error()
	if zc.File != "" {
		msg += " File: " + zc.File
	}
	return msg
}

//*************************************************************************
// Utilities
//*************************************************************************

// GetDomainSignature returns a signature suited for giving email address and domain name.
func GetDomainSignature(email, domain string) string {
	mod := md5.New()
	mod.Write([]byte(email))
	mod.Write([]byte(domain))
	signature := base64.StdEncoding.EncodeToString(mod.Sum(nil))
	return signature + "_domain"
}

// GetUserSignature returns a signature suited for giving email address.
func GetUserSignature(email string) string {
	mod := md5.New()
	mod.Write([]byte(email))
	signature := base64.StdEncoding.EncodeToString(mod.Sum(nil))
	return signature + "_user"
}
