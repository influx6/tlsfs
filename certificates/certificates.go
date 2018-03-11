package certificates

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

// const defines series of constant values
const (
	defaultSerialLength   uint = 128
	certFileName               = "ca.cert"
	certKeyFileName            = "ca.key"
	reqcertFileName            = "req_ca.cert"
	reqcertKeyFileName         = "req_ca.key"
	reqcertRootCAFileName      = "req_root_ca.cert"
	certTypeName               = "CERTIFICATE"
	certReqTypeName            = "CERTIFICATE REQUEST"
	rsaCertKeyName             = "RSA PRIVATE KEY"
	ecCertKeyName              = "EC PRIVATE KEY"
	unknownCertKeyName         = "UNKNOWN PRIVATE KEY"
)

// errors ...
var (
	ErrFailedToAddCertToPool    = errors.New("failed to add certificate to x509.CertPool")
	ErrExcludedDNSName          = errors.New("excluded DNSName")
	ErrNoCertificate            = errors.New("has no certificate")
	ErrNoRootCACertificate      = errors.New("has no root CA certificate")
	ErrNoCertificateRequest     = errors.New("has no certificate request")
	ErrNoPrivateKey             = errors.New("has no private key")
	ErrWrongSignatureAlgorithmn = errors.New("incorrect signature algorithmn received")
	ErrInvalidPemBlock          = errors.New("pem.Decode found no pem.Block data")
	ErrInvalidPrivateKey        = errors.New("private key is invalid")
	ErrInvalidCABlockType       = errors.New("pem.Block has invalid block header for ca cert")
	ErrInvalidCAKeyBlockType    = errors.New("pem.Block has invalid block header for ca key")
	ErrEmptyCARawSlice          = errors.New("CA Raw slice is empty")
	ErrInvalidRawLength         = errors.New("CA Raw slice length is invalid")
	ErrInvalidRequestRawLength  = errors.New("RequestCA Raw slice length is invalid")
	ErrInvalidRootCARawLength   = errors.New("RootCA Raw slice length is invalid")
	ErrInvalidRawCertLength     = errors.New("Cert raw slice length is invalid")
	ErrInvalidRawCertKeyLength  = errors.New("Cert Key raw slice length is invalid")
	ErrUnknownPrivateKeyType    = errors.New("unknown private key type, only rsa and ec supported")
	ErrInvalidRSAKey            = errors.New("type is not a *rsa.PrivateKey")
	ErrInvalidECDSAKey          = errors.New("type is not a *ecdsa.PrivateKey")
)

var (
	// ModernCiphers defines a list of modern tls cipher suites.
	ModernCiphers = []uint16{
		tls.TLS_FALLBACK_SCSV,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,

		// Added due to ECDSA elliptic.P384().
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
)

// PrivateKeyType defines the type of supported private key types.
type PrivateKeyType int

// ToPrivateKeyType returns the PrivateKeyType for the giving
// string. See PrivateKeyType.String for string names.
func ToPrivateKeyType(m string) PrivateKeyType {
	m = strings.ToLower(m)
	switch m {
	case rsaCertKeyName:
		return RSAKeyType
	case ecCertKeyName:
		return ECDSAKeyType
	}
	return UnknownType
}

// private key type constants.
const (
	UnknownType PrivateKeyType = iota
	RSAKeyType
	ECDSAKeyType
)

// String returns the lower-case string representation of private key type.
func (pk PrivateKeyType) String() string {
	switch pk {
	case RSAKeyType:
		return rsaCertKeyName
	case ECDSAKeyType:
		return ecCertKeyName
	}

	return unknownCertKeyName
}

//********************************************************************************************
// SecondaryCertificateAuthority Implementation
//********************************************************************************************

// SecondaryCertificateAuthority defines a certificate authority which is not a CA and is signed
// by a root CA.
type SecondaryCertificateAuthority struct {
	RootCA      *x509.Certificate
	Certificate *x509.Certificate
}

// RootCertificateRaw returns the raw version of the certificate.
func (sca SecondaryCertificateAuthority) RootCertificateRaw() ([]byte, error) {
	if sca.RootCA == nil {
		return nil, ErrNoRootCACertificate
	}

	return EncodeCertificate(sca.RootCA)
}

// CertificateRaw returns the raw version of the certificate.
func (sca SecondaryCertificateAuthority) CertificateRaw() ([]byte, error) {
	if sca.Certificate == nil {
		return nil, ErrNoCertificate
	}
	return EncodeCertificate(sca.Certificate)
}

//********************************************************************************************
// CertificateAuthority Implementation
//********************************************************************************************

// CertificateAuthority defines a struct which contains a generated certificate template with
// associated private and public keys.
type CertificateAuthority struct {
	KeyType     PrivateKeyType
	PrivateKey  interface{}
	PublicKey   interface{}
	Certificate *x509.Certificate
}

// VerifyCA validates provided Certificate is still valid with CeritifcateAuthority's CA
// with accordance to usage slice.
func (ca CertificateAuthority) VerifyCA(cas *x509.Certificate, keyUsage []x509.ExtKeyUsage) error {
	if ca.Certificate == nil {
		return ErrNoCertificate
	}

	certpool := x509.NewCertPool()
	certpool.AddCert(ca.Certificate)
	options := x509.VerifyOptions{Roots: certpool, KeyUsages: keyUsage}
	if _, err := cas.Verify(options); err != nil {
		return err
	}
	return nil
}

// ApproveServerClientCertificateSigningRequest processes the provided CertificateRequest
// returning a new Certificate Authority
// which has being signed by this root CA.
// All received signed by this method receive ExtKeyUsageServerAuth and ExtKeyUsageClientAuth.
func (ca CertificateAuthority) ApproveServerClientCertificateSigningRequest(req *CertificateRequest, lifeTime time.Duration) error {
	var secondaryCA SecondaryCertificateAuthority

	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	template, err := ca.initCertificateRequest(req, lifeTime, usage)
	if err != nil {
		return err
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, template.PublicKey, ca.PrivateKey)
	if err != nil {
		return err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return err
	}

	secondaryCA.Certificate = certificate
	secondaryCA.RootCA = ca.Certificate

	return req.ValidateAndAccept(secondaryCA, usage)
}

// ApproveServerCertificateSigningRequest processes the provided CertificateRequest
// returning a new Certificate Authority
// which has being signed by this root CA.
// All received signed by this method receive ExtKeyUsageServerAuth alone.
func (ca CertificateAuthority) ApproveServerCertificateSigningRequest(req *CertificateRequest, lifeTime time.Duration) error {
	var secondaryCA SecondaryCertificateAuthority

	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template, err := ca.initCertificateRequest(req, lifeTime, usage)
	if err != nil {
		return err
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, template.PublicKey, ca.PrivateKey)
	if err != nil {
		return err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return err
	}

	secondaryCA.Certificate = certificate
	secondaryCA.RootCA = ca.Certificate

	return req.ValidateAndAccept(secondaryCA, usage)
}

// ApproveClientCertificateSigningRequest processes the provided CertificateRequest
// returning a new Certificate Authority
// which has being signed by this root CA.
// All received signed by this method receive ExtKeyUsageClientAuth alone.
func (ca CertificateAuthority) ApproveClientCertificateSigningRequest(req *CertificateRequest, lifeTime time.Duration) error {
	var secondaryCA SecondaryCertificateAuthority

	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template, err := ca.initCertificateRequest(req, lifeTime, usage)
	if err != nil {
		return err
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, template.PublicKey, ca.PrivateKey)
	if err != nil {
		return err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return err
	}

	secondaryCA.RootCA = ca.Certificate
	secondaryCA.Certificate = certificate

	return req.ValidateAndAccept(secondaryCA, usage)
}

// initCertificateRequests initializes the certificate template needed for the request, generating
// necessary certificate and attaching to request object.
func (ca CertificateAuthority) initCertificateRequest(creq *CertificateRequest, lifeTime time.Duration, usages []x509.ExtKeyUsage) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	before := time.Now()
	req := creq.Request

	var template x509.Certificate
	template.NotBefore = before
	template.ExtKeyUsage = usages
	template.Subject = req.Subject
	template.DNSNames = req.DNSNames
	template.Signature = req.Signature
	template.PublicKey = req.PublicKey
	template.Extensions = req.Extensions
	template.SerialNumber = serialNumber
	template.IPAddresses = req.IPAddresses
	template.Issuer = ca.Certificate.Subject
	template.NotAfter = before.Add(lifeTime)
	template.EmailAddresses = req.EmailAddresses
	template.ExtraExtensions = req.ExtraExtensions
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.SignatureAlgorithm = req.SignatureAlgorithm
	template.PublicKeyAlgorithm = req.PublicKeyAlgorithm

	return &template, nil
}

// PrivateKeyRaw returns the raw version of the certificate's private key.
func (ca CertificateAuthority) PrivateKeyRaw() ([]byte, error) {
	if ca.PrivateKey == nil {
		return nil, ErrNoPrivateKey
	}

	return EncodePrivateKey(ca.PrivateKey)
}

// CertificateRaw returns the raw version of the certificate.
func (ca CertificateAuthority) CertificateRaw() ([]byte, error) {
	if ca.Certificate == nil {
		return nil, ErrNoCertificate
	}
	return EncodeCertificate(ca.Certificate)
}

// TLSCertPool returns a new CertPool which contains the certificate for the CA which can
// be used on a Client net.Conn or tls Connection to validate against the
// usage of the certificate for the request to be valid on the server using the same certificate.
func (ca *CertificateAuthority) TLSCertPool() (*x509.CertPool, error) {
	certPEM, err := ca.CertificateRaw()
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(certPEM); !ok {
		return nil, ErrFailedToAddCertToPool
	}

	return pool, nil
}

// TLSCert returns a new tls.Certificate made from the certificate and private key
// of the CA.
func (ca *CertificateAuthority) TLSCert() (tls.Certificate, error) {
	certbytes, err := ca.CertificateRaw()
	if err != nil {
		return tls.Certificate{}, err
	}

	keybytes, err := ca.PrivateKeyRaw()
	if err != nil {
		return tls.Certificate{}, err
	}

	tlsCert, err := tls.X509KeyPair(certbytes, keybytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tlsCert, nil
}

// CertificateAuthorityProfile holds authority profile data which are used to
// annotate a CA.
type CertificateAuthorityProfile struct {
	Organization string `json:"org"`
	Country      string `json:"country"`
	Province     string `json:"province"`
	Local        string `json:"local"`
	Address      string `json:"address"`
	Postal       string `json:"postal"`
	CommonName   string `json:"common_name"`

	// PrivateKey is for optional generated private to be used
	// instead of the the generating one for the request profile.
	// If this is present the PrivateKeyType, ECCurve and RSAKeyStrength
	// will be ignored.
	PrivateKey crypto.PrivateKey

	// PrivateKeyType defines the expected private key to
	// be used to create the ca key. See private key type
	// constants.
	PrivateKeyType PrivateKeyType

	// ECCurve defines the curve to use for a ECDSA key type.
	ECCurve elliptic.Curve

	// RSAStrength defines the strength to the use of the key type.
	RSAKeyStrength int

	// Version field of certificate request.
	Version int

	// Lifetime of certificate authority.
	LifeTime time.Duration

	// SignatureAlgorithm for creating certificates with.
	SignatureAlgorithm x509.SignatureAlgorithm

	KeyUsages []x509.ExtKeyUsage
	Emails    []string
	IPs       []string

	// General list of DNSNames for certificate.
	DNSNames []string

	// DNSNames to be excluded.
	ExedDNSNames []string

	// DNSNames to be permitted.
	PermDNSNames []string
}

// CreateCertificateAuthority returns a new instance of Certificate Authority which implements the
// the necessary interface to write given certificate data into memory or
// into a given store.
func CreateCertificateAuthority(cas CertificateAuthorityProfile) (CertificateAuthority, error) {
	if cas.ECCurve == nil {
		cas.ECCurve = elliptic.P384()
	}

	if cas.RSAKeyStrength <= 2048 {
		cas.RSAKeyStrength = 2048
	}

	var err error
	var ca CertificateAuthority

	if cas.PrivateKey == nil {
		switch cas.PrivateKeyType {
		case RSAKeyType:
			ca.PrivateKey, ca.PublicKey, err = CreateRSAKey(cas.RSAKeyStrength)
			if err != nil {
				return ca, err
			}

		case ECDSAKeyType:
			ca.PrivateKey, ca.PublicKey, err = CreateECKey(cas.ECCurve)
			if err != nil {
				return ca, err
			}
		}

		ca.KeyType = cas.PrivateKeyType
	} else {
		switch ky := cas.PrivateKey.(type) {
		case *rsa.PrivateKey:
			ca.PrivateKey = ky
			ca.KeyType = RSAKeyType
			ca.PublicKey = ky.PublicKey
		case *ecdsa.PrivateKey:
			ca.PrivateKey = ky
			ca.KeyType = ECDSAKeyType
			ca.PublicKey = ky.PublicKey
		default:
			return ca, ErrUnknownPrivateKeyType
		}
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return ca, err
	}

	ca.KeyType = cas.PrivateKeyType
	if cas.SignatureAlgorithm <= 0 {
		cas.SignatureAlgorithm = x509.SHA256WithRSA
	}

	var ips []net.IP

	for _, ip := range cas.IPs {
		ips = append(ips, net.ParseIP(ip))
	}

	before := time.Now()

	var profile pkix.Name
	profile.CommonName = cas.CommonName
	profile.Organization = []string{cas.Organization}
	profile.Country = []string{cas.Country}
	profile.Province = []string{cas.Province}
	profile.Locality = []string{cas.Local}
	profile.StreetAddress = []string{cas.Address}
	profile.PostalCode = []string{cas.Postal}

	var template x509.Certificate
	template.Version = cas.Version
	template.IsCA = true
	template.IPAddresses = ips
	template.Subject = profile
	template.NotBefore = before
	template.SerialNumber = serial
	template.DNSNames = cas.DNSNames
	template.EmailAddresses = cas.Emails
	template.BasicConstraintsValid = true
	template.NotAfter = before.Add(cas.LifeTime)
	template.ExcludedDNSDomains = cas.ExedDNSNames
	template.SignatureAlgorithm = cas.SignatureAlgorithm
	template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	template.ExtKeyUsage = append([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, cas.KeyUsages...)

	if len(cas.PermDNSNames) != 0 {
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = cas.PermDNSNames
	}

	certData, err := x509.CreateCertificate(rand.Reader, &template, &template, ca.PublicKey, ca.PrivateKey)
	if err != nil {
		return ca, err
	}

	parsedCertificate, err := x509.ParseCertificate(certData)
	if err != nil {
		return ca, err
	}

	ca.Certificate = parsedCertificate

	return ca, nil
}

//********************************************************************************************
// CertificateRequestProfile Implementation
//********************************************************************************************

// CertificateRequestProfile generates a certificate request with associated private key
// and public key, which can be sent over the wire or directly to a CeritificateAuthority
// for signing.
type CertificateRequestProfile struct {
	Organization string `json:"org"`
	Country      string `json:"country"`
	Province     string `json:"province"`
	Local        string `json:"local"`
	Address      string `json:"address"`
	Postal       string `json:"postal"`
	CommonName   string `json:"common_name"`

	// PrivateKey is for optional generated private to be used
	// instead of the the generating one for the request profile.
	// If this is present the PrivateKeyType, ECCurve and RSAKeyStrength
	// will be ignored.
	PrivateKey crypto.PrivateKey

	// PrivateKeyType defines the expected private key to
	// be used to create the ca key. See private key type
	// constants.
	PrivateKeyType PrivateKeyType

	// ECCurve defines the curve to use for a ECDSA key type.
	ECCurve elliptic.Curve

	// RSAStrength defines the strength to the use of the key type.
	RSAKeyStrength int

	// SignatureAlgorithm for creating certificates with.
	SignatureAlgorithm x509.SignatureAlgorithm

	// Version field of certificate request.
	Version int

	// Emails and ip address allowed.
	Emails []string
	IPs    []string

	// General list of DNSNames for certificate.
	DNSNames []string

	// DNSNames to be excluded.
	ExDNSNames []string

	// DNSNames to be permitted.
	PermDNSNames []string
}

// New returns a new instance of Certificate Authority which implements the
// the necessary interface to write given certificate data into memory or
// into a given store.
func CreateCertificateRequest(cas CertificateRequestProfile) (CertificateRequest, error) {
	if cas.ECCurve == nil {
		cas.ECCurve = elliptic.P384()
	}

	if cas.RSAKeyStrength <= 2048 {
		cas.RSAKeyStrength = 2048
	}

	var err error
	var ca CertificateRequest

	if cas.PrivateKey == nil {
		switch cas.PrivateKeyType {
		case RSAKeyType:
			ca.PrivateKey, ca.PublicKey, err = CreateRSAKey(cas.RSAKeyStrength)
			if err != nil {
				return ca, err
			}

		case ECDSAKeyType:
			ca.PrivateKey, ca.PublicKey, err = CreateECKey(cas.ECCurve)
			if err != nil {
				return ca, err
			}
		}

		ca.KeyType = cas.PrivateKeyType
	} else {
		switch ky := cas.PrivateKey.(type) {
		case *rsa.PrivateKey:
			ca.PrivateKey = ky
			ca.KeyType = RSAKeyType
			ca.PublicKey = ky.PublicKey
		case *ecdsa.PrivateKey:
			ca.PrivateKey = ky
			ca.KeyType = ECDSAKeyType
			ca.PublicKey = ky.PublicKey
		default:
			return ca, ErrUnknownPrivateKeyType
		}
	}

	if cas.SignatureAlgorithm <= 0 {
		cas.SignatureAlgorithm = x509.SHA256WithRSA
	}

	var ips []net.IP

	for _, ip := range cas.IPs {
		ips = append(ips, net.ParseIP(ip))
	}

	var profile pkix.Name
	profile.CommonName = cas.CommonName
	profile.Organization = []string{cas.Organization}
	profile.Country = []string{cas.Country}
	profile.Province = []string{cas.Province}
	profile.Locality = []string{cas.Local}
	profile.StreetAddress = []string{cas.Address}
	profile.PostalCode = []string{cas.Postal}

	var template x509.CertificateRequest
	template.Version = cas.Version
	template.IPAddresses = ips
	template.Subject = profile
	template.DNSNames = cas.DNSNames
	template.EmailAddresses = cas.Emails
	template.SignatureAlgorithm = cas.SignatureAlgorithm

	certData, err := x509.CreateCertificateRequest(rand.Reader, &template, ca.PrivateKey)
	if err != nil {
		return ca, err
	}

	parsedRequest, err := x509.ParseCertificateRequest(certData)
	if err != nil {
		return ca, err
	}

	ca.Request = parsedRequest

	return ca, nil
}

// CertificateRequest defines a struct which contains a generated certificate request template with
// associated private and public keys.
type CertificateRequest struct {
	KeyType     PrivateKeyType
	PrivateKey  interface{}
	PublicKey   interface{}
	Request     *x509.CertificateRequest
	SecondaryCA SecondaryCertificateAuthority
}

// RequestRaw returns the raw bytes that make up the request.
func (ca CertificateRequest) RequestRaw() ([]byte, error) {
	if ca.Request == nil {
		return nil, ErrNoCertificateRequest
	}

	return EncodeCertificateRequest(ca.Request)
}

// PrivateKeyRaw returns the raw version of the certificate's private key.
func (ca CertificateRequest) PrivateKeyRaw() ([]byte, error) {
	if ca.PrivateKey == nil {
		return nil, ErrNoPrivateKey
	}

	return EncodePrivateKey(ca.PrivateKey)
}

// IsValid validates that Certificate is still valid with rootCA with accordance to usage.
func (ca *CertificateRequest) IsValid(keyUsage []x509.ExtKeyUsage) error {
	certpool := x509.NewCertPool()
	certpool.AddCert(ca.SecondaryCA.RootCA)

	options := x509.VerifyOptions{Roots: certpool, KeyUsages: keyUsage}
	if _, err := ca.SecondaryCA.Certificate.Verify(options); err != nil {
		return err
	}
	return nil
}

// ValidateAndAccept takes the provided request response and rootCA, validating the fact that the certifcate comes from the rootCA
// before setting the certificate has the certificate and setting the rootCA has it's RootCA. You must take care to ensure
// this incoming ones match the Certificate request data.
// It uses Sha256
func (ca *CertificateRequest) ValidateAndAccept(sec SecondaryCertificateAuthority, keyUsage []x509.ExtKeyUsage) error {
	if sec.Certificate.SignatureAlgorithm != ca.Request.SignatureAlgorithm {
		return ErrWrongSignatureAlgorithmn
	}

	certpool := x509.NewCertPool()
	certpool.AddCert(sec.RootCA)

	options := x509.VerifyOptions{Roots: certpool, KeyUsages: keyUsage}
	if _, err := sec.Certificate.Verify(options); err != nil {
		return err
	}

	ca.SecondaryCA = sec
	return nil
}

// TLSClientConfig returns a tls.Config which contains the certificate for the CertificateRequest and
// has it's tls.Config.ClientCAs pool set to the root certificate.
// WARNING: Use this for client connections wishing to use tls certificates. Its a helper method.
func (ca *CertificateRequest) TLSClientConfig() (*tls.Config, error) {
	pool, err := ca.TLSCertPool()
	if err != nil {
		return nil, err
	}

	return ca.TLSConfigWithRootCA(pool, false)
}

// TLSServerConfig returns a tls.Config which contains the certificate for the CertificateRequest and
// has it's tls.Config.ClientCAs pool set to the root certificate.
// WARNING: Use this for server connections wishing to use tls certificates. Its a helper method.
func (ca *CertificateRequest) TLSServerConfig(verifyClient bool) (*tls.Config, error) {
	pool, err := ca.TLSCertPool()
	if err != nil {
		return nil, err
	}

	return ca.TLSConfigWithClientCA(pool, verifyClient)
}

// TLSConfigWithRootCA returns a tls.Config which receives the tls.Certificate from TLSCert()
// and uses that for tls authentication and encryption. It uses the provided CertPool has the
// RootCAs for the tlsConfig returned.
// Use this to generate tls.Config for the server receiving client connection to ensure client
// certificate are confirmed.
// Warning: This sets the tls.Config.RootCA.
func (ca *CertificateRequest) TLSConfigWithRootCA(rootCAPool *x509.CertPool, verifyClient bool) (*tls.Config, error) {
	tlsCert, err := ca.TLSCert()
	if err != nil {
		return nil, err
	}

	var tlsConfig tls.Config
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
	tlsConfig.RootCAs = rootCAPool

	if verifyClient {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return &tlsConfig, nil
}

// TLSConfigWithClientCA returns a tls.Config which receives the tls.Certificate from TLSCert()
// and uses that for tls authentication and encryption. It uses the provided CertPool has the
// ClientCA for the tlsConfig returned.
// Use this to generate tls.Config for the client connecting to a tls Server that requires client
// certification.
// Warning: This sets the tls.Config.ClientCA.
func (ca *CertificateRequest) TLSConfigWithClientCA(clientCAPool *x509.CertPool, verifyClient bool) (*tls.Config, error) {
	tlsCert, err := ca.TLSCert()
	if err != nil {
		return nil, err
	}

	var tlsConfig tls.Config
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
	tlsConfig.ClientCAs = clientCAPool

	if verifyClient {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return &tlsConfig, nil
}

// TLSCertPool returns a new CertPool which contains the root CA which can
// be used on a Client net.Conn or tls Connection to validate against the
// usage of the certificate for the request to be valid.
func (ca *CertificateRequest) TLSCertPool() (*x509.CertPool, error) {
	rootPEM, err := ca.SecondaryCA.RootCertificateRaw()
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(rootPEM); !ok {
		return nil, ErrFailedToAddCertToPool
	}

	return pool, nil
}

// TLSCert returns a new tls.Certificate made from the certificate and private key
// of the CAR.
func (ca *CertificateRequest) TLSCert() (tls.Certificate, error) {
	certbytes, err := ca.SecondaryCA.CertificateRaw()
	if err != nil {
		return tls.Certificate{}, err
	}

	keybytes, err := ca.PrivateKeyRaw()
	if err != nil {
		return tls.Certificate{}, err
	}

	tlsCert, err := tls.X509KeyPair(certbytes, keybytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tlsCert, nil
}

//********************************************************************************************
// Private Key Generation
//********************************************************************************************

// GetPrivateKeyType returns the PrivateKeyType type which represents the
// provided crypto key.
func GetPrivateKeyType(privateKey crypto.PrivateKey) PrivateKeyType {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return RSAKeyType
	case *ecdsa.PrivateKey:
		return ECDSAKeyType
	default:
		return UnknownType
	}
}

// CreateRSAKey defines a function which will return a private and public key, and any
// error that may occur. It uses the strength argument if the key type is for rsa and uses
// the curve argument if it's a ecdsa key type.
func CreateRSAKey(strength int) (privateKey interface{}, publicKey interface{}, err error) {
	pkey, perr := rsa.GenerateKey(rand.Reader, strength)
	if perr != nil {
		err = perr
		return
	}

	privateKey = pkey
	publicKey = &pkey.PublicKey
	return
}

// CreateECKey defines a function which will return a private and public key using the ecdsa generator.
func CreateECKey(curve elliptic.Curve) (privateKey interface{}, publicKey interface{}, err error) {
	pkey, perr := ecdsa.GenerateKey(curve, rand.Reader)
	if perr != nil {
		err = perr
		return
	}

	privateKey = pkey
	publicKey = &pkey.PublicKey
	return
}

//*********************************************************************************
// Encode Functions
//*********************************************************************************

// EncodeCertificate returns the raw version of the certificate and
// any error it encountered. Certificate is encoded into a pem.Block.
func EncodeCertificate(ca *x509.Certificate) ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  certTypeName,
		Bytes: ca.Raw,
	}), nil
}

// EncodeCertificateRequest returns the raw version of the certificate request
// and any error it encountered. Certificate is encoded into a pem.Block.
func EncodeCertificateRequest(ca *x509.CertificateRequest) ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  certReqTypeName,
		Bytes: ca.Raw,
	}), nil
}

// EncodePrivateKey returns the raw version of a private key and
// any error it encountered. Certificate is encoded into a pem.Block.
func EncodePrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	ktype := GetPrivateKeyType(privateKey)
	switch ktype {
	case RSAKeyType:
		pkey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidRSAKey
		}

		return pem.EncodeToMemory(&pem.Block{
			Type:    ktype.String(),
			Bytes:   x509.MarshalPKCS1PrivateKey(pkey),
			Headers: map[string]string{"type": ktype.String()},
		}), nil
	case ECDSAKeyType:
		pkey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidECDSAKey
		}

		encoded, err := x509.MarshalECPrivateKey(pkey)
		if !ok {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{
			Type:  ktype.String(),
			Bytes: encoded,
		}), nil
	}

	return nil, ErrUnknownPrivateKeyType
}

//*********************************************************************************
// Decode Functions
//*********************************************************************************

// DecodeCertificate returns the raw version of the certificate and
// any error it encountered. Certificate is encoded into a pem.Block.
// This will discards the provided extra data found in a pem encoded
// certificate block.
func DecodeCertificate(data []byte) (*x509.Certificate, error) {
	certBlock, _ := pem.Decode(data)
	if certBlock.Type != certTypeName {
		return nil, ErrNoCertificate
	}

	return x509.ParseCertificate(certBlock.Bytes)
}

// DecodeCertificateRequest returns the raw version of the certificate request
// and any error it encountered. Certificate is encoded into a pem.Block.
// This will discards the provided extra data found in a pem encoded
// certificate request block.
func DecodeCertificateRequest(d []byte) (*x509.CertificateRequest, error) {
	certBlock, _ := pem.Decode(d)
	if certBlock.Type != certReqTypeName {
		return nil, ErrNoCertificateRequest
	}

	return x509.ParseCertificateRequest(certBlock.Bytes)
}

// DecodePrivateKey returns the raw version of a private key and
// any error it encountered. Certificate is encoded into a pem.Block.
// This will discards the provided extra data found in a pem encoded
// certificate request block.
func DecodePrivateKey(d []byte) (PrivateKeyType, crypto.PrivateKey, error) {
	certBlock, _ := pem.Decode(d)
	pkeyType := ToPrivateKeyType(certBlock.Type)

	switch pkeyType {
	case RSAKeyType:
		pkey, err := x509.ParsePKCS1PrivateKey(certBlock.Bytes)
		return pkeyType, pkey, err
	case ECDSAKeyType:
		pkey, err := x509.ParseECPrivateKey(certBlock.Bytes)
		return pkeyType, pkey, err
	}

	return pkeyType, nil, ErrUnknownPrivateKeyType
}
