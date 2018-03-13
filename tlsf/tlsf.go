package tlsf

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/wirekit/tlsfs"
)

//*****************************************************************
// ServerCertificates
//*****************************************************************

// ServerCertificates implements the tls.GetCertificates method
// by providing a structure that allows the creation of certificates
// during the initial tls hello message for a server connection.
type ServerCertificates struct {
	fs tlsfs.TLSFS
}

// GetCertificates returns retrieved certificate for the given domain according to
// the information retrieved from the tls.ClientHelloInfo.
func (s *ServerCertificates) GetCertificates(hello *tls.ClientHelloInfo) (*x509.Certificate, error) {
	var obtained *x509.Certificate
	return obtained, nil
}

//*****************************************************************
// ClientCertificates
//*****************************************************************

// ClientCertificates implements the tls.GetCertificates method
// by providing a structure that allows the creation of certificates
// during the initial tls hello message for a client connection.
type ClientCertificates struct {
}

// GetCertificates returns retrieved certificate for the given domain according to
// the information retrieved from the tls.ClientHelloInfo.
func (s *ClientCertificates) GetCertificates(hello *tls.ClientHelloInfo) (*x509.Certificate, error) {
	var obtained *x509.Certificate
	return obtained, nil
}
