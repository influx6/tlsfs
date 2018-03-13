package tlsf

import "github.com/wirekit/tlsfs"

// ServerCertificates implements the tls.GetCertificates method
// by providing a structure that allows the creation of certificates
// during the initial tls hello message for a server connection.
type ServerCertificates struct {
	fs tlsfs.TLSFS
}

// ClientCertificates implements the tls.GetCertificates method
// by providing a structure that allows the creation of certificates
// during the initial tls hello message for a client connection.
type ClientCertificates struct {
}
