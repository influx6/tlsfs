package tharness

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync"
	"testing"
	"time"

	"fmt"

	"github.com/influx6/faux/netutils"
	"github.com/influx6/faux/tests"
	"github.com/stretchr/testify/assert"
	"github.com/wirekit/tlsfs"
	"github.com/wirekit/tlsfs/certificates"
	"github.com/wirekit/tlsfs/tlsp/owned"
)

// RunTLSFSTestHarness provides a generic test harness that works to
// test an implementation of the tlsfs.TLSFS interface. It attempts to
// ensure that all expected behaviour is valid.
func RunTLSFSTestHarness(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	testForDomainCreation(t, fs, domain, email)
	testForDomainSubCACreation(t, fs, domain, email)
	testForDomainCreationWithCSRForExistingUserDomain(t, fs, domain, email)
	testForDomainCreationWithCSR(t, fs, domain, email)
	testForDomainUserRetrieve(t, fs, domain, email)
	testForDomainCertificateRetrieve(t, fs, domain, email)
	testForDomainRenewal(t, fs, domain, email)
	testForDomainAllCertificatesRetrieval(t, fs, domain, email)
	testForDomainRevoke(t, fs, domain, email)
}

func RunCertificateWithTwoCA(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	testValidCertWithTwoTFS(t, fs, domain, email)
	testValidCertWithTwoTFSAndSubCA(t, fs, domain, email)
}

func testValidCertWithTwoTFSAndSubCA(t *testing.T, fx tlsfs.TLSFS, domain string, email string) {
	tests.Header("Use Certificate and CA for two trusted CA and SubCA on domain")

	var wg sync.WaitGroup
	wg.Add(1)

	subCAcct := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: "RACK CA",
		Email:      "subca@ca.com",
		Domain:     "rackiwas.com",
		KeyType:    tlsfs.ECKey384,
	}

	subCA, _, err := fx.CreateCA(subCAcct, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	encoded, err := certificates.EncodeCertificate(subCA.Certificate)
	if err != nil {
		tests.FailedWithError(err, "Should have created tls.certificate")
	}
	tests.Passed("Should have created tls.certificate")

	subCAUser, err := fx.GetUser("subca@ca.com")
	if err != nil {
		tests.FailedWithError(err, "Should have retrieved certificate user")
	}
	tests.Passed("Should have retrieved certificate user")

	rx, err := owned.FromCA(subCA.Certificate, subCAUser.GetPrivateKey(), time.Minute*30)
	if err != nil {
		tests.FailedWithError(err, "Should have created sub ca")
	}
	tests.Passed("Should have created sub ca")

	acct := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: "RACK",
		Email:      email,
		Domain:     domain,
		KeyType:    tlsfs.ECKey384,
	}

	testimony, _, err := rx.Create(acct, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	testimonyUser, err := rx.GetUser(email)
	if err != nil {
		tests.FailedWithError(err, "Should have retrieved certificate user")
	}
	tests.Passed("Should have retrieved certificate user")

	tlsCert, err := certificates.MakeTLSCertificate(testimony.Certificate, testimonyUser.GetPrivateKey())
	if err != nil {
		tests.FailedWithError(err, "Should have created tls.certificate")
	}
	tests.Passed("Should have created tls.certificate")

	acct2 := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: "UL CA",
		Domain:     domain,
		Email:      email,
		KeyType:    tlsfs.ECKey384,
	}

	fs, err := owned.BasicFS("WAAA", 3*time.Hour, 30*time.Minute)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate CA")
	}
	tests.Passed("Should have successfully created certificate CA")

	testimony2, _, err := fs.Create(acct2, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	testimonyUser2, err := fs.GetUser(email)
	if err != nil {
		tests.FailedWithError(err, "Should have retrieved certificate user")
	}
	tests.Passed("Should have retrieved certificate user")

	tlsCert2, err := certificates.MakeTLSCertificate(testimony2.Certificate, testimonyUser2.GetPrivateKey())
	if err != nil {
		tests.FailedWithError(err, "Should have created tls.certificate")
	}
	tests.Passed("Should have created tls.certificate")

	decoded, err := certificates.DecodeCertificate(encoded)
	if err != nil {
		tests.FailedWithError(err, "Should have created tls.certificate")
	}
	tests.Passed("Should have created tls.certificate")

	pool := x509.NewCertPool()
	pool.AddCert(subCA.Certificate)

	config := new(tls.Config)
	config.ClientCAs = pool
	config.MinVersion = tls.VersionTLS12
	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.Certificates = append(config.Certificates, tlsCert)
	config.BuildNameToCertificate()

	addr := netutils.ResolveAddr("0.0.0.0:0")
	network, err := tls.Listen("tcp", addr, config)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created listener")
	}
	tests.Passed("Should have successfully created listener")

	go func() {
		defer wg.Done()
		for {
			newConn, err := network.Accept()
			if err != nil {
				return
			}

			msg := make([]byte, 512)
			n, err := newConn.Read(msg)
			if err != nil {
				newConn.Close()
				return
			}

			fmt.Fprint(newConn, string(msg[:n]))

			<-time.After(time.Second * 2)
			newConn.Close()
			return
		}
	}()

	pool2 := x509.NewCertPool()
	pool2.AddCert(decoded)

	clientConfig := new(tls.Config)
	clientConfig.RootCAs = pool2
	clientConfig.ServerName = domain
	clientConfig.MinVersion = tls.VersionTLS12
	clientConfig.Certificates = append(config.Certificates, tlsCert2)
	clientConfig.BuildNameToCertificate()

	conn, err := tls.Dial("tcp", addr, clientConfig)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully connected to server")
	}
	tests.Passed("Should have successfully connected to server")

	hello := "Hello\r\n"
	if _, err := fmt.Fprintf(conn, hello); err != nil {
		tests.FailedWithError(err, "Should have written to connection")
	}
	tests.Passed("Should have written to connection")

	msg := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err := conn.Read(msg)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully read from connection")
	}
	tests.Passed("Should have successfully read from connection")

	if hello != string(msg[:n]) {
		tests.Failed("Should have matched sent message")
	}
	tests.Passed("Should have matched sent message")

	conn.Close()
	wg.Wait()
	network.Close()

	if err := fs.Revoke(email, domain); err != nil {
		tests.FailedWithError(err, "Should have revoked certificate")
	}
	tests.Passed("Should have revoked certificate")
}

func testValidCertWithTwoTFS(t *testing.T, fx tlsfs.TLSFS, domain string, email string) {
	tests.Header("Use Certificate and CA for two trusted CA on domain")

	var wg sync.WaitGroup
	wg.Add(1)

	acct := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: "RACK",
		Email:      email,
		Domain:     domain,
		KeyType:    tlsfs.ECKey384,
	}

	testimony, _, err := fx.Create(acct, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	testimonyUser, err := fx.GetUser(email)
	if err != nil {
		tests.FailedWithError(err, "Should have retrieved certificate user")
	}
	tests.Passed("Should have retrieved certificate user")

	tlsCert, err := certificates.MakeTLSCertificate(testimony.Certificate, testimonyUser.GetPrivateKey())
	if err != nil {
		tests.FailedWithError(err, "Should have created tls.certificate")
	}
	tests.Passed("Should have created tls.certificate")

	acct2 := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: "RACKI",
		Domain:     domain,
		Email:      "rz@domain.com",
		KeyType:    tlsfs.ECKey384,
	}

	fs, err := owned.BasicFS("WAAA", 3*time.Hour, 30*time.Minute)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate CA")
	}
	tests.Passed("Should have successfully created certificate CA")

	testimony2, _, err := fs.Create(acct2, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	testimonyUser2, err := fs.GetUser("rz@domain.com")
	if err != nil {
		tests.FailedWithError(err, "Should have retrieved certificate user")
	}
	tests.Passed("Should have retrieved certificate user")

	tlsCert2, err := certificates.MakeTLSCertificate(testimony2.Certificate, testimonyUser2.GetPrivateKey())
	if err != nil {
		tests.FailedWithError(err, "Should have created tls.certificate")
	}
	tests.Passed("Should have created tls.certificate")

	pool := x509.NewCertPool()
	pool.AddCert(testimony.IssuerCertificate)

	config := new(tls.Config)
	config.ClientCAs = pool
	config.MinVersion = tls.VersionTLS12
	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.Certificates = append(config.Certificates, tlsCert)
	config.BuildNameToCertificate()

	addr := netutils.ResolveAddr("0.0.0.0:0")

	network, err := tls.Listen("tcp", addr, config)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created listener")
	}
	tests.Passed("Should have successfully created listener")

	go func() {
		defer wg.Done()
		for {
			newConn, err := network.Accept()
			if err != nil {
				return
			}

			msg := make([]byte, 512)
			n, err := newConn.Read(msg)
			if err != nil {
				newConn.Close()
				return
			}

			fmt.Fprint(newConn, string(msg[:n]))

			<-time.After(time.Second * 2)
			newConn.Close()
			return
		}
	}()

	pool2 := x509.NewCertPool()
	pool2.AddCert(testimony.IssuerCertificate)
	clientConfig := new(tls.Config)
	clientConfig.RootCAs = pool2
	clientConfig.ServerName = domain
	clientConfig.MinVersion = tls.VersionTLS12
	clientConfig.Certificates = append(config.Certificates, tlsCert2)
	clientConfig.BuildNameToCertificate()

	conn, err := tls.Dial("tcp", addr, clientConfig)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully connected to server")
	}
	tests.Passed("Should have successfully connected to server")

	hello := "Hello\r\n"
	if _, err := fmt.Fprintf(conn, hello); err != nil {
		tests.FailedWithError(err, "Should have written to connection")
	}
	tests.Passed("Should have written to connection")

	msg := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err := conn.Read(msg)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully read from connection")
	}
	tests.Passed("Should have successfully read from connection")

	if hello != string(msg[:n]) {
		tests.Failed("Should have matched sent message")
	}
	tests.Passed("Should have matched sent message")

	conn.Close()
	wg.Wait()
	network.Close()

	if err := fs.Revoke(email, domain); err != nil {
		tests.FailedWithError(err, "Should have revoked certificate")
	}
	tests.Passed("Should have revoked certificate")
}

func CertificateConnectionTestHarness(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	testForGetCertificate(t, fs, domain, email)
	testForGetCertificateWithTrustedCert(t, fs, domain, email)
	testForGetCertificateWithTwoTrustedCert(t, fs, domain, email)
}

func testForGetCertificateWithTwoTrustedCert(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Use Certificate and CA for two trusted domain")

	var wg sync.WaitGroup
	wg.Add(1)

	acct := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: domain,
		Email:      email,
		Domain:     domain,
		KeyType:    tlsfs.ECKey384,
	}

	testimony, _, err := fs.Create(acct, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	acct2 := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: domain,
		Domain:     domain,
		Email:      "rz@domain.com",
		KeyType:    tlsfs.ECKey384,
	}

	testimony2, _, err := fs.Create(acct2, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	testimonyUser, err := fs.GetUser(email)
	if err != nil {
		tests.FailedWithError(err, "Should have retrieved certificate user")
	}
	tests.Passed("Should have retrieved certificate user")

	testimonyUser2, err := fs.GetUser("rz@domain.com")
	if err != nil {
		tests.FailedWithError(err, "Should have retrieved certificate user")
	}
	tests.Passed("Should have retrieved certificate user")

	tlsCert, err := certificates.MakeTLSCertificate(testimony.Certificate, testimonyUser.GetPrivateKey())
	if err != nil {
		tests.FailedWithError(err, "Should have created tls.certificate")
	}
	tests.Passed("Should have created tls.certificate")

	tlsCert2, err := certificates.MakeTLSCertificate(testimony2.Certificate, testimonyUser2.GetPrivateKey())
	if err != nil {
		tests.FailedWithError(err, "Should have created tls.certificate")
	}
	tests.Passed("Should have created tls.certificate")

	pool := x509.NewCertPool()
	pool.AddCert(testimony.IssuerCertificate)

	config := new(tls.Config)
	config.ClientCAs = pool
	config.ServerName = domain
	config.MinVersion = tls.VersionTLS12
	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.Certificates = append(config.Certificates, tlsCert)
	config.BuildNameToCertificate()

	addr := netutils.ResolveAddr("0.0.0.0:0")

	network, err := tls.Listen("tcp", addr, config)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created listener")
	}
	tests.Passed("Should have successfully created listener")

	go func() {
		defer wg.Done()
		for {
			newConn, err := network.Accept()
			if err != nil {
				return
			}

			msg := make([]byte, 512)
			n, err := newConn.Read(msg)
			if err != nil {
				newConn.Close()
				return
			}

			fmt.Fprint(newConn, string(msg[:n]))

			<-time.After(time.Second * 2)
			newConn.Close()
			return
		}
	}()

	clientConfig := new(tls.Config)
	clientConfig.RootCAs = pool
	clientConfig.ServerName = domain
	clientConfig.MinVersion = tls.VersionTLS12
	clientConfig.Certificates = append(config.Certificates, tlsCert2)
	clientConfig.BuildNameToCertificate()

	conn, err := tls.Dial("tcp", addr, clientConfig)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully connected to server")
	}
	tests.Passed("Should have successfully connected to server")

	hello := "Hello\r\n"
	if _, err := fmt.Fprintf(conn, hello); err != nil {
		tests.FailedWithError(err, "Should have written to connection")
	}
	tests.Passed("Should have written to connection")

	msg := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err := conn.Read(msg)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully read from connection")
	}
	tests.Passed("Should have successfully read from connection")

	if hello != string(msg[:n]) {
		tests.Failed("Should have matched sent message")
	}
	tests.Passed("Should have matched sent message")

	conn.Close()
	wg.Wait()
	network.Close()

	if err := fs.Revoke(email, domain); err != nil {
		tests.FailedWithError(err, "Should have revoked certificate")
	}
	tests.Passed("Should have revoked certificate")
}

func testForGetCertificateWithTrustedCert(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Use Certificate and CA for trusted domain")

	var wg sync.WaitGroup
	wg.Add(1)

	acct := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: domain,
		Email:      email,
		Domain:     domain,
		KeyType:    tlsfs.ECKey384,
	}

	testimony, _, err := fs.Create(acct, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	testimonyUser, err := fs.GetUser(email)
	if err != nil {
		tests.FailedWithError(err, "Should have retrieved certificate user")
	}
	tests.Passed("Should have retrieved certificate user")

	tlsCert, err := certificates.MakeTLSCertificate(testimony.Certificate, testimonyUser.GetPrivateKey())
	if err != nil {
		tests.FailedWithError(err, "Should have created tls.certificate")
	}
	tests.Passed("Should have created tls.certificate")

	pool := x509.NewCertPool()
	pool.AddCert(testimony.IssuerCertificate)

	config := new(tls.Config)
	config.ClientCAs = pool
	config.ServerName = domain
	config.MinVersion = tls.VersionTLS12
	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.Certificates = append(config.Certificates, tlsCert)
	config.BuildNameToCertificate()

	addr := netutils.ResolveAddr("0.0.0.0:0")

	network, err := tls.Listen("tcp", addr, config)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created listener")
	}
	tests.Passed("Should have successfully created listener")

	go func() {
		defer wg.Done()
		for {
			newConn, err := network.Accept()
			if err != nil {
				return
			}

			msg := make([]byte, 512)
			n, err := newConn.Read(msg)
			if err != nil {
				newConn.Close()
				return
			}

			fmt.Fprint(newConn, string(msg[:n]))

			<-time.After(time.Second * 2)
			newConn.Close()
			return
		}
	}()

	clientConfig := new(tls.Config)
	clientConfig.RootCAs = pool
	clientConfig.ServerName = domain
	clientConfig.MinVersion = tls.VersionTLS12
	clientConfig.Certificates = append(config.Certificates, tlsCert)
	clientConfig.BuildNameToCertificate()

	conn, err := tls.Dial("tcp", addr, clientConfig)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully connected to server")
	}
	tests.Passed("Should have successfully connected to server")

	hello := "Hello\r\n"
	if _, err := fmt.Fprintf(conn, hello); err != nil {
		tests.FailedWithError(err, "Should have written to connection")
	}
	tests.Passed("Should have written to connection")

	msg := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err := conn.Read(msg)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully read from connection")
	}
	tests.Passed("Should have successfully read from connection")

	if hello != string(msg[:n]) {
		tests.Failed("Should have matched sent message")
	}
	tests.Passed("Should have matched sent message")

	conn.Close()
	wg.Wait()
	network.Close()

	if err := fs.Revoke(email, domain); err != nil {
		tests.FailedWithError(err, "Should have revoked certificate")
	}
	tests.Passed("Should have revoked certificate")
}

func testForGetCertificate(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Get Certificate Automatically for domain")

	var wg sync.WaitGroup
	wg.Add(1)

	config := new(tls.Config)
	config.ServerName = domain
	config.MinVersion = tls.VersionTLS12
	getCertificate := fs.GetCertificate(email)
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return getCertificate(hello)
	}

	addr := netutils.ResolveAddr("0.0.0.0:0")

	network, err := tls.Listen("tcp", addr, config)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created listener")
	}
	tests.Passed("Should have successfully created listener")

	go func() {
		defer wg.Done()
		for {
			newConn, err := network.Accept()
			if err != nil {
				return
			}

			msg := make([]byte, 512)
			n, err := newConn.Read(msg)
			if err != nil {
				newConn.Close()
				return
			}

			fmt.Fprint(newConn, string(msg[:n]))

			<-time.After(time.Second * 2)
			newConn.Close()
			return
		}
	}()

	clientConfig := new(tls.Config)
	clientConfig.ServerName = domain
	clientConfig.InsecureSkipVerify = true
	clientConfig.MinVersion = tls.VersionTLS12

	conn, err := tls.Dial("tcp", addr, clientConfig)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully connected to server")
	}
	tests.Passed("Should have successfully connected to server")

	hello := "Hello\r\n"
	if _, err := fmt.Fprintf(conn, hello); err != nil {
		tests.FailedWithError(err, "Should have written to connection")
	}
	tests.Passed("Should have written to connection")

	msg := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err := conn.Read(msg)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully read from connection")
	}
	tests.Passed("Should have successfully read from connection")

	if hello != string(msg[:n]) {
		tests.Failed("Should have matched sent message")
	}
	tests.Passed("Should have matched sent message")

	conn.Close()
	wg.Wait()
	network.Close()

	if err := fs.Revoke(email, domain); err != nil {
		tests.FailedWithError(err, "Should have revoked certificate")
	}
	tests.Passed("Should have revoked certificate")
}

func testForDomainCreationWithCSRForExistingUserDomain(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Create Certificate with CSR With Existing Domain")
	requestService := certificates.CertificateRequestProfile{
		Local:        "Lagos",
		Organization: "DreamBench",
		CommonName:   domain,
		Country:      "Nigeria",
		Province:     "South-West",
		Emails:       []string{email},
	}

	requestService.RSAKeyStrength = 2048

	reqCA, err := certificates.CreateCertificateRequest(requestService)
	if err != nil {
		tests.FailedWithError(err, "Should have generated new CertificateRequest")
	}
	tests.Passed("Should have generated new CertificateRequest")

	testimony, status, err := fs.CreateWithCSR(*reqCA.Request, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	if status.Flag() != tlsfs.Live {
		tests.Info("Expected: %+q", tlsfs.Live)
		tests.Info("Received: %+q", status.Flag())
		tests.Failed("Should have successfully received acceptable certificate status")
	}
	tests.Passed("Should have successfully received acceptable certificate status")

	assert.NotNil(t, testimony.Request)
	assert.NotNil(t, testimony.Certificate)
	assert.NotNil(t, testimony.IssuerCertificate)

	distance := testimony.Certificate.NotAfter.Sub(testimony.Certificate.NotBefore)
	assert.True(t, distance >= tlsfs.ThreeMonths)
}

func testForDomainCreationWithCSR(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Create Certificate with CSR")
	domain = "wackomoilo.com"

	requestService := certificates.CertificateRequestProfile{
		Local:        "Lagos",
		Organization: "DreamBench",
		CommonName:   domain,
		Country:      "Nigeria",
		Province:     "South-West",
		Emails:       []string{email},
	}

	requestService.RSAKeyStrength = 2048

	reqCA, err := certificates.CreateCertificateRequest(requestService)
	if err != nil {
		tests.FailedWithError(err, "Should have generated new CertificateRequest")
	}
	tests.Passed("Should have generated new CertificateRequest")

	testimony, status, err := fs.CreateWithCSR(*reqCA.Request, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	if status.Flag() != tlsfs.Created {
		tests.Info("Expected: %+q", tlsfs.Created)
		tests.Info("Received: %+q", status.Flag())
		tests.Failed("Should have successfully received acceptable certificate status")
	}
	tests.Passed("Should have successfully received acceptable certificate status")

	assert.NotNil(t, testimony.Request)
	assert.NotNil(t, testimony.Certificate)
	assert.NotNil(t, testimony.IssuerCertificate)

	distance := testimony.Certificate.NotAfter.Sub(testimony.Certificate.NotBefore)
	assert.True(t, distance >= tlsfs.ThreeMonths)
}

func testForDomainSubCACreation(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Create SubCA Certificate with tlsfs.NewDomain")

	email = "wondertrux@gmail.com"
	acct := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: "*",
		Email:      email,
		Domain:     domain,
		KeyType:    tlsfs.ECKey384,
	}

	testimony, status, err := fs.CreateCA(acct, tlsfs.AgreeToTOS)
	if err != nil {
		if err == tlsfs.ErrNotSupported {
			t.Skip()
			return
		}

		tests.FailedWithError(err, "Should have successfully created certificate sub-ca for domain")
	}
	tests.Passed("Should have successfully created certificate sub-ca for domain")

	if status.Flag() != tlsfs.Created {
		tests.Info("Expected: %+q", tlsfs.Created)
		tests.Info("Received: %+q", status.Flag())
		tests.Failed("Should have successfully received acceptable certificate status")
	}
	tests.Passed("Should have successfully received acceptable certificate status")

	assert.Nil(t, testimony.Request)
	assert.NotNil(t, testimony.Certificate)
	assert.NotNil(t, testimony.IssuerCertificate)
	assert.Equal(t, testimony.User, acct.Email)
	assert.Equal(t, testimony.Domain, strings.ToLower(acct.Domain))

	distance := testimony.Certificate.NotAfter.Sub(testimony.Certificate.NotBefore)
	assert.True(t, distance >= tlsfs.ThreeMonths)
}

func testForDomainCreation(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Create Certificate with tlsfs.NewDomain")

	acct := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: "*",
		Email:      email,
		Domain:     domain,
		KeyType:    tlsfs.ECKey384,
	}

	testimony, status, err := fs.Create(acct, tlsfs.AgreeToTOS)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created certificate for domain")
	}
	tests.Passed("Should have successfully created certificate for domain")

	if status.Flag() != tlsfs.Created {
		tests.Info("Expected: %+q", tlsfs.Created)
		tests.Info("Received: %+q", status.Flag())
		tests.Failed("Should have successfully received acceptable certificate status")
	}
	tests.Passed("Should have successfully received acceptable certificate status")

	assert.NotNil(t, testimony.Request)
	assert.NotNil(t, testimony.Certificate)
	assert.NotNil(t, testimony.IssuerCertificate)
	assert.Equal(t, testimony.User, acct.Email)
	assert.Equal(t, testimony.Domain, strings.ToLower(acct.Domain))

	distance := testimony.Certificate.NotAfter.Sub(testimony.Certificate.NotBefore)
	assert.True(t, distance >= tlsfs.ThreeMonths)
}

func testForDomainRenewal(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Renew Certificate")

	renewedTestimony, state, err := fs.Renew(email, domain)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully renewed domain certificate")
	}
	tests.Passed("Should have successfully renewed domain certificate")

	if state.Flag() != tlsfs.Renewed {
		tests.Info("Expected: %+q", tlsfs.Renewed)
		tests.Info("Received: %+q", state.Flag())
		tests.Failed("Should have successfully received acceptable certificate status")
	}
	tests.Passed("Should have successfully received acceptable certificate status")

	assert.NotNil(t, renewedTestimony.Request)
	assert.NotNil(t, renewedTestimony.Certificate)
	assert.NotNil(t, renewedTestimony.IssuerCertificate)
	assert.Equal(t, renewedTestimony.User, email)
	assert.Equal(t, renewedTestimony.Domain, strings.ToLower(domain))

	distance := renewedTestimony.Certificate.NotAfter.Sub(renewedTestimony.Certificate.NotBefore)
	assert.Equal(t, distance, tlsfs.ThreeMonths)
}

func testForDomainRevoke(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Revoke Certificate")
	if err := fs.Revoke(email, domain); err != nil {
		tests.FailedWithError(err, "Should have successfully revoked domain certificate")
	}
	tests.Passed("Should have successfully revoked domain certificate")

	if _, _, err := fs.Get(email, domain); err == nil {
		tests.Failed("Should have failed to retrieve revoked certificate")
	}
	tests.Passed("Should have failed to retrieve revoked certificate")
}

func testForDomainUserRetrieve(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Retrieve User Account")

	user, err := fs.GetUser(email)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully retrieved user by email")
	}
	tests.Passed("Should have successfully retrieved user by email")

	assert.NotNil(t, user.GetPrivateKey())
	assert.NotEmpty(t, user.GetEmail())
	assert.Equal(t, user.GetEmail(), email)
}

func testForDomainCertificateRetrieve(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Retrieve User Ceritifcate by Email and Domain")
	testimony, _, err := fs.Get(email, domain)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully retrieved certificate for domain and email")
	}
	tests.Passed("Should have successfully retrieved certificate for domain and email")

	assert.NotNil(t, testimony.Request)
	assert.NotNil(t, testimony.Certificate)
	assert.NotNil(t, testimony.IssuerCertificate)
	assert.Equal(t, testimony.User, email)
	assert.Equal(t, testimony.Domain, strings.ToLower(domain))
}

func testForDomainAllCertificatesRetrieval(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Retrieve all certificates")
	domains, err := fs.All()
	if err != nil {
		tests.FailedWithError(err, "Should have successfully retrieved all certificates")
	}
	tests.Passed("Should have successfully retrieved all certificates")

	if len(domains) == 0 {
		tests.Failed("Should currently have registered domains in file system")
	}
	tests.Passed("Should currently have registered domains in file system")
}
