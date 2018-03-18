package tharness

import (
	"crypto/tls"
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
)

// RunTLSFSTestHarness provides a generic test harness that works to
// test an implementation of the tlsfs.TLSFS interface. It attempts to
// ensure that all expected behaviour is valid.
func RunTLSFSTestHarness(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	testForDomainCreation(t, fs, domain, email)
	testForDomainCreationWithCSRForExistingUserDomain(t, fs, domain, email)
	testForDomainCreationWithCSR(t, fs, domain, email)
	testForDomainUserRetrieve(t, fs, domain, email)
	testForDomainCertificateRetrieve(t, fs, domain, email)
	testForDomainRenewal(t, fs, domain, email)
	testForDomainAllCertificatesRetrieval(t, fs, domain, email)
	testForDomainRevoke(t, fs, domain, email)

	testForGetCertificate(t, fs, domain, email)
}

func testForGetCertificate(t *testing.T, fs tlsfs.TLSFS, domain string, email string) {
	tests.Header("Get Certificate Automagically for domain")

	var wg sync.WaitGroup
	wg.Add(1)

	config := new(tls.Config)
	config.ServerName = domain
	config.MinVersion = tls.VersionTLS12
	getCertificate := fs.GetCertificate(email)
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		//fmt.Printf("server::Certificate: %#v -> %+q\n", hello, hello)
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
	//clientConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	//	fmt.Printf("client::ClientCertificate: %#v -> %+q\n", info, info)
	//	return nil, nil
	//}

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
