package tharness

import (
	"strings"
	"testing"

	"github.com/influx6/faux/tests"
	"github.com/stretchr/testify/assert"
	"github.com/wirekit/tlsfs"
)

// RunTLSFSTestHarness provides a generic test harness that works to
// test an implementation of the tlsfs.TLSFS interface. It attempts to
// ensure that all expected behaviour is valid.
func RunTLSFSTestHarness(t *testing.T, fs tlsfs.TLSFS) {
	testForDomainCreation(t, fs)
	testForDomainUserRetrieve(t, fs)
	testForDomainCertificateRetrieve(t, fs)
	testForDomainRenewal(t, fs)
	testForDomainAllCertificatesRetrieval(t, fs)
	testForDomainRevoke(t, fs)
}

func testForDomainCreation(t *testing.T, fs tlsfs.TLSFS) {
	acct := tlsfs.NewDomain{
		Version:    1,
		Province:   "LG",
		CommonName: "westros",
		Email:      "thunder_cat@gmail.com",
		Domain:     "thundercat.io",
		KeyType:    tlsfs.ECKey512,
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
	assert.Equal(t, distance, tlsfs.ThreeMonths)
}

func testForDomainRenewal(t *testing.T, fs tlsfs.TLSFS) {
	email := "thunder_cat@gmail.com"
	domain := "thundercat.io"

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

func testForDomainRevoke(t *testing.T, fs tlsfs.TLSFS) {
	email := "thunder_cat@gmail.com"
	domain := "thundercat.io"

	if err := fs.Revoke(email, domain); err != nil {
		tests.FailedWithError(err, "Should have successfully revoked domain certificate")
	}
	tests.Passed("Should have successfully revoked domain certificate")

	if _, _, err := fs.Get(email, domain); err == nil {
		tests.Failed("Should have failed to retrieve revoked certificate")
	}
	tests.Passed("Should have failed to retrieve revoked certificate")
}

func testForDomainUserRetrieve(t *testing.T, fs tlsfs.TLSFS) {
	email := "thunder_cat@gmail.com"

	user, err := fs.GetUser(email)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully retrieved user by email")
	}
	tests.Passed("Should have successfully retrieved user by email")

	assert.NotNil(t, user.GetPrivateKey())
	assert.NotEmpty(t, user.GetEmail())
	assert.Equal(t, user.GetEmail(), email)
}

func testForDomainCertificateRetrieve(t *testing.T, fs tlsfs.TLSFS) {
	email := "thunder_cat@gmail.com"
	domain := "thundercat.io"

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

func testForDomainAllCertificatesRetrieval(t *testing.T, fs tlsfs.TLSFS) {
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
