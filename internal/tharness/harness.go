package tharness

import (
	"testing"

	"github.com/wirekit/tlsfs"
)

// RunTLSFSTestHarness provides a generic test harness that works to
// test an implementation of the tlsfs.TLSFS interface. It attempts to
// ensure that all expected behaviour is valid.
func RunTLSFSTestHarness(t *testing.T, fs tlsfs.TLSFS) {
	testForDomainRevoke(t, fs)
	testForDomainRenewal(t, fs)
	testForDomainCreation(t, fs)
	testForDomainUserRetrieve(t, fs)
	testForDomainCertificateRetrieve(t, fs)
	testForDomainAllCertificatesRetrieval(t, fs)
}

func testForDomainCreation(t *testing.T, fs tlsfs.TLSFS) {

}

func testForDomainRenewal(t *testing.T, fs tlsfs.TLSFS)                  {}
func testForDomainRevoke(t *testing.T, fs tlsfs.TLSFS)                   {}
func testForDomainUserRetrieve(t *testing.T, fs tlsfs.TLSFS)             {}
func testForDomainCertificateRetrieve(t *testing.T, fs tlsfs.TLSFS)      {}
func testForDomainAllCertificatesRetrieval(t *testing.T, fs tlsfs.TLSFS) {}
