package acme_test

import (
	"os"
	"testing"

	"github.com/wirekit/tlsfs/fs/memfs"
	"github.com/wirekit/tlsfs/fs/sysfs"
	"github.com/wirekit/tlsfs/internal/tharness"
	"github.com/wirekit/tlsfs/tlsp/acme"
)

var (
	domain    = os.Getenv("TEST_DOMAIN")
	email     = os.Getenv("TEST_DOMAIN_EMAIL")
	boulderCA = os.Getenv("BOULDER_CA_HOSTDIR")
)

func TestAcmeFSWithMemFS(t *testing.T) {
	if boulderCA == "" {
		t.Skip("Require to have letsencrypt-boulder running with env BOULDER_CA_HOSTDIR set")
		return
	}

	var config acme.Config
	config.CAURL = boulderCA
	config.HTTPChallengePort = 5002
	config.TLSSNIChallengePort = 5001
	config.EnableHTTP01Challenge = true
	config.EnableTLSSNI01Challenge = true
	config.UsersFileSystem = memfs.NewMemFS()
	config.CertificatesFileSystem = memfs.NewMemFS()

	tharness.RunTLSFSTestHarness(t, acme.NewAcmeFS(config), domain, email)
}

func TestAcmeFSWithSysFS(t *testing.T) {
	if boulderCA == "" {
		t.Skip("Require to have letsencrypt-boulder running with env BOULDER_CA_HOSTDIR set")
		return
	}

	defer os.RemoveAll("temp")

	var config acme.Config
	config.CAURL = boulderCA
	config.HTTPChallengePort = 5002
	config.TLSSNIChallengePort = 5001
	config.EnableHTTP01Challenge = true
	config.EnableTLSSNI01Challenge = true
	config.UsersFileSystem = sysfs.NewSystemZapFS("temp/acme/users")
	config.CertificatesFileSystem = sysfs.NewSystemZapFS("temp/acme/certs")
	tharness.RunTLSFSTestHarness(t, acme.NewAcmeFS(config), domain, email)
}
