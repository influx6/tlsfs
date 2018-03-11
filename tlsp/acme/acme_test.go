package acme_test

import (
	"os"
	"testing"

	"github.com/wirekit/tlsfs/fs/memfs"
	"github.com/wirekit/tlsfs/fs/sysfs"
	"github.com/wirekit/tlsfs/internal/tharness"
	"github.com/wirekit/tlsfs/tlsp/acme"
)

func TestAcmeFSWithMemFS(t *testing.T) {
	var config acme.Config
	config.HTTPChallengePort = 3550
	config.TLSSNIChallengePort = 4433
	config.EnableHTTP01Challenge = true
	config.UsersFileSystem = memfs.NewMemFS()
	config.CertificatesFileSystem = memfs.NewMemFS()
	tharness.RunTLSFSTestHarness(t, acme.NewAcmeFS(config))
}

func TestAcmeFSWithSysFS(t *testing.T) {
	defer os.RemoveAll("temp/acme")

	var config acme.Config
	config.HTTPChallengePort = 3550
	config.TLSSNIChallengePort = 4433
	config.EnableHTTP01Challenge = true
	config.UsersFileSystem = sysfs.NewSystemZapFS("temp/acme/users")
	config.CertificatesFileSystem = sysfs.NewSystemZapFS("temp/acme/certs")
	tharness.RunTLSFSTestHarness(t, acme.NewAcmeFS(config))
}
