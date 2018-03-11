package acme_test

import (
	"testing"

	"github.com/wirekit/tlsfs/fs/memfs"
	"github.com/wirekit/tlsfs/internal/tharness"
	"github.com/wirekit/tlsfs/tlsp/acme"
)

func TestAcmeFS(t *testing.T) {
	var config acme.Config
	config.HTTPChallengePort = 3550
	config.TLSSNIChallengePort = 4433
	config.EnableHTTP01Challenge= true
	config.UsersFileSystem = memfs.NewMemFS()
	config.CertificatesFileSystem = memfs.NewMemFS()
	tharness.RunTLSFSTestHarness(t, acme.NewAcmeFS(config))
}
