package owned_test

import (
	"os"
	"testing"

	"github.com/influx6/faux/tests"
	"github.com/wirekit/tlsfs"
	"github.com/wirekit/tlsfs/certificates"
	"github.com/wirekit/tlsfs/fs/memfs"
	"github.com/wirekit/tlsfs/fs/sysfs"
	"github.com/wirekit/tlsfs/internal/tharness"
	"github.com/wirekit/tlsfs/tlsp/owned"
)

func TestCustomFSWithMemFS(t *testing.T) {
	var config owned.Config
	config.RootFilesystem = memfs.NewMemFS()
	config.UsersFileSystem = memfs.NewMemFS()
	config.CertificatesFileSystem = memfs.NewMemFS()
	config.Profile = certificates.CertificateAuthorityProfile{
		CommonName: "Dracol Certificate Authority",
		Country:    "NG",
		Province:   "LG",
		Version:    1,
		LifeTime:   tlsfs.OneYear * 5,
	}

	fs, err := owned.NewCustomFS(config)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created tlsfs filesystem")
	}
	tests.Passed("Should have successfully created tlsfs filesystem")

	tharness.RunTLSFSTestHarness(t, fs)
}

func TestCustomFSWithSysFS(t *testing.T) {
	defer os.RemoveAll("temp")

	var config owned.Config
	config.RootFilesystem = sysfs.NewSystemZapFS("temp/syscerts/roots")
	config.UsersFileSystem = sysfs.NewSystemZapFS("temp/syscerts/users")
	config.CertificatesFileSystem = sysfs.NewSystemZapFS("temp/syscerts/certs")
	config.Profile = certificates.CertificateAuthorityProfile{
		CommonName: "Dracol Certificate Authority",
		Country:    "NG",
		Province:   "LG",
		Version:    1,
		LifeTime:   tlsfs.OneYear * 5,
	}

	fs, err := owned.NewCustomFS(config)
	if err != nil {
		tests.FailedWithError(err, "Should have successfully created tlsfs filesystem")
	}
	tests.Passed("Should have successfully created tlsfs filesystem")

	tharness.RunTLSFSTestHarness(t, fs)
}
