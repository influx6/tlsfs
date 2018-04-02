TLSFS
--------
[![Go Report Card](https://goreportcard.com/badge/github.com/wirekit/tlsfs)](https://goreportcard.com/report/github.com/wirekit/tlsfs)
[![Travis CI](https://travis-ci.org/wirekit/wire.svg?master=branch)](https://travis-ci.org/wirekit/tlsfs)
[![Circle CI](https://circleci.com/gh/wirekit/tlsfs.svg?style=svg)](https://circleci.com/gh/wirekit/tlsfs)

Filesystem-like manager to provide TLS/SSL certificate creation, renewal and retrieval.

## Install

```bash
go get -u github.com/wirekit/tlsfs
```

## Examples

Below are examples of creating a tlsfs Filesystem based on using Let's Encrypt as the desired CA authority.

### In-Memory Lets Encrypt CA

```go
import (
	"os"

	"github.com/wirekit/tlsfs/fs/memfs"
	"github.com/wirekit/tlsfs/tlsp/acme"
)

var config acme.Config
config.HTTPChallengePort = 3550
config.TLSSNIChallengePort = 4433
config.EnableHTTP01Challenge = true
config.UsersFileSystem = memfs.NewMemFS()
config.CertificatesFileSystem = memfs.NewMemFS()
config.CAURL = "https://acme-v01.api.letsencrypt.org/directory"

service := acme.NewAcmeFS(config)
service.Create("bob@gmail.com", "*.westros.com")
```

### FileSystem  Lets Encrypt CA

```go
import (
	"os"

	"github.com/wirekit/tlsfs/fs/sysfs"
	"github.com/wirekit/tlsfs/tlsp/acme"
)

var config acme.Config
config.HTTPChallengePort = 3550
config.TLSSNIChallengePort = 4433
config.EnableHTTP01Challenge = true
config.UsersFileSystem = sysfs.NewSystemZapFS("acme/users")
config.CertificatesFileSystem = sysfs.NewSystemZapFS("acme/certs")
config.CAURL = "https://acme-v01.api.letsencrypt.org/directory"

service := acme.NewAcmeFS(config)
service.Create("bob@gmail.com", "*.westros.com")
```

## Vendoring
Vendoring was done with [Dep](https://github.com/golang/dep).
