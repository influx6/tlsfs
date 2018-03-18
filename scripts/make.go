package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/gokit/history"
	"github.com/gokit/history/handlers/std"
	"github.com/gokit/zexec"
	"github.com/influx6/faux/flags"
)

func main() {
	history.SetDefaultHandlers(std.Std)
	flags.Run("make", flags.Command{
		Name:   "coverage",
		Action: coverage,
	}, flags.Command{
		Name:   "tests",
		Action: tests,
	})
}

func getMyIP(ctx context.Context) string {
	var res bytes.Buffer
	if exitCode, err := zexec.New(zexec.Command(`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'`), zexec.Output(&res)).Exec(ctx); err != nil {
		log.Fatalf("failed to get system ip: (exit: %d) %+s", exitCode, err)
	}

	return res.String()
}

func getDockerAddr(ctx context.Context) string {
	var res bytes.Buffer
	if _, err := zexec.New(zexec.Command(`ifconfig docker0 | grep "inet addr:" | cut -d: -f2 | awk '{ print $1}'`), zexec.Output(&res)).Exec(ctx); err != nil {
		//log.Fatalf("failed to get docker ip: %+s", err)
	}
	return res.String()
}

func tests(ctx flags.Context) error {
	dockerAddr := getDockerAddr(ctx)
	if dockerAddr == "" {
		if runtime.GOOS == "darwin" {
			dockerAddr = "172.17.0.4"
		} else {
			dockerAddr = getMyIP(ctx)
		}
	}

	dockerAddr = strings.TrimSpace(dockerAddr)

	history.With("docker-addr", dockerAddr).Info("Initializing with docker ip")

	zexec.New(zexec.Command("go test -v -race ./"), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)
	zexec.New(zexec.Command("go test -v -race ./certificates/..."), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)
	zexec.New(zexec.Command("go test -v -race ./fs/..."), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)
	zexec.New(zexec.Command("go test -v -race ./tlsp/owned/..."), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)

	os.Setenv("DOCKER_HOST_DNS", dockerAddr)
	zexec.New(zexec.Command("docker-compose up -d"), zexec.Envs(map[string]string{
		"DOCKER_HOST_DNS": dockerAddr,
	}), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)
	zexec.New(zexec.Command("go test -v -race ./tlsp/acme/..."), zexec.Output(os.Stderr), zexec.Err(os.Stderr), zexec.Envs(map[string]string{
		"DOCKER_HOST_DNS":    dockerAddr,
		"TEST_DOMAIN":        "mydomain.com",
		"TEST_DOMAIN_EMAIL":  "yours@mydomain.com",
		"BOULDER_CA_HOSTDIR": "http://0.0.0.0:4000/directory",
	})).Exec(ctx)
	zexec.New(zexec.Command("docker-compose down"), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)

	return nil
}

func coverage(ctx flags.Context) error {
	dockerAddr := getDockerAddr(ctx)
	if dockerAddr == "" {
		if runtime.GOOS == "darwin" {
			dockerAddr = "172.17.0.4"
		} else {
			dockerAddr = getMyIP(ctx)
		}
	}

	dockerAddr = strings.TrimSpace(dockerAddr)
	history.With("docker-addr", dockerAddr).Info("Initializing with docker ip")

	zexec.New(zexec.Command("go test -cover ./"), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)
	zexec.New(zexec.Command("go test -cover ./certificates/..."), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)
	zexec.New(zexec.Command("go test -cover ./fs/..."), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)
	zexec.New(zexec.Command("go test -cover ./tlsp/owned/..."), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)

	os.Setenv("DOCKER_HOST_DNS", dockerAddr)
	zexec.New(zexec.Command("docker-compose up -d"), zexec.Envs(map[string]string{
		"DOCKER_HOST_DNS": dockerAddr,
	}), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)
	zexec.New(zexec.Command("go test -cover ./tlsp/acme/..."), zexec.Output(os.Stderr), zexec.Err(os.Stderr), zexec.Envs(map[string]string{
		"DOCKER_HOST_DNS":    dockerAddr,
		"TEST_DOMAIN":        "mydomain.com",
		"TEST_DOMAIN_EMAIL":  "yours@mydomain.com",
		"BOULDER_CA_HOSTDIR": "http://0.0.0.0:4000/directory",
	})).Exec(ctx)
	zexec.New(zexec.Command("docker-compose down"), zexec.Output(os.Stderr), zexec.Err(os.Stderr)).Exec(ctx)

	return nil
}
