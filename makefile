.PHONY : clean

netip = $(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')

travis-ci: boulder ci clean

travis-tests: boulder tests clean

ci: coverage tests

boulder:
	docker-compose up -d

coverage:
	go test -cover
	go test -cover ./certificates/...
	go test -cover ./fs/...
	go test -cover ./tlsp/owned/...
	env TEST_DOMAIN="mydomain.com" TEST_DOMAIN_EMAIL="yours@yours.com" BOULDER_CA_HOSTDIR="http://0.0.0.0:4000/directory" go test -cover ./tlsp/acme/...

tests:
	go test -v
	go test -v ./certificates/...
	go test -v ./fs/...
	go test -v ./tlsp/owned/...
	env TEST_DOMAIN="mydomain.com" TEST_DOMAIN_EMAIL="yours@yours.com" BOULDER_CA_HOSTDIR="http://0.0.0.0:4000/directory" go test -v ./tlsp/acme/...

clean:
	docker-compose down
