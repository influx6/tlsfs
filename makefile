.PHONY : clean

netip = $(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')

travis-ci: boulder tests coverage clean

boulder:
	docker-compose up -d

coverage:
	go test -cover
	go test -cover ./certificates/...
	go test -cover ./fs/...
	go test -cover ./tlsp/owned/...
	env TEST_DOMAIN="mydomain.com" TEST_DOMAIN_EMAIL="yours@yours.com" BOULDER_CA_HOSTDIR="http://0.0.0.0:4000/directory" go test -cover ./tlsp/acme/...

tests:
	go test -v -race
	go test -race -v ./certificates/...
	go test -v -race ./fs/...
	go test -v -race ./tlsp/owned/...
	env TEST_DOMAIN="mydomain.com" TEST_DOMAIN_EMAIL="yours@yours.com" BOULDER_CA_HOSTDIR="http://0.0.0.0:4000/directory" go test -v -race ./tlsp/acme/...

clean:
	docker-compose down
