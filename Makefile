install:
	@go build -o mtls-proxy .
	@mv mtls-proxy /usr/local/bin