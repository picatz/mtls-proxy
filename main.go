package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"

	"github.com/hashicorp/go-hclog"
	"github.com/picatz/mtls-proxy/pkg/proxy"
)

var (
	listenerAddr      string
	proxyTarget       string
	caCertPEMFile     string
	clientCertPemFile string
	clientKeyPemFile  string
	verifyDNSName     string
	config            string
)

func envWithDefault(env, def string) string {
	str := os.Getenv(env)
	if str == "" {
		str = def
	}
	return str
}

func init() {
	flag.StringVar(&listenerAddr, "listener-addr", envWithDefault("MTLS_PROXY_LISTENER_ADDR", "127.0.0.1:"), "listener address to serve connections from (to the proxy target)")
	flag.StringVar(&proxyTarget, "target-addr", envWithDefault("MTLS_PROXY_TARGET_ADDR", "127.0.0.1:"), "address to forward connections to (from the listener address)")
	flag.StringVar(&caCertPEMFile, "ca-file", envWithDefault("MTLS_PROXY_CA_CERT", ""), "path to PEM encoded x509 CA file")
	flag.StringVar(&clientCertPemFile, "cert-file", envWithDefault("MTLS_PROXY_CLIENT_CERT", ""), "path to PEM encoded x509 client certificate file")
	flag.StringVar(&clientKeyPemFile, "key-file", envWithDefault("MTLS_PROXY_CLIENT_KEY", ""), "path to PEM encoded x509 client key file")
	flag.StringVar(&verifyDNSName, "verify-dns-name", envWithDefault("MTLS_PROXY_VERIFY_DNS_NAME", ""), "optional DNS name x509 server verification")
	flag.StringVar(&config, "config", envWithDefault("MTLS_PROXY_CONFIG", ""), "optional mTLS proxy HCL configuration file")
}

func ctrlC() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		select {
		case <-c:
			cancel()
			os.Exit(1) // TODO(kent): handle graceful shutdowns, not just killing the program yolo style
		case <-ctx.Done():
		}
	}()
	return ctx
}

func readFile(path string) []byte {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Errorf("failed to read file %q: %w", path, err))
	}
	return bytes
}

func main() {
	flag.Parse()

	logger := hclog.Default().Named("mtls-proxy")

	if config != "" {
		proxyConfig, err := proxy.ParseConfig(bytes.NewBuffer(readFile(config)))
		if err != nil {
			logger.Error(fmt.Sprintf("failed to parse proxy HCL config %q", config), "error", err)
			os.Exit(1)

		}
		if proxyConfig.ListenerAddr != "" {
			listenerAddr = proxyConfig.ListenerAddr
		}
		if proxyConfig.TargetAddr != "" {
			proxyTarget = proxyConfig.TargetAddr
		}
		if proxyConfig.CACertPEMFile != "" {
			caCertPEMFile = proxyConfig.CACertPEMFile
		}
		if proxyConfig.ClientCertPemFile != "" {
			clientCertPemFile = proxyConfig.ClientCertPemFile
		}
		if proxyConfig.ClientKeyPemFile != "" {
			clientKeyPemFile = proxyConfig.ClientKeyPemFile
		}
	}

	if proxyTarget == "" {
		logger.Error("no proxy target specified")
		os.Exit(1)
	}

	if caCertPEMFile == "" {
		logger.Error("no CA PEM file path specified")
		os.Exit(1)
	}

	if clientCertPemFile == "" {
		logger.Error("no client cert PEM file path specified")
		os.Exit(1)
	}

	if clientKeyPemFile == "" {
		logger.Error("no client key PEM file path specified")
		os.Exit(1)
	}

	ctx := ctrlC()

	srv, err := proxy.NewServer(
		proxy.WithX509CACertsFromPEM(readFile(caCertPEMFile)),
		proxy.WithX509KeyPair(readFile(clientCertPemFile), readFile(clientKeyPemFile)),
		proxy.WithX509VerifyDNSName(verifyDNSName),
	)
	if err != nil {
		logger.Error("failed to create new proxy server", "error", err)
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", listenerAddr)
	if err != nil {
		logger.Error("failed to create listener", "address", listenerAddr, "error", err)
		os.Exit(1)
	}

	logger.Info("starting server", "address", listener.Addr())
	err = srv.Serve(ctx, proxyTarget, listener)
	if err != nil {
		logger.Error("server serve error", "error", err)
	}
}
