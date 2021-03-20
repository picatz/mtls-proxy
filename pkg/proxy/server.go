package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/go-hclog"
)

type Server struct {
	Options *ServerOptions
}

type ServerOptions struct {
	Logger            hclog.Logger
	X509KeyPair       tls.Certificate
	X509CertPool      *x509.CertPool
	X509VerifyDNSName string
}

func (opts *ServerOptions) SetDefaults() {
	opts = &ServerOptions{
		Logger:       hclog.Default().Named("mtls-proxy"),
		X509CertPool: x509.NewCertPool(),
	}
}

type NewServerOption func(*ServerOptions) error

func newServerOptionWithoutError(fn func(*ServerOptions)) NewServerOption {
	return func(opts *ServerOptions) error {
		fn(opts)
		return nil
	}
}

func WithLogger(logger hclog.Logger) NewServerOption {
	return newServerOptionWithoutError(func(opts *ServerOptions) {
		opts.Logger = logger
	})
}

func WithX509VerifyDNSName(dnsName string) NewServerOption {
	return newServerOptionWithoutError(func(opts *ServerOptions) {
		opts.X509VerifyDNSName = dnsName
	})
}

func WithX509KeyPair(certPEMBlock []byte, keyPEMBlock []byte) NewServerOption {
	return func(opts *ServerOptions) error {
		cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			return fmt.Errorf("failed to load x509 key pair: %w", err)
		}
		opts.X509KeyPair = cert
		return nil
	}
}

func WitwX509CertPool(pool *x509.CertPool) NewServerOption {
	return func(opts *ServerOptions) error {
		opts.X509CertPool = pool
		return nil
	}
}

func WithX509CACert(cert *x509.Certificate) NewServerOption {
	return func(opts *ServerOptions) error {
		if opts.X509CertPool == nil {
			opts.X509CertPool = x509.NewCertPool()
		}
		opts.X509CertPool.AddCert(cert)
		return nil
	}
}

func WithX509CACertsFromPEM(pemCerts []byte) NewServerOption {
	return func(opts *ServerOptions) error {
		if opts.X509CertPool == nil {
			opts.X509CertPool = x509.NewCertPool()
		}
		opts.X509CertPool.AppendCertsFromPEM(pemCerts)
		return nil
	}
}

func NewServer(opts ...NewServerOption) (*Server, error) {
	srvOpts := &ServerOptions{
		Logger: hclog.Default().Named("mtls-proxy"),
	}

	for _, opt := range opts {
		err := opt(srvOpts)
		if err != nil {
			return nil, fmt.Errorf("custom server option error: %w", err)
		}
	}

	return &Server{Options: srvOpts}, nil
}

func (srv *Server) Serve(ctx context.Context, proxyTarget string, ln net.Listener) error {
	var tempDelay time.Duration // how long to sleep on accept failure

	var tlsVerifyOpts = x509.VerifyOptions{
		Roots:   srv.Options.X509CertPool,
		DNSName: srv.Options.X509VerifyDNSName,
	}

	var tlsConf = &tls.Config{
		Certificates:       []tls.Certificate{srv.Options.X509KeyPair},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // required for custom mTLS certificate verification
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) != 1 {
				return fmt.Errorf("custom verification expected 1 cert duirng peer verification from server, found %d", len(rawCerts))
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse peer certificate: %w", err)
			}
			_, err = peerCert.Verify(tlsVerifyOpts)
			if err != nil {
				return fmt.Errorf("failed to verify peer certificate: %w", err)
			}
			return nil
		},
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					if tempDelay == 0 {
						tempDelay = 5 * time.Millisecond
					} else {
						tempDelay *= 2
					}
					if max := 1 * time.Second; tempDelay > max {
						tempDelay = max
					}
					srv.Options.Logger.Warn("listener accept error", "error", err, "temporary-delay", tempDelay)
					time.Sleep(tempDelay)
					srv.Options.Logger.Warn("retrying after listener accept error")
					continue
				}
				return fmt.Errorf("net listener non-temporary error: %w", err)
			}
			srv.Options.Logger.Info("serving connection", "addr", conn.RemoteAddr())
			go func() {
				proxyConn, err := net.DialTimeout("tcp", proxyTarget, 30*time.Second)
				if err != nil {
					srv.Options.Logger.Error("failed to connect to target proxy", "proxy-target", proxyTarget, "error", err)
					return
				}

				tlsWrap := tls.Client(proxyConn, tlsConf)
				err = tlsWrap.Handshake()
				if err != nil {
					log.Println(err)
					return
				}

				// copy connections bi-directionally
				copyConn := func(writer, reader net.Conn) {
					defer writer.Close()
					defer reader.Close()
					io.Copy(writer, reader)
				}

				go copyConn(conn, tlsWrap)
				go copyConn(tlsWrap, conn)
			}()
		}
	}
}
