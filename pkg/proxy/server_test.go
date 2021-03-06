package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// createTLSCACert is a helper function that produces a test certificate authority
// and corresponding private key, in this case using ECDSA.
func generateNewSerialNumber(t *testing.T) *big.Int {
	t.Helper()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err)
	require.NotNil(t, serialNumber)

	return serialNumber
}

// createTLSCACert is a helper function that produces a test certificate authority (CA)
// and corresponding private key, in this case using ECDSA.
func createTLSCACert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate a new serial number for the certificate
	serialNumber := generateNewSerialNumber(t)

	// Create a new CA certificate template
	certTemplate := &x509.Certificate{
		IsCA:                  true,
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // valid for 10 years
		DNSNames:              []string{"ca"},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate a new ECDSA private key
	caCertPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, caCertPrivKey)

	// Create a CA certificate (self-signed) using the given template and ECDSA key material
	caCertAns1DerBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &caCertPrivKey.PublicKey, caCertPrivKey)
	require.NoError(t, err)
	require.NotNil(t, caCertAns1DerBytes)

	// Parse the created certificate to use it
	caCert, err := x509.ParseCertificate(caCertAns1DerBytes)
	require.NoError(t, err)
	require.NotNil(t, caCert)

	return caCert, caCertPrivKey
}

// createTLSServerCert is a helper function that produces a test server certificate
// and corresponding private key, in this case using ECDSA.
func createTLSServerCert(t *testing.T, caCert *x509.Certificate, caPrivKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate a new serial number for the certificate
	serialNumber := generateNewSerialNumber(t)

	// Create a new server certificate template
	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // valid for 10 years
		DNSNames:              []string{"server"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate a new ECDSA private key
	serverCertPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, serverCertPrivKey)

	// Create a server certificate from the CA using the given template and ECDSA key material
	serverCertAns1DerBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &serverCertPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)
	require.NotNil(t, serverCertAns1DerBytes)

	// Parse the created certificate to use it
	serverCert, err := x509.ParseCertificate(serverCertAns1DerBytes)
	require.NoError(t, err)
	require.NotNil(t, serverCert)

	return serverCert, serverCertPrivKey
}

// createTLSServerCert is a helper function that produces a test client certificate
// and corresponding private key, in this case using ECDSA.
func createTLSClientCert(t *testing.T, caCert *x509.Certificate, caPrivKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	require.NotNil(t, caCert)

	// Generate a new serial number for the certificate
	serialNumber := generateNewSerialNumber(t)

	// Create a new client certificate template
	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // valid for 10 years
		DNSNames:              []string{"client"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Generate a new ECDSA private key
	clientCertPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, clientCertPrivKey)

	// Create a client certificate from the CA using the given template and ECDSA key material
	clientCertAns1DerBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &clientCertPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)
	require.NotNil(t, clientCertAns1DerBytes)

	// Parse the created certificate to use it
	clientCert, err := x509.ParseCertificate(clientCertAns1DerBytes)
	require.NoError(t, err)
	require.NotNil(t, clientCert)

	return clientCert, clientCertPrivKey
}

func TestNewServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(func() {
		cancel()
	})

	// Create mTLS certificates and mTLS enabled upstream service listener
	caCert, caKey := createTLSCACert(t)
	serverCert, serverKey := createTLSServerCert(t, caCert, caKey)
	clientCert, clientKey := createTLSClientCert(t, caCert, caKey)

	clientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCert.Raw,
	})

	b1, err := x509.MarshalPKCS8PrivateKey(clientKey)
	require.NoError(t, err)

	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b1,
	})

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCertPEM)

	serverCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCert.Raw,
	})

	b2, err := x509.MarshalPKCS8PrivateKey(serverKey)
	require.NoError(t, err)

	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b2,
	})

	tlsServerCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	upstreamListener, err := tls.Listen("tcp", "127.0.0.1:", &tls.Config{
		ClientAuth:         tls.RequireAndVerifyClientCert,
		RootCAs:            pool,
		InsecureSkipVerify: false,
		Certificates:       []tls.Certificate{tlsServerCert},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		upstreamListener.Close()
	})

	// Create local proxy listener
	proxyListener, err := net.Listen("tcp", "127.0.0.1:")
	require.NoError(t, err)
	require.NotNil(t, proxyListener)
	t.Cleanup(func() {
		proxyListener.Close()
	})

	// Create new proxy server
	srv, err := NewServer(WithX509CACertsFromPEM(caCertPEM), WithX509KeyPair(clientCertPEM, clientKeyPEM))
	require.NoError(t, err)
	require.NotNil(t, srv)

	// Concurrent readiness locks to predictably coordinate the
	// upstream, proxy, and client test runners.

	type ready = struct{}

	var (
		proxyReady    = make(chan ready)
		upstreamReady = make(chan ready)
		clientReady   = make(chan ready)
	)

	// 1. client <--> 2. proxy <--> 3. upstream

	t.Run("upstrem", func(t *testing.T) {
		t.Parallel()

		upstreamReady <- ready{}
		t.Logf("upstream ready to accept connections")
		conn, err := upstreamListener.Accept()
		require.NoError(t, err)
		require.NotNil(t, conn)
		t.Logf("recvd connection from proxy at upstream")

		<-clientReady
		t.Logf("writing payload which will also force the TLS handshake")

		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte("hello world"))
		upstreamReady <- ready{}
		conn.Close()
	})

	t.Run("proxy", func(t *testing.T) {
		t.Parallel()
		<-upstreamReady
		t.Logf("serving connections on %v", proxyListener.Addr())
		proxyReady <- ready{}
		go srv.Serve(ctx, upstreamListener.Addr().String(), proxyListener)
	})

	t.Run("client", func(t *testing.T) {
		t.Logf("dialing server %v", proxyListener.Addr())
		t.Parallel()
		<-proxyReady
		conn, err := net.Dial(proxyListener.Addr().Network(), proxyListener.Addr().String())
		require.NoError(t, err)
		require.NotNil(t, proxyListener)
		t.Logf("connection established")

		clientReady <- ready{}
		<-upstreamReady
		conn.Close()
		t.Logf("closed connection")
	})
}
