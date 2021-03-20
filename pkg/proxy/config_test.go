package proxy

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	src := bytes.NewBufferString(`
		listener_addr = "127.0.0.1:4443"
		target_addr   = "127.0.0.1:4444"
		ca_file       = "/tmp/fake"
		client_file   = "/tmp/fake"
		key_file      = "/tmp/fake"
	`)
	conf, err := ParseConfig(src)
	require.NoError(t, err)
	require.NotNil(t, conf)

	require.Equal(t, "127.0.0.1:4443", conf.ListenerAddr)
	require.Equal(t, "127.0.0.1:4444", conf.TargetAddr)
	require.Equal(t, "/tmp/fake", conf.CACertPEMFile)
	require.Equal(t, "/tmp/fake", conf.ClientCertPemFile)
	require.Equal(t, "/tmp/fake", conf.ClientKeyPemFile)
}
