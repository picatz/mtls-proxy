package proxy

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

type Config struct {
	ListenerAddr      string `hcl:"listener_addr,optional"`
	TargetAddr        string `hcl:"target_addr"`
	CACertPEMFile     string `hcl:"ca_file"`
	ClientCertPemFile string `hcl:"client_file"`
	ClientKeyPemFile  string `hcl:"key_file"`
	VerifyDNSName     string `hcl:"verify_dns_name,optional"`
}

func ParseConfig(src io.Reader) (*Config, error) {
	parser := hclparse.NewParser()
	srcBytes, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, fmt.Errorf("failed while reading given reader: %w", err)
	}

	ctx := &hcl.EvalContext{}

	conf := &Config{}

	f, err := parser.ParseHCL(srcBytes, "")
	decodeDiags := gohcl.DecodeBody(f.Body, ctx, conf)
	if decodeDiags.HasErrors() {
		return nil, fmt.Errorf("decode error(s): %v", decodeDiags.Error())
	}

	return conf, nil
}
