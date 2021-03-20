# mtls-proxy

This is an mTLS terminating local proxy that handles custom x509 verification between a listener address and an upstream target address. This enables working with mTLS enabled services much easier without needing to fiddle around with system or browser x509 certificate configurations. Just use the proxy, and it'll handle tuneling your non-mTLS connection securely to the upstream target address.

## Configuration

The program can be configured using environment variables, HCL, and/or command-line flags. Please refer to the `-help` menu or source code for more information.

```hcl
listener_addr   = "127.0.0.1:8200"                      # MTLS_PROXY_LISTENER_ADDR or -listener-addr
target_addr     = "LOAD_BALANCER_IP_OR_DNS_NAME:8200"   # MTLS_PROXY_TARGET_ADDR   or -target-addr
ca_file         = "/full/path/to/vault-ca.pem"          # MTLS_PROXY_CA_CERT       or -ca-file
client_file     = "/full/path/to/vault-cli-cert.pem"    # MTLS_PROXY_CLIENT_CERT   or -cert-file
key_file        = "/full/path/to/vault-cli-key.pem"     # MTLS_PROXY_CLIENT_KEY    or -key-file
verify_dns_name = "server.global.vault"                 # MTLS_PROXY_CONFIG        or -config
```

## Examples

Example usage of this program.

### Vault

```console
$ mtls-proxy -listener-addr="127.0.0.1:8200" -target-addr="$VAULT_IP:8200" -ca-file="vault-ca.pem" -cert-file="vault-cli-cert.pem" -key-file="vault-cli-key.pem" -verify-dns-name="server.global.vault"
2021-03-20T16:39:42.127-0400 [INFO]  mtls-proxy: starting server: address=127.0.0.1:8200
...
```

### Consul

```console
$ mtls-proxy -listener-addr="127.0.0.1:8500" -target-addr="$CONSUL_IP:8500" -ca-file="consul-ca.pem" -cert-file="consul-cli-cert.pem" -key-file="consul-cli-key.pem" -verify-dns-name="server.dc1.consul"
2021-03-20T16:39:42.127-0400 [INFO]  mtls-proxy: starting server: address=127.0.0.1:8500
...
```

### Nomad

```console
$ mtls-proxy -listener-addr="127.0.0.1:4646" -target-addr="$NOMAD_IP:4646" -ca-file="nomad-ca.pem" -cert-file="nomad-cli-cert.pem" -key-file="nomad-cli-key.pem"  -verify-dns-name="server.global.nomad"
2021-03-20T16:39:42.127-0400 [INFO]  mtls-proxy: starting server: address=127.0.0.1:4646
...
```
