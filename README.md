# tlsbin

`tlsbin` is a small CLI for inspecting and debugging TLS handshakes.
It runs a local HTTPS server and returns a JSON view of what the client offered and what the server negotiated.
It is useful for checking TLS versions, cipher suites, ALPN, ECH (Encrypted Client Hello), JA3/JA4 fingerprints, and mTLS behavior.

`tlsbin` also includes helper commands to generate CA material for mTLS and static ECH configuration for repeatable test setups.


## Features

- **Handshake Information**: Inspect client hello fields and negotiated TLS parameters over HTTPS.
- **Fingerprints**: Return JA3, JA3 raw, JA4, and JA4 raw values for the connecting client.
- **ECH Support**: Generate static ECH (Encrypted Client Hello) keys and configure the server to use them.
- **mTLS Support**: Easily test mTLS setups by generating a CA and configuring the server to require client certificates.


## Installation
```
go install github.com/haccht/tlsbin@latest
```

## Usage

`tlsbin` uses a subcommand structure.

```
$ tlsbin --help
Usage:
  tlsbin [OPTIONS] <server|config>

Available commands:
  server  Run the TLS inspection server
  config  Generate configuration artifacts (mTLS/ECH)
```

### `server` command

This command starts the TLS inspection server.

```
$ tlsbin server [OPTIONS]
```
The server listens on `https://127.0.0.1:8080` by default.
If you do not provide `--tls-cert` and `--tls-key`, `tlsbin` generates a temporary self-signed certificate for `localhost`.

Send any HTTPS request to the server and it will return a JSON snapshot of:

- `client_hello`: what the client offered
- `negotiated`: what the connection actually used
- `fingerprint`: JA3/JA4 values for the client hello
- `mtls`: client certificate details, if a client certificate was sent
- `served_cert`: the certificate presented by `tlsbin`

**Example:**
```
# Start the server
$ tlsbin server

# In another terminal, make a request
$ curl -s -k https://127.0.0.1:8080
{
  "client_hello": {
    "sni": "",
    "alpn": [
      "h2",
      "http/1.1"
    ],
    "supported_versions": [
      "TLS 1.3 (0x0304)",
      "TLS 1.2 (0x0303)",
      "TLS 1.1 (0x0302)",
      "TLS 1.0 (0x0301)"
    ],
    "cipher_suites": [
      "TLS_AES_128_GCM_SHA256 (0x1301)",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)"
    ],
    "signature_schemes": [
      "PSSWithSHA256",
      "PKCS1WithSHA256",
      "ECDSAWithP256AndSHA256"
    ],
    "extensions": [
      "supported_versions (0x002b)",
      "key_share (0x0033)",
      "ec_point_formats (0x000b)",
      "supported_groups (0x000a)",
      "signature_algorithms (0x000d)",
      "application_layer_protocol_negotiation (0x0010)"
    ]
  },
  "served_cert": {
    "subject": "CN=localhost",
    "issuer": "CN=localhost",
    "serial": "FF0584230B97BB",
    "not_before": "2025-11-11T04:01:44Z",
    "not_after": "2026-11-11T05:01:44Z",
    "dns_names": [
      "localhost"
    ],
    "public_key_algo": "ECDSA"
  },
  "fingerprint": {
    "ja3": "18ad6e1a77c00d96229ccb62a794860d",
    "ja3_raw": "771,4865-49199-49195,43-51-11-10-13-16,29-23-24,0",
    "ja4": "t13i0306h2_f57a46bbacb6_73f4e70f3587",
    "ja4_raw": "t13i0306h2_1301,c02b,c02f_000a,000b,000d,002b,0033_0403,0804"
  },
  "mtls": {
    "enabled": false
  },
  "negotiated": {
    "sni": "",
    "ech": {
      "accepted": false
    },
    "alpn": "h2",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "did_resume": false,
    "ocsp_bytes": 0,
    "signed_certificate_timestamps": 0,
    "tls_version": "TLS 1.3"
  }
}
```

**Common `server` options:**

```
      -a, --addr=                                                   Server address (default: 127.0.0.1:8080)
          --tls-cert=                                               TLS certificate file path
          --tls-key=                                                TLS key file path
          --tls-min-ver=[1.0|1.1|1.2|1.3]                           Minimum TLS version
          --tls-max-ver=[1.0|1.1|1.2|1.3]                           Maximum TLS version
          --alpn=[http/1.1|h2]                                      List of application protocols
          --cipher=                                                 List of ciphersuites (TLS1.3 ciphersuites are not configurable)
          --mtls-auth=[off|request|required|verify|verify-if-given] Client cert auth mode (default: off)
          --mtls-ca=                                                mTLS Client CA certificate file path
          --ech-enabled                                             Enable ECH (Encrypted Client Hello)
          --ech-key=                                                Base64-encoded ECH private key
          --ech-cfg=                                                Base64-encoded ECH configuration
```

---

### `config` command

This command provides subcommands to generate cryptographic materials.

```
$ tlsbin config --help
Usage:
  tlsbin [OPTIONS] config <ech|mtls>

Available commands:
  ech   Configure ECH key
  mtls  Configure mTLS key
```

#### `config mtls`

Create a new root Certificate Authority (CA) for mTLS.

```
$ tlsbin config mtls --cn="mTLS CA"
Generating a new CA key pair...

Successfully generated a CA key pair.
---------------------------------
Generate a client certificate to authenticate client with this CA

$ openssl genrsa -out client.key 2048
$ openssl req -new -key client.key -out client.csr -subj '/CN=client-name.tlsbin.net'
$ openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -in client.csr -out client.crt -days 365 -sha256 -extfile <(echo "extendedKeyUsage = clientAuth")
---------------------------------
```
This creates `ca.crt` and `ca.key` in the current directory.
Start `tlsbin server` with `--mtls-auth=verify --mtls-ca=ca.crt`, then connect with `curl --cert client.crt --key client.key`.


#### `config ech`

Create a new static ECH key pair and configuration blob.

```
$ tlsbin config ech --public-name="ech.tlsbin.net"
Generating a new ECH key pair...

Successfully generated a ECH key pair.
---------------------------------
Add the following flags to the 'server' command to use this static key:

  --ech-key="..." \
  --ech-cfg="..."

Add the following HTTPS record to your zone for the backend FQDN:

  IN HTTPS 1 . ech="..."
```
You can then pass the generated `--ech-key` and `--ech-cfg` values to `tlsbin server --ech-enabled` to run with a stable ECH configuration.
