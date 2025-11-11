# tlsbin

`tlsbin` is a simple tool for inspecting and debugging TLS (Transport Layer Security) negotiations.
This application provides a TLS server that allows you to easily observe the details of the TLS handshake from any client.
It is especially useful for testing supported TLS versions, cipher suites, ALPN protocols, ECH (Encrypted Client Hello), and mTLS configurations.

`tlsbin` also includes helper commands to generate the necessary cryptographic materials (CAs, ECH keys) for setting up advanced TLS test scenarios.


## Features

- **Handshake Information**: View detailed TLS handshake dumps via an HTTP request.
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

This command starts the main TLS inspection server.

```
$ tlsbin server [OPTIONS]
```
The server will start, and you can send a request to it (e.g., with `curl`) to receive a JSON dump of the client's TLS handshake information.

**Example:**
```
# Start the server
$ tlsbin server

# In another terminal, make a request
$ curl -s -k https://localhost:8080
{
  "client_hello": {
    "sni": "localhost",
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
      "TLS_AES_256_GCM_SHA384 (0x1302)",
      "TLS_CHACHA20_POLY1305_SHA256 (0x1303)",
      "TLS_AES_128_GCM_SHA256 (0x1301)",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)",
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)",
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)",
      "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)",
      "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)",
      "TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)",
      "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)",
      "Reserved or Unassigned (0xff85)",
      "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0x00c4)",
      "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)",
      "Reserved or Unassigned (0x0081)",
      "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)",
      "TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)",
      "TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)",
      "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0x00c0)",
      "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0084)",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)",
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)",
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)",
      "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e)",
      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)",
      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)",
      "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0x00be)",
      "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0045)",
      "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)",
      "TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)",
      "TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)",
      "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0x00ba)",
      "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0041)",
      "TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xc011)",
      "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (0xc007)",
      "TLS_RSA_WITH_RC4_128_SHA (0x0005)",
      "TLS_RSA_WITH_RC4_128_MD5 (0x0004)",
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)",
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008)",
      "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)",
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)",
      "TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)"
    ],
    "sig_schemes": [
      "PSSWithSHA512",
      "PKCS1WithSHA512",
      "ECDSAWithP521AndSHA512",
      "PSSWithSHA384",
      "PKCS1WithSHA384",
      "ECDSAWithP384AndSHA384",
      "PSSWithSHA256",
      "PKCS1WithSHA256",
      "ECDSAWithP256AndSHA256",
      "PKCS1WithSHA1",
      "ECDSAWithSHA1"
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
  "mtls": {
    "client_certs": [
      {
        "issuer": "CN=tlsbin root CA",
        "not_after": "2026-11-06T14:37:32Z",
        "not_before": "2025-11-06T14:37:32Z",
        "public_key_algo": "RSA",
        "serial": "35B2C0EB26B9B6286E44D2119477430AE3EA85AA",
        "subject": "CN=client1.tlsbin.net"
      }
    ],
    "enabled": true
  },
  "negotiated": {
    "alpn": "h2",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "did_resume": false,
    "ech_accepted": false,
    "ocsp_bytes": 0,
    "scts": 0,
    "sni": "",
    "tls_version": "TLS 1.3"
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
$ openssl req -new -key client.key -out client.csr -subj 'CN=/client-name.tlsbin.net'
$ openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial \
    -in client.csr -out client.crt -days 365 -sha256 -extfile <(echo "extendedKeyUsage = clientAuth")
---------------------------------
```
This creates `ca.crt` and `ca.key` in the current directory. You can then use `openssl` to generate client certificates signed by this CA.


#### `config ech`

Create a new certificate signed by your CA for mTLS.

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
You can then pass the generated `--ech-key` and `--ech-cfg` values to the `server` command to start the server with a stable ECH configuration.
