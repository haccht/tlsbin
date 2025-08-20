# tlsbin

`tlsbin` is a simple tool for inspecting and debugging TLS (Transport Layer Security) negotiations.
This application provides a TLS server that allows you to easily observe the details of the TLS handshake from any client.
It is especially useful for testing supported TLS versions, cipher suites, ALPN protocols, ECH (Encrypted Client Hello), and mTLS configurations.

`tlsbin` also includes helper commands to generate the necessary cryptographic materials (CAs, certificates, ECH keys) for setting up advanced TLS test scenarios.

## Features

- **TLS Inspection Server**: Start a TLS server with customizable address, protocol, and cipher settings.
- **Detailed Handshake Information**: View detailed TLS handshake dumps (including Client Hello) via an HTTP request.
- **Certificate Generation**: Built-in commands to create your own Certificate Authority (CA) and sign server/client certificates.
- **ECH Support**: Generate static ECH (Encrypted Client Hello) keys and configure the server to use them.
- **mTLS Testing**: Easily test mTLS setups by generating CAs and client certificates and configuring the server to require them.

## Installation
```
go install github.com/haccht/tlsbin@latest
```

## Usage

`tlsbin` uses a subcommand structure.

```
$ tlsbin --help
Usage:
  tlsbin [OPTIONS] <gen-ech|gen-ca|gen-cert|run>

Available commands:
  gen-ca    Generate a new CA certificate and key for mTLS
  gen-cert  Generate a new certificate signed by a CA for mTLS
  gen-ech   Generate a new key and config for ECH
  run       Run the TLS inspection server
```

### `run` command

This command starts the main TLS inspection server.

```
$ tlsbin run [OPTIONS]
```
The server will start, and you can send a request to it (e.g., with `curl`) to receive a JSON dump of the client's TLS handshake information.

**Example:**
```
# Start the server
$ tlsbin run

# In another terminal, make a request
$ curl -s -k https://127.0.0.1:8080 | jq .
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
      "server_name (0x0000)",
      "ec_point_formats (0x000b)",
      "supported_groups (0x000a)",
      "signature_algorithms (0x000d)",
      "application_layer_protocol_negotiation (0x0010)"
    ]
  },
  "mTLS": {
    "enabled": false
  },
  "negotiated": {
    "alpn": "h2",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "did_resume": false,
    "ech_accepted": false,
    "ocsp_bytes": 0,
    "scts": 0,
    "sni": "localhost",
    "tls_version": "TLS 1.3"
  }
}
```

**Common `run` options:**

```
      -a, --addr=                         Server address (default: 127.0.0.1:8080)
          --tls-crt=                      TLS certificate file path
          --tls-key=                      TLS key file path
          --tls-min-ver=[1.0|1.1|1.2|1.3] Minimum TLS version
          --tls-max-ver=[1.0|1.1|1.2|1.3] Maximum TLS version
          --alpn=[http/1.1|h2]            List of application protocols
          --cipher=                       List of ciphersuites (TLS1.3 ciphersuites are not configurable)
          --enable-mtls                   Enable mTLS
          --mtls-ca=                      mTLS Client CA certificate file path
          --enable-ech                    Enable ECH (Encrypted Client Hello)
          --ech-key=                      Base64-encoded ECH private key
          --ech-config=                   Base64-encoded ECH configuration list
```

---

### Certificate and Key Generation for mTLS

#### 1. `gen-ca`

Create a new root Certificate Authority (CA) for mTLS.

```
$ tlsbin gen-ca --common-name="mTLS CA"
2025/08/18 21:30:00 wrote CA certificate to ca.crt
2025/08/18 21:30:00 wrote CA private key to ca.key
```
This creates `ca.crt` and `ca.key`.

#### 2. `gen-cert`

Create a new certificate signed by your CA for mTLS.
```
$ tlsbin gen-cert --common-name="my-client" --cert-path=client.crt --key-path=client.key
2025/08/18 21:32:00 wrote certificate to client.crt
2025/08/18 21:32:00 wrote private key to client.key
```
This uses `ca.crt` and `ca.key` by default to sign the new certificate.

---

### ECH (Encrypted Client Hello)

#### `gen-ech`

Generate a static ECH key pair and the corresponding DNS record info.

```
$ tlsbin gen-ech --public-name="ech.example.com"
Generating new ECH key pair...

Successfully generated ECH keys.
---------------------------------
Add the following flags to the 'run' command to use this static key:

  --ech-key="..." \
  --ech-config="..."

Add the following HTTPS record to your zone for the backend FQDN:

  HTTPS 1 . ech="..."
---------------------------------
```
You can then pass the generated `--ech-key` and `--ech-config` values to the `run` command to start the server with a stable ECH configuration.
