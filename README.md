# tlsbin

`tlsbin` is a simple tool for inspecting and debugging TLS (Transport Layer Security) negotiations.  
This server application allows you to easily observe the details of the TLS handshake between a client and the server.  
It is especially useful for testing supported TLS versions, cipher suites, ALPN protocols, and certificate configurations.

## Features

- Start a TLS server with customizable address, protocol, and cipher settings
- View detailed TLS handshake dumps via HTTP requests
- Inspect Client Hello, negotiated protocol, cipher suite, and more
- Supports multiple TLS versions and ALPN protocols
- Easily test mTLS setups (client certificate authentication)

## Usage
```
$ tlsbin -h
Usage:
  main [OPTIONS]

Application Options:
  -a, --addr=                     Server address (default: 127.0.0.1:8080)
      --alpn=[h2|http/1.1]        List of application protocols
      --tls-ver=[1.0|1.1|1.2|1.3] List of TLS versions
      --cipher=                   List of ciphersuites (TLS1.3 ciphersuites are not configurable)
      --tls-crt=                  TLS certificate file path
      --tls-key=                  TLS key file path

Help Options:
  -h, --help                      Show this help message
```


To start the TLS server, simply execute the binary:
```
$ tlsbin
2025/08/11 13:34:00 start listening on https://127.0.0.1:8080
```

Send an HTTP request to the server to get a detailed dump of the TLS negotiation:
```
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
