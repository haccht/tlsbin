package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/jessevdk/go-flags"
)

var (
	clientHelloStore sync.Map
	extensionName    = map[uint16]string{
		0:      "server_name",
		5:      "status_request",
		10:     "supported_groups",
		11:     "ec_point_formats",
		13:     "signature_algorithms",
		16:     "application_layer_protocol_negotiation",
		18:     "signed_certificate_timestamp",
		21:     "padding",
		23:     "extended_master_secret",
		27:     "compress_certificate",
		28:     "record_size_limit",
		34:     "delegated_credentials",
		35:     "session_ticket",
		41:     "pre_shared_key",
		42:     "early_data",
		43:     "supported_versions",
		45:     "psk_key_exchange_modes",
		51:     "key_share",
		0xfe0d: "encrypted_client_hello",
		0xff01: "renegotiation_info",
	}
)

type clientHelloInfo struct {
	ServerName        string   `json:"sni"`
	SupportedProtos   []string `json:"alpn"`
	SupportedVersions []string `json:"supported_versions"`
	CipherSuites      []string `json:"cipher_suites"`
	SignatureSchemes  []string `json:"sig_schemes"`
	SupportedCurves   []string `json:"curves"`
	Extensions        []string `json:"extensions"`
}

type ctxConnKey struct{}

func connKey(c net.Conn) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s", c.LocalAddr().String(), c.RemoteAddr().String())
}

type options struct {
	Addr        string   `short:"a" long:"addr" description:"Server address" default:"127.0.0.1:8080"`
	Protocol    []string `long:"alpn" description:"List of application protocols" choice:"h2" choice:"http/1.1"`
	TLSVersion  []string `long:"tls-ver" description:"List of TLS versions" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	CipherSuite []string `long:"cipher" description:"List of ciphersuites (TLS1.3 ciphersuites are not configurable)"`
	TLSCert     string   `long:"tls-crt" description:"TLS certificate file path"`
	TLSKey      string   `long:"tls-key" description:"TLS key file path"`
}

func mustSelfSignedCert() tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("key gen: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
}

func toCipherSuite(v string) (uint16, error) {
	switch v {
	case "TLS_RSA_WITH_RC4_128_SHA":
		return tls.TLS_RSA_WITH_RC4_128_SHA, nil
	case "TLS_RSA_WITH_3DES_EDE_CBC_SHA":
		return tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, nil
	case "TLS_RSA_WITH_AES_128_CBC_SHA":
		return tls.TLS_RSA_WITH_AES_128_CBC_SHA, nil
	case "TLS_RSA_WITH_AES_256_CBC_SHA":
		return tls.TLS_RSA_WITH_AES_256_CBC_SHA, nil
	case "TLS_RSA_WITH_AES_128_CBC_SHA256":
		return tls.TLS_RSA_WITH_AES_128_CBC_SHA256, nil
	case "TLS_RSA_WITH_AES_128_GCM_SHA256":
		return tls.TLS_RSA_WITH_AES_128_GCM_SHA256, nil
	case "TLS_RSA_WITH_AES_256_GCM_SHA384":
		return tls.TLS_RSA_WITH_AES_256_GCM_SHA384, nil
	case "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":
		return tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, nil
	case "TLS_ECDHE_RSA_WITH_RC4_128_SHA":
		return tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, nil
	case "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":
		return tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, nil
	case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":
		return tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, nil
	case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
		return tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, nil
	case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":
		return tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, nil
	case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
		return tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, nil
	case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
		return tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, nil
	case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
		return tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, nil
	case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":
		return tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, nil
	case "TLS_AES_128_GCM_SHA256":
		return tls.TLS_AES_128_GCM_SHA256, nil
	case "TLS_AES_256_GCM_SHA384":
		return tls.TLS_AES_256_GCM_SHA384, nil
	case "TLS_CHACHA20_POLY1305_SHA256":
		return tls.TLS_CHACHA20_POLY1305_SHA256, nil
	}
	return 0, fmt.Errorf("Unsupported cipher suite %s", v)
}

func toTLSVersion(v string) (uint16, error) {
	switch v {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("Unsupported version %s", v)
}

func isGREASE(id uint16) bool {
	b := byte(id >> 8)
	return b == byte(id) && (b&0x0f) == 0x0a
}

func toCipherSuiteName(id uint16) string {
	if isGREASE(id) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", id)
	}
	return fmt.Sprintf("%s (0x%04x)", tls.CipherSuiteName(id), id)
}

func toTLSVersionName(id uint16) string {
	if isGREASE(id) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", id)
	}
	return fmt.Sprintf("%s (0x%04x)", tls.VersionName(id), id)
}

func toSignatureScheme(v tls.SignatureScheme) string {
	return v.String()
}

func toCurveName(v tls.CurveID) string {
	return v.String()
}

func toExtensionName(id uint16) string {
	if isGREASE(id) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", id)
	}
	n, ok := extensionName[id]
	if !ok {
		n = fmt.Sprintf("0x%04x", id)
	}
	return fmt.Sprintf("%s (0x%04x)", n, id)
}

func mapToString[T any](in []T, f func(T) string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}

func main() {
	var opts options
	_, err := flags.Parse(&opts)
	if err != nil {
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{mustSelfSignedCert()},
		// EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{ ... }, // uncomment this for ECH
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHelloStore.Store(connKey(ch.Conn), clientHelloInfo{
				ServerName:        ch.ServerName,
				SupportedProtos:   ch.SupportedProtos,
				CipherSuites:      mapToString(ch.CipherSuites, toCipherSuiteName),
				SupportedVersions: mapToString(ch.SupportedVersions, toTLSVersionName),
				SignatureSchemes:  mapToString(ch.SignatureSchemes, toSignatureScheme),
				SupportedCurves:   mapToString(ch.SupportedCurves, toCurveName),
				Extensions:        mapToString(ch.Extensions, toExtensionName),
			})
			return nil, nil
		},
	}
	if len(opts.Protocol) > 0 {
		tlsConf.NextProtos = opts.Protocol
	}
	if len(opts.TLSVersion) > 0 {
		var err error
		tlsConf.MinVersion, err = toTLSVersion(slices.Min(opts.TLSVersion))
		tlsConf.MaxVersion, err = toTLSVersion(slices.Max(opts.TLSVersion))
		if err != nil {
			log.Fatal(err)
		}
	}
	if len(opts.CipherSuite) > 0 {
		suites := make([]uint16, len(opts.CipherSuite))
		for i, v := range opts.CipherSuite {
			c, err := toCipherSuite(v)
			if err != nil {
				log.Fatal(err)
			}
			suites[i] = c
		}
		tlsConf.CipherSuites = suites
		fmt.Println(tlsConf.CipherSuites)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusBadRequest)
			return
		}

		var hello clientHelloInfo
		if v := r.Context().Value(ctxConnKey{}); v != nil {
			if c, ok := v.(net.Conn); ok {
				if hv, ok := clientHelloStore.Load(connKey(c)); ok {
					hello = hv.(clientHelloInfo)
				}
			}
		}

		var clientSubject string
		if len(r.TLS.PeerCertificates) > 0 {
			clientSubject = r.TLS.PeerCertificates[0].Subject.String()
		}

		resp := map[string]any{
			"client_hello": hello,
			"negotiated": map[string]any{
				"sni":          r.TLS.ServerName,
				"alpn":         r.TLS.NegotiatedProtocol,
				"ech_accepted": r.TLS.ECHAccepted,
				"tls_version":  tls.VersionName(r.TLS.Version),
				"cipher_suite": tls.CipherSuiteName(r.TLS.CipherSuite),
				"did_resume":   r.TLS.DidResume,
				"scts":         len(r.TLS.SignedCertificateTimestamps),
				"ocsp_bytes":   len(r.TLS.OCSPResponse),
			},
			"mTLS": map[string]any{
				"enabled": len(r.TLS.PeerCertificates) > 0,
				"subject": clientSubject,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{
		Addr:      opts.Addr,
		Handler:   mux,
		TLSConfig: tlsConf,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ctxConnKey{}, c)
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				clientHelloStore.Delete(connKey(c))
			}
		},
	}

	log.Printf("start listening on https://%s", opts.Addr)
	log.Fatal(srv.ListenAndServeTLS(opts.TLSCert, opts.TLSKey))
}
