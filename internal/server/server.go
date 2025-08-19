package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

	"github.com/c2FmZQ/ech"
	"github.com/haccht/tlsbin/internal/tlsutil"
)

// RunOptions holds the command-line options for the run command
type RunOptions struct {
	Addr        string   `short:"a" long:"addr" description:"Server address" default:"127.0.0.1:8080"`
	Protocol    []string `long:"alpn" description:"List of application protocols" choice:"h2" choice:"http/1.1"`
	TLSVersion  []string `long:"tls-ver" description:"List of TLS versions" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	CipherSuite []string `long:"cipher" description:"List of ciphersuites (TLS1.3 ciphersuites are not configurable)"`
	EnableMTLS  bool     `long:"enable-mtls" description:"Enable mTLS for client certificate"`
	EnableECH     bool     `long:"enable-ech" description:"Enable Encrypted Client Hello for TLS1.3"`
	EchKey        string   `long:"ech-key" description:"Base64-encoded private key for ECH"`
	EchConfigList string   `long:"ech-config-list" description:"Base64-encoded ECH configuration list"`
	TLSCert       string   `long:"tls-crt" description:"TLS certificate file path"`
	TLSKey      string   `long:"tls-key" description:"TLS key file path"`
	ClientCA    string   `long:"tls-ca" description:"Client CA certificate file path for mTLS"`
}

type clientHelloInfo struct {
	ServerName        string   `json:"sni"`
	SupportedProtos   []string `json:"alpn"`
	SupportedVersions []string `json:"supported_versions"`
	CipherSuites      []string `json:"cipher_suites"`
	SignatureSchemes  []string `json:"sig_schemes"`
	Extensions        []string `json:"extensions"`
}

type ctxConnKey struct{}

func connKey(c net.Conn) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s", c.LocalAddr().String(), c.RemoteAddr().String())
}

// Server is the main server struct
type Server struct {
	opts             RunOptions
	clientHelloStore sync.Map
}

// New creates a new server with the given options.
func New(opts RunOptions) *Server {
	return &Server{opts: opts}
}

// Execute runs the server command.
func (o *RunOptions) Execute(args []string) error {
	s := New(*o)
	s.ListenAndServe()
	return nil
}

// ListenAndServe starts the TLS server.
func (s *Server) ListenAndServe() {
	var certs []tls.Certificate
	if s.opts.TLSCert != "" && s.opts.TLSKey != "" {
		c, err := tls.LoadX509KeyPair(s.opts.TLSCert, s.opts.TLSKey)
		if err != nil {
			log.Fatalf("failed to load key pair: %v", err)
		}
		certs = []tls.Certificate{c}
	} else {
		certs = []tls.Certificate{mustSelfSignedCert()}
	}

	tlsConf := &tls.Config{
		Certificates: certs,
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			s.clientHelloStore.Store(connKey(ch.Conn), clientHelloInfo{
				ServerName:        ch.ServerName,
				SupportedProtos:   ch.SupportedProtos,
				CipherSuites:      tlsutil.MapToString(ch.CipherSuites, tlsutil.ToCipherSuiteName),
				SupportedVersions: tlsutil.MapToString(ch.SupportedVersions, tlsutil.ToTLSVersionName),
				SignatureSchemes:  tlsutil.MapToString(ch.SignatureSchemes, tlsutil.ToSignatureSchemeName),
				Extensions:        tlsutil.MapToString(ch.Extensions, tlsutil.ToExtensionName),
			})
			return nil, nil
		},
	}
	if len(s.opts.Protocol) > 0 {
		tlsConf.NextProtos = s.opts.Protocol
	}
	if len(s.opts.TLSVersion) > 0 {
		var err error
		tlsConf.MinVersion, err = tlsutil.StrToTLSVersion(slices.Min(s.opts.TLSVersion))
		if err != nil {
			log.Fatal(err)
		}
		tlsConf.MaxVersion, err = tlsutil.StrToTLSVersion(slices.Max(s.opts.TLSVersion))
		if err != nil {
			log.Fatal(err)
		}
	}
	if len(s.opts.CipherSuite) > 0 {
		suites := make([]uint16, len(s.opts.CipherSuite))
		for i, v := range s.opts.CipherSuite {
			c, err := tlsutil.StrToCipherSuite(v)
			if err != nil {
				log.Fatal(err)
			}
			suites[i] = c
		}
		tlsConf.CipherSuites = suites
	}
	if s.opts.EnableMTLS {
		if s.opts.ClientCA != "" {
			caCert, err := os.ReadFile(s.opts.ClientCA)
			if err != nil {
				log.Fatalf("failed to read client CA cert: %v", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConf.ClientCAs = caCertPool
			tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConf.ClientAuth = tls.RequestClientCert
		}
	}
	if s.opts.EnableECH {
		var serverKey tls.EncryptedClientHelloKey
		if s.opts.EchKey != "" && s.opts.EchConfigList != "" {
			// Use static key provided by user
			keyBytes, err := base64.StdEncoding.DecodeString(s.opts.EchKey)
			if err != nil {
				log.Fatalf("failed to decode ech-key: %v", err)
			}
			configBytes, err := base64.StdEncoding.DecodeString(s.opts.EchConfigList)
			if err != nil {
				log.Fatalf("failed to decode ech-config-list: %v", err)
			}
			serverKey = tls.EncryptedClientHelloKey{
				PrivateKey: keyBytes,
				Config:     configBytes,
			}
			log.Println("Using static ECH key and config from flags.")
		} else {
			// Generate temporary key
			log.Println("WARNING: Generating temporary ECH key. Use 'gen-ech' subcommand for a static key.")
			publicName := "localhost" // Public name is not configurable for temporary keys
			priv, cfg, err := ech.NewConfig(1, []byte(publicName))
			if err != nil {
				log.Fatalf("ECHconfig: %v", err)
			}

			list, err := ech.ConfigList([]ech.Config{cfg})
			if err != nil {
				log.Fatalf("ECHconfig: %v", err)
			}
			echB64 := base64.StdEncoding.EncodeToString(list)
			log.Printf("Temporary DNS HTTPS record: ech=\"%s\"", echB64)

			serverKey = tls.EncryptedClientHelloKey{Config: list, PrivateKey: priv.Bytes()}
		}
		tlsConf.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{serverKey}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	srv := &http.Server{
		Addr:      s.opts.Addr,
		Handler:   mux,
		TLSConfig: tlsConf,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ctxConnKey{}, c)
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				s.clientHelloStore.Delete(connKey(c))
			}
		},
	}

	log.Printf("start listening on https://%s", s.opts.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS required", http.StatusBadRequest)
		return
	}

	var hello clientHelloInfo
	if v := r.Context().Value(ctxConnKey{}); v != nil {
		if c, ok := v.(net.Conn); ok {
			if hv, ok := s.clientHelloStore.Load(connKey(c)); ok {
				hello = hv.(clientHelloInfo)
			}
		}
	}

	var mtls = map[string]any{"enabled": false}
	if len(r.TLS.PeerCertificates) > 0 {
		mtls["enabled"] = true
		mtls["subject"] = tlsutil.MapToString(r.TLS.PeerCertificates, func(v *x509.Certificate) string {
			return v.Subject.String()
		})
	}

	resp := map[string]any{
		"client_hello": hello,
		"mTLS":         mtls,
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
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func mustSelfSignedCert() tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("keygen: %v", err)
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
