package subcmd

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
	"sync"
	"time"
)

// ServerCmd holds the command-line options for the server command
type ServerCmd struct {
	Addr          string   `short:"a" long:"addr" description:"Server address" default:"127.0.0.1:8080"`
	TLSCert       string   `long:"tls-cert" description:"TLS certificate file path"`
	TLSKey        string   `long:"tls-key" description:"TLS key file path"`
	TLSMinVersion string   `long:"tls-min-ver" description:"Minimum TLS version" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	TLSMaxVersion string   `long:"tls-max-ver" description:"Maximum TLS version" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	Protocols     []string `long:"alpn" description:"List of application protocols" choice:"http/1.1" choice:"h2"`
	CipherSuites  []string `long:"cipher" description:"List of ciphersuites (TLS1.3 ciphersuites are not configurable)"`
	MTLSAuth      string   `long:"mtls-auth" default:"off" choice:"off" choice:"request" choice:"require" description:"Client cert auth mode"`
	MTLSClientCA  string   `long:"mtls-ca" description:"mTLS Client CA certificate file path"`
	ECHEnabled    bool     `long:"ech-enabled" description:"Enable ECH (Encrypted Client Hello)"`
	EchKey        string   `long:"ech-key" description:"Base64-encoded ECH private key"`
	EchConfig     string   `long:"ech-cfg" description:"Base64-encoded ECH configuration"`
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
	opts     ServerCmd
	chiStore sync.Map
}

// New creates a new server with the given options.
func New(opts ServerCmd) *Server {
	return &Server{opts: opts}
}

// Execute runs the server command.
func (o *ServerCmd) Execute(args []string) error {
	s := New(*o)
	s.ListenAndServe()
	return nil
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

func (s *Server) handleInspectRequest(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS required", http.StatusBadRequest)
		return
	}

	var chi clientHelloInfo
	if v := r.Context().Value(ctxConnKey{}); v != nil {
		if c, ok := v.(net.Conn); ok {
			if hv, ok := s.chiStore.Load(connKey(c)); ok {
				chi = hv.(clientHelloInfo)
			}
		}
	}

	var mtls = map[string]any{"enabled": false}
	if len(r.TLS.PeerCertificates) > 0 {
		mtls["enabled"] = true
		mtls["subject"] = mapSliceToString(r.TLS.PeerCertificates, func(v *x509.Certificate) string {
			return v.Subject.String()
		})
	}

	resp := map[string]any{
		"client_hello": chi,
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
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(resp)
}

// ListenAndServe starts the TLS server.
func (s *Server) ListenAndServe() {
	tlsConf := &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			s.chiStore.Store(connKey(ch.Conn), clientHelloInfo{
				ServerName:        ch.ServerName,
				SupportedProtos:   ch.SupportedProtos,
				CipherSuites:      mapSliceToString(ch.CipherSuites, toCipherSuiteName),
				SupportedVersions: mapSliceToString(ch.SupportedVersions, toTLSVersionName),
				SignatureSchemes:  mapSliceToString(ch.SignatureSchemes, toSignatureSchemeName),
				Extensions:        mapSliceToString(ch.Extensions, toExtensionName),
			})
			return nil, nil
		},
	}

	if s.opts.TLSCert != "" && s.opts.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(s.opts.TLSCert, s.opts.TLSKey)
		if err != nil {
			log.Fatalf("failed to load key pair: %v", err)
		}

		tlsConf.Certificates = []tls.Certificate{cert}
	} else {
		log.Printf("generating a self signed certificate for this server")
		tlsConf.Certificates = []tls.Certificate{mustSelfSignedCert()}
	}

	if s.opts.TLSMinVersion != "" {
		verion, err := strToTLSVersion(s.opts.TLSMinVersion)
		if err != nil {
			log.Fatalf("failed to set minimum tls version: %v", err)
		}
		tlsConf.MinVersion = verion
	}

	if s.opts.TLSMaxVersion != "" {
		verion, err := strToTLSVersion(s.opts.TLSMaxVersion)
		if err != nil {
			log.Fatalf("failed to set maximum tls version: %v", err)
		}
		tlsConf.MaxVersion = verion
	}

	if len(s.opts.Protocols) > 0 {
		tlsConf.NextProtos = s.opts.Protocols
	}

	if len(s.opts.CipherSuites) > 0 {
		suites := make([]uint16, len(s.opts.CipherSuites))
		for i, v := range s.opts.CipherSuites {
			c, err := strToCipherSuite(v)
			if err != nil {
				log.Fatal(err)
			}
			suites[i] = c
		}
		tlsConf.CipherSuites = suites
	}

	if s.opts.MTLSAuth != "off" {
		if s.opts.MTLSClientCA == "" {
			log.Fatalf("--mtls-ca is required to enable mTLS")
		}

		caCert, err := os.ReadFile(s.opts.MTLSClientCA)
		if err != nil {
			log.Fatalf("failed to load client CA cert: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConf.ClientCAs = caCertPool

		switch s.opts.MTLSAuth {
		case "request":
			tlsConf.ClientAuth = tls.RequestClientCert
		case "required":
			tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	if s.opts.ECHEnabled {
		if s.opts.EchKey == "" || s.opts.EchConfig == "" {
			log.Fatalf("--ech-key and --ech-config is required to enable ECH")
		}

		key, err := base64.StdEncoding.DecodeString(s.opts.EchKey)
		if err != nil {
			log.Fatalf("failed to decode ech-key: %v", err)
		}

		cfg, err := base64.StdEncoding.DecodeString(s.opts.EchConfig)
		if err != nil {
			log.Fatalf("failed to decode ech-config: %v", err)
		}

		serverKey := tls.EncryptedClientHelloKey{PrivateKey: key, Config: cfg}
		tlsConf.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{serverKey}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleInspectRequest)

	srv := &http.Server{
		Addr:      s.opts.Addr,
		Handler:   mux,
		TLSConfig: tlsConf,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ctxConnKey{}, c)
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				s.chiStore.Delete(connKey(c))
			}
		},
	}

	log.Printf("start listening on https://%s", s.opts.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
