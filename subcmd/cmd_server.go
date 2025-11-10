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
	MTLSAuth      string   `long:"mtls-auth" default:"off" choice:"off" choice:"request" choice:"required" choice:"verify" description:"Client cert auth mode"`
	MTLSClientCA  string   `long:"mtls-ca" description:"mTLS Client CA certificate file path"`
	ECHEnabled    bool     `long:"ech-enabled" description:"Enable ECH (Encrypted Client Hello)"`
	ECHKey        string   `long:"ech-key" description:"Base64-encoded ECH private key"`
	ECHConfig     string   `long:"ech-cfg" description:"Base64-encoded ECH configuration"`
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
	return s.ListenAndServe()
}

func newSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("keygen: %v", err)
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
		return tls.Certificate{}, fmt.Errorf("create cert: %v", err)
	}

	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
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
		certs := make([]map[string]string, len(r.TLS.PeerCertificates))
		for i, v := range r.TLS.PeerCertificates{
			serial := fmt.Sprintf("%X", v.SerialNumber)
			if len(serial)%2 != 0 {
				serial = "0" + serial
			}

			certs[i] = map[string]string{
				"subject": v.Subject.String(),
				"issuer": v.Issuer.String(),
				"serial": serial,
				"not_before": v.NotBefore.String(),
				"not_after": v.NotAfter.String(),
			}
		}

		mtls["enabled"] = true
		mtls["peer_certs"] = certs
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
func (s *Server) ListenAndServe() error {
	tlsConf := &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			s.chiStore.Store(connKey(chi.Conn), clientHelloInfo{
				ServerName:        chi.ServerName,
				SupportedProtos:   chi.SupportedProtos,
				CipherSuites:      mapSliceToString(chi.CipherSuites, toCipherSuiteName),
				SupportedVersions: mapSliceToString(chi.SupportedVersions, toTLSVersionName),
				SignatureSchemes:  mapSliceToString(chi.SignatureSchemes, toSignatureSchemeName),
				Extensions:        mapSliceToString(chi.Extensions, toExtensionName),
			})
			return nil, nil
		},
	}

	if s.opts.TLSCert != "" && s.opts.TLSKey != "" {
		log.Printf("TLS certificate: %s", s.opts.TLSCert)
		log.Printf("TLS private key: %s", s.opts.TLSKey)

		cert, err := tls.LoadX509KeyPair(s.opts.TLSCert, s.opts.TLSKey)
		if err != nil {
			fmt.Errorf("failed to load a key pair: %v", err)
		}

		tlsConf.Certificates = []tls.Certificate{cert}
	} else {
		log.Printf("Generate a new self-signed cert")

		cert, err := newSelfSignedCert()
		if err != nil {
			fmt.Errorf("failed to generate a self signed cert: %v", err)
		}

		tlsConf.Certificates = []tls.Certificate{cert}
	}

	if s.opts.TLSMinVersion != "" {
		log.Printf("Minimal TLS vertion: %s", s.opts.TLSMinVersion)

		version, err := strToTLSVersion(s.opts.TLSMinVersion)
		if err != nil {
			fmt.Errorf("failed to set minimum tls version: %v", err)
		}
		tlsConf.MinVersion = version
	}

	if s.opts.TLSMaxVersion != "" {
		log.Printf("Maximum TLS vertion: %s", s.opts.TLSMaxVersion)

		version, err := strToTLSVersion(s.opts.TLSMaxVersion)
		if err != nil {
			fmt.Errorf("failed to set maximum tls version: %v", err)
		}
		tlsConf.MaxVersion = version
	}

	if len(s.opts.Protocols) > 0 {
		log.Printf("Protocols: %s", s.opts.Protocols)
		tlsConf.NextProtos = s.opts.Protocols
	}

	if len(s.opts.CipherSuites) > 0 {
		log.Printf("CipherSuites: %s", s.opts.CipherSuites)

		suites := make([]uint16, len(s.opts.CipherSuites))
		for i, v := range s.opts.CipherSuites {
			c, err := strToCipherSuite(v)
			if err != nil {
				return err
			}
			suites[i] = c
		}
		tlsConf.CipherSuites = suites
	}

	log.Printf("Client mTLS Auth mode: %s", s.opts.MTLSAuth)
	if s.opts.MTLSAuth != "off" {
		if s.opts.MTLSClientCA == "" {
			fmt.Errorf("--mtls-ca is required to enable mTLS")
		}

		caCert, err := os.ReadFile(s.opts.MTLSClientCA)
		if err != nil {
			fmt.Errorf("failed to load client CA cert: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConf.ClientCAs = caCertPool
	}

	switch s.opts.MTLSAuth {
	case "request":
		tlsConf.ClientAuth = tls.RequestClientCert
	case "required":
		tlsConf.ClientAuth = tls.RequireAnyClientCert
	case "verify":
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		tlsConf.ClientAuth = tls.NoClientCert
	}

	if s.opts.ECHEnabled {
		log.Printf("ECH Enabled: true")

		if s.opts.ECHKey == "" || s.opts.ECHConfig == "" {
			fmt.Errorf("--ech-key and --ech-config is required to enable ECH")
		}

		log.Printf("ECH Key (Base64): '%s'", s.opts.ECHKey)
		key, err := base64.StdEncoding.DecodeString(s.opts.ECHKey)
		if err != nil {
			fmt.Errorf("failed to decode ech-key: %v", err)
		}

		log.Printf("ECH Config (Base64): '%s'", s.opts.ECHConfig)
		cfg, err := base64.StdEncoding.DecodeString(s.opts.ECHConfig)
		if err != nil {
			fmt.Errorf("failed to decode ech-config: %v", err)
		}

		serverKey := tls.EncryptedClientHelloKey{Config: cfg, PrivateKey: key, SendAsRetry: true}
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

	log.Printf("Start listening on https://%s", s.opts.Addr)
	return srv.ListenAndServeTLS("", "")
}
