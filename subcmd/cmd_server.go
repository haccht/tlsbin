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

// ServerCmd holds the command-line options for the 'server' command.
type ServerCmd struct {
	Addr          string   `short:"a" long:"addr" description:"Server address" default:"127.0.0.1:8080"`
	TLSCert       string   `long:"tls-cert" description:"TLS certificate file path"`
	TLSKey        string   `long:"tls-key" description:"TLS key file path"`
	TLSMinVersion string   `long:"tls-min-ver" description:"Minimum TLS version" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	TLSMaxVersion string   `long:"tls-max-ver" description:"Maximum TLS version" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	Protocols     []string `long:"alpn" description:"List of application protocols" choice:"http/1.1" choice:"h2"`
	CipherSuites  []string `long:"cipher" description:"List of ciphersuites (TLS1.3 ciphersuites are not configurable)"`
	MTLSAuth      string   `long:"mtls-auth" default:"off" choice:"off" choice:"request" choice:"required" choice:"verify" choice:"verify-if-given" description:"Client cert auth mode"`
	MTLSClientCA  string   `long:"mtls-ca" description:"mTLS Client CA certificate file path"`
	ECHEnabled    bool     `long:"ech-enabled" description:"Enable ECH (Encrypted Client Hello)"`
	ECHKey        string   `long:"ech-key" description:"Base64-encoded ECH private key"`
	ECHConfig     string   `long:"ech-cfg" description:"Base64-encoded ECH configuration"`
}

// clientHelloInfo stores information from the TLS Client Hello message.
type clientHelloInfo struct {
	ServerName        string   `json:"sni"`
	SupportedProtos   []string `json:"alpn"`
	SupportedVersions []string `json:"supported_versions"`
	CipherSuites      []string `json:"cipher_suites"`
	SignatureSchemes  []string `json:"sig_schemes"`
	Extensions        []string `json:"extensions"`
}

// servedCertInfo stores information about the certificate served to the client.
type servedCertInfo struct {
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	Serial     string   `json:"serial"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	DNSNames   []string `json:"dns_names"`
	PubKeyAlgo string   `json:"public_key_algo"`
}

type clientCertInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	Serial     string `json:"serial"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	PubKeyAlgo string `json:"public_key_algo"`
}

type mtlsInfo struct {
	Enabled     bool             `json:"enabled"`
	ClientCerts []clientCertInfo `json:"client_certs,omitempty"`
}

type echInfo struct {
	Accepted bool   `json:"accepted"`
	OuterSNI string `json:"outer_sni,omitempty"`
	InnerSNI string `json:"inner_sni,omitempty"`
}

type negotiatedInfo struct {
	SNI         string  `json:"sni"`
	ECH         echInfo `json:"ech"`
	ALPN        string  `json:"alpn"`
	TLSVersion  string  `json:"tls_version"`
	CipherSuite string  `json:"cipher_suite"`
	DidResume   bool    `json:"did_resume"`
	OCSPBytes   int     `json:"ocsp_bytes"`
	SCTs        int     `json:"scts"`
}

type inspectResponse struct {
	ClientHello clientHelloInfo `json:"client_hello"`
	ServedCert  servedCertInfo  `json:"served_cert"`
	Negotiated  negotiatedInfo  `json:"negotiated"`
	MTLS        mtlsInfo        `json:"mtls"`
}

type ctxConnKey struct{}

func connKey(c net.Conn) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s", c.LocalAddr().String(), c.RemoteAddr().String())
}

// Server represents the TLS inspection server.
type Server struct {
	opts   ServerCmd
	cStore sync.Map
	sStore sync.Map
	oStore sync.Map
}

// New creates a new Server instance.
func New(opts ServerCmd) *Server {
	return &Server{opts: opts}
}

// Execute is the entry point for the 'server' command.
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

// handleResponse handles the HTTP request for inspecting TLS parameters.
// It writes a JSON response with the details of the TLS handshake.
func (s *Server) handleResponse(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS required", http.StatusBadRequest)
		return
	}

	conn := s.connFromContext(r.Context())
	storeKey := connKey(conn)
	outerSNI := s.loadOuterSNI(storeKey)

	resp := inspectResponse{
		ClientHello: s.loadClientHelloInfo(storeKey),
		ServedCert:  s.loadServedCertInfo(storeKey),
		MTLS:        buildMTLSInfo(r.TLS.PeerCertificates),
		Negotiated: negotiatedInfo{
			SNI:         r.TLS.ServerName,
			ECH:         buildECHInfo(r.TLS.ECHAccepted, outerSNI, r.TLS.ServerName),
			ALPN:        r.TLS.NegotiatedProtocol,
			TLSVersion:  tls.VersionName(r.TLS.Version),
			CipherSuite: tls.CipherSuiteName(r.TLS.CipherSuite),
			DidResume:   r.TLS.DidResume,
			OCSPBytes:   len(r.TLS.OCSPResponse),
			SCTs:        len(r.TLS.SignedCertificateTimestamps),
		},
	}

	w.Header().Set("Content-Type", "application/json")

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

// ListenAndServe starts the TLS server.
func (s *Server) ListenAndServe() error {
	conf, err := s.setupTLSConfig()
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleResponse)
	srv := &http.Server{
		Addr:      s.opts.Addr,
		Handler:   mux,
		TLSConfig: conf,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ctxConnKey{}, c)
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				s.cStore.Delete(connKey(c))
			}
		},
	}

	log.Printf("Start listening on https://%s", s.opts.Addr)
	return srv.ListenAndServeTLS("", "")
}

// setupTLSConfig creates a new tls.Config based on the server options.
func (s *Server) setupTLSConfig() (*tls.Config, error) {
	conf := &tls.Config{}
	if err := s.applyCertificate(conf); err != nil {
		return nil, err
	}
	if err := s.applyTLSVersions(conf); err != nil {
		return nil, err
	}
	if err := s.applyProtocols(conf); err != nil {
		return nil, err
	}
	if err := s.applyCipherSuites(conf); err != nil {
		return nil, err
	}
	if err := s.applyMTLS(conf); err != nil {
		return nil, err
	}
	if err := s.applyECH(conf); err != nil {
		return nil, err
	}
	return conf, nil
}

func (s *Server) applyCertificate(conf *tls.Config) error {
	var err error
	var cert tls.Certificate

	if s.opts.TLSCert != "" && s.opts.TLSKey != "" {
		log.Printf("TLS certificate: %s", s.opts.TLSCert)
		log.Printf("TLS private key: %s", s.opts.TLSKey)

		cert, err = tls.LoadX509KeyPair(s.opts.TLSCert, s.opts.TLSKey)
		if err != nil {
			return fmt.Errorf("failed to load a key pair: %w", err)
		}
		return nil
	} else {
		log.Printf("Generate a new self-signed cert")
		cert, err = newSelfSignedCert()
		if err != nil {
			return fmt.Errorf("failed to generate a self signed cert: %w", err)
		}
	}

	conf.Certificates = []tls.Certificate{cert}
	conf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		k := connKey(chi.Conn)
		s.cStore.Store(k, clientHelloInfo{
			ServerName:        chi.ServerName,
			SupportedProtos:   chi.SupportedProtos,
			CipherSuites:      mapSliceToString(chi.CipherSuites, toCipherSuiteName),
			SupportedVersions: mapSliceToString(chi.SupportedVersions, toTLSVersionName),
			SignatureSchemes:  mapSliceToString(chi.SignatureSchemes, toSignatureSchemeName),
			Extensions:        mapSliceToString(chi.Extensions, toExtensionName),
		})

		leaf := ensureLeaf(&cert)
		if leaf != nil {
			s.sStore.Store(k, servedCertInfo{
				Subject:    leaf.Subject.String(),
				Issuer:     leaf.Issuer.String(),
				Serial:     fmt.Sprintf("%X", leaf.SerialNumber),
				NotBefore:  leaf.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:   leaf.NotAfter.UTC().Format(time.RFC3339),
				PubKeyAlgo: leaf.PublicKeyAlgorithm.String(),
				DNSNames:   append([]string(nil), leaf.DNSNames...),
			})
		}
		return nil, nil
	}
	return nil
}

func (s *Server) applyTLSVersions(conf *tls.Config) error {
	if s.opts.TLSMinVersion != "" {
		log.Printf("Minimal TLS version: %s", s.opts.TLSMinVersion)

		version, err := strToTLSVersion(s.opts.TLSMinVersion)
		if err != nil {
			return fmt.Errorf("failed to set minimum tls version: %w", err)
		}
		conf.MinVersion = version
	}

	if s.opts.TLSMaxVersion != "" {
		log.Printf("Maximum TLS version: %s", s.opts.TLSMaxVersion)

		version, err := strToTLSVersion(s.opts.TLSMaxVersion)
		if err != nil {
			return fmt.Errorf("failed to set maximum tls version: %w", err)
		}
		conf.MaxVersion = version
	}

	return nil
}

func (s *Server) applyProtocols(conf *tls.Config) error {
	if len(s.opts.Protocols) == 0 {
		return nil
	}

	log.Printf("Protocols: %s", s.opts.Protocols)
	conf.NextProtos = s.opts.Protocols
	return nil
}

func (s *Server) applyCipherSuites(conf *tls.Config) error {
	if len(s.opts.CipherSuites) == 0 {
		return nil
	}

	log.Printf("CipherSuites: %s", s.opts.CipherSuites)

	suites := make([]uint16, len(s.opts.CipherSuites))
	for i, v := range s.opts.CipherSuites {
		c, err := strToCipherSuite(v)
		if err != nil {
			return err
		}
		suites[i] = c
	}
	conf.CipherSuites = suites
	return nil
}

func (s *Server) applyMTLS(conf *tls.Config) error {
	log.Printf("Client mTLS Auth mode: %s", s.opts.MTLSAuth)
	if s.opts.MTLSAuth == "off" {
		conf.ClientAuth = tls.NoClientCert
		return nil
	}

	if s.opts.MTLSClientCA == "" {
		return fmt.Errorf("--mtls-ca is required to enable mTLS")
	}

	caCert, err := os.ReadFile(s.opts.MTLSClientCA)
	if err != nil {
		return fmt.Errorf("failed to load client CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	conf.ClientCAs = caCertPool

	switch s.opts.MTLSAuth {
	case "request":
		conf.ClientAuth = tls.RequestClientCert
	case "required":
		conf.ClientAuth = tls.RequireAnyClientCert
	case "verify":
		conf.ClientAuth = tls.RequireAndVerifyClientCert
	case "verify-if-given":
		conf.ClientAuth = tls.VerifyClientCertIfGiven
	default:
		conf.ClientAuth = tls.NoClientCert
	}

	return nil
}

func (s *Server) applyECH(conf *tls.Config) error {
	if !s.opts.ECHEnabled {
		return nil
	}

	if s.opts.ECHKey == "" || s.opts.ECHConfig == "" {
		return fmt.Errorf("--ech-key and --ech-config is required to enable ECH")
	}

	log.Printf("ECH Enabled: true")
	log.Printf("ECH Key (Base64): '%s'", s.opts.ECHKey)

	key, err := base64.StdEncoding.DecodeString(s.opts.ECHKey)
	if err != nil {
		return fmt.Errorf("failed to decode ech-key: %w", err)
	}

	log.Printf("ECH Config (Base64): '%s'", s.opts.ECHConfig)
	cfg, err := base64.StdEncoding.DecodeString(s.opts.ECHConfig)
	if err != nil {
		return fmt.Errorf("failed to decode ech-config: %w", err)
	}

	serverKey := tls.EncryptedClientHelloKey{Config: cfg, PrivateKey: key, SendAsRetry: true}
	serverKeys := []tls.EncryptedClientHelloKey{serverKey}
	conf.EncryptedClientHelloKeys = serverKeys

	conf.GetEncryptedClientHelloKeys = func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		k := connKey(chi.Conn)
		s.oStore.LoadOrStore(k, chi.ServerName)
		return serverKeys, nil
	}
	return nil
}

func ensureLeaf(cert *tls.Certificate) *x509.Certificate {
	if cert.Leaf != nil {
		return cert.Leaf
	}
	if len(cert.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Printf("failed to parse leaf certificate: %v", err)
		return nil
	}
	cert.Leaf = leaf
	return leaf
}

func (s *Server) connFromContext(ctx context.Context) net.Conn {
	if ctx == nil {
		return nil
	}
	if conn, ok := ctx.Value(ctxConnKey{}).(net.Conn); ok {
		return conn
	}
	return nil
}

func (s *Server) loadOuterSNI(key string) string {
	v, _ := s.oStore.Load(key)
	info, _ := v.(string)
	return info
}

func (s *Server) loadClientHelloInfo(key string) clientHelloInfo {
	v, _ := s.cStore.Load(key)
	info, _ := v.(clientHelloInfo)
	return info
}

func (s *Server) loadServedCertInfo(key string) servedCertInfo {
	v, _ := s.sStore.Load(key)
	info, _ := v.(servedCertInfo)
	return info
}

func buildMTLSInfo(peerCerts []*x509.Certificate) mtlsInfo {
	if len(peerCerts) == 0 {
		return mtlsInfo{Enabled: false}
	}

	certs := make([]clientCertInfo, len(peerCerts))
	for i, v := range peerCerts {
		certs[i] = clientCertInfo{
			Subject:    v.Subject.String(),
			Issuer:     v.Issuer.String(),
			Serial:     fmt.Sprintf("%X", v.SerialNumber),
			NotBefore:  v.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:   v.NotAfter.UTC().Format(time.RFC3339),
			PubKeyAlgo: v.PublicKeyAlgorithm.String(),
		}
	}

	return mtlsInfo{
		Enabled:     true,
		ClientCerts: certs,
	}
}

func buildECHInfo(accepted bool, outerSNI, innerSNI string) echInfo {
	if !accepted {
		return echInfo{Accepted: false}
	}

	return echInfo{
		Accepted: true,
		OuterSNI: outerSNI,
		InnerSNI: innerSNI,
	}
}
