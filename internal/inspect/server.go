package inspect

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

type clientHelloInfo struct {
	ServerName        string   `json:"sni"`
	SupportedProtos   []string `json:"alpn"`
	SupportedVersions []string `json:"supported_versions"`
	CipherSuites      []string `json:"cipher_suites"`
	SupportedCurves   []string `json:"supported_curves,omitempty"`
	SignatureSchemes  []string `json:"signature_schemes"`
	Extensions        []string `json:"extensions"`
}

type fingerprintInfo struct {
	JA3    string `json:"ja3"`
	JA3Raw string `json:"ja3_raw"`
	JA4    string `json:"ja4"`
	JA4Raw string `json:"ja4_raw"`
}

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
	SNI                         string  `json:"sni"`
	ECH                         echInfo `json:"ech"`
	ALPN                        string  `json:"alpn"`
	TLSVersion                  string  `json:"tls_version"`
	CipherSuite                 string  `json:"cipher_suite"`
	KeyExchange                 string  `json:"key_exchange,omitempty"`
	DidResume                   bool    `json:"did_resume"`
	HelloRetryRequest           bool    `json:"hello_retry_request"`
	TLSUnique                   string  `json:"tls_unique,omitempty"`
	OCSPBytes                   int     `json:"ocsp_bytes"`
	SignedCertificateTimestamps int     `json:"signed_certificate_timestamps"`
}

type inspectResponse struct {
	ClientHello clientHelloInfo `json:"client_hello"`
	ServedCert  servedCertInfo  `json:"served_cert"`
	Negotiated  negotiatedInfo  `json:"negotiated"`
	MTLS        mtlsInfo        `json:"mtls"`
	Fingerprint fingerprintInfo `json:"fingerprint"`
}

type connectionStateData struct {
	mu          sync.Mutex
	outerSNI    string
	clientHello clientHelloInfo
	servedCert  servedCertInfo
	fingerprint fingerprintInfo
}

type ctxStateKey struct{}

type Server struct {
	opts Options
}

func New(opts Options) *Server {
	return &Server{opts: opts}
}

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
			var state *connectionStateData
			if tc, ok := c.(*tls.Conn); ok {
				if pc, ok := tc.NetConn().(*prefixConn); ok {
					state = pc.state
				}
			}
			return context.WithValue(ctx, ctxStateKey{}, state)
		},
	}

	log.Printf("Start listening on https://%s", s.opts.Addr)
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return err
	}

	tlsLn := tls.NewListener(newObservedListener(ln), conf)
	return srv.Serve(tlsLn)
}

func (s *Server) handleResponse(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS required", http.StatusBadRequest)
		return
	}

	state := s.stateFromContext(r.Context())

	var outerSNI string
	var clientHello clientHelloInfo
	var servedCert servedCertInfo
	var fingerprint fingerprintInfo

	if state != nil {
		state.mu.Lock()
		outerSNI = state.outerSNI
		clientHello = state.clientHello
		servedCert = state.servedCert
		fingerprint = state.fingerprint
		state.mu.Unlock()
	}

	var keyExchange string
	if r.TLS.CurveID != 0 {
		keyExchange = toCurveIDName(r.TLS.CurveID)
	}

	var tlsUnique string
	if len(r.TLS.TLSUnique) > 0 {
		tlsUnique = fmt.Sprintf("%x", r.TLS.TLSUnique)
	}

	resp := inspectResponse{
		ClientHello: clientHello,
		ServedCert:  servedCert,
		MTLS:        buildMTLSInfo(r.TLS.PeerCertificates),
		Fingerprint: fingerprint,
		Negotiated: negotiatedInfo{
			SNI:                         r.TLS.ServerName,
			ECH:                         buildECHInfo(r.TLS.ECHAccepted, outerSNI, r.TLS.ServerName),
			ALPN:                        r.TLS.NegotiatedProtocol,
			TLSVersion:                  tls.VersionName(r.TLS.Version),
			CipherSuite:                 tls.CipherSuiteName(r.TLS.CipherSuite),
			KeyExchange:                 keyExchange,
			DidResume:                   r.TLS.DidResume,
			HelloRetryRequest:           r.TLS.HelloRetryRequest,
			TLSUnique:                   tlsUnique,
			OCSPBytes:                   len(r.TLS.OCSPResponse),
			SignedCertificateTimestamps: len(r.TLS.SignedCertificateTimestamps),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

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
	var (
		cert tls.Certificate
		err  error
	)

	if s.opts.TLSCert != "" && s.opts.TLSKey != "" {
		log.Printf("TLS certificate: %s", s.opts.TLSCert)
		log.Printf("TLS private key: %s", s.opts.TLSKey)

		cert, err = tls.LoadX509KeyPair(s.opts.TLSCert, s.opts.TLSKey)
		if err != nil {
			return fmt.Errorf("failed to load a key pair: %w", err)
		}
	} else {
		log.Printf("Generate a new self-signed cert")
		cert, err = newSelfSignedCert()
		if err != nil {
			return fmt.Errorf("failed to generate a self signed cert: %w", err)
		}
	}

	conf.Certificates = []tls.Certificate{cert}
	conf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if pc, ok := chi.Conn.(*prefixConn); ok && pc.state != nil {
			pc.state.mu.Lock()
			pc.state.clientHello = clientHelloInfo{
				ServerName:        chi.ServerName,
				SupportedProtos:   chi.SupportedProtos,
				CipherSuites:      mapSliceToString(chi.CipherSuites, toCipherSuiteName),
				SupportedCurves:   mapSliceToString(chi.SupportedCurves, toCurveIDName),
				SupportedVersions: mapSliceToString(chi.SupportedVersions, toTLSVersionName),
				SignatureSchemes:  mapSliceToString(chi.SignatureSchemes, toSignatureSchemeName),
				Extensions:        mapSliceToString(chi.Extensions, toExtensionName),
			}
			if v := ensureLeaf(&cert); v != nil {
				pc.state.servedCert = servedCertInfo{
					Subject:    v.Subject.String(),
					Issuer:     v.Issuer.String(),
					Serial:     fmt.Sprintf("%X", v.SerialNumber),
					NotBefore:  v.NotBefore.UTC().Format(time.RFC3339),
					NotAfter:   v.NotAfter.UTC().Format(time.RFC3339),
					PubKeyAlgo: v.PublicKeyAlgorithm.String(),
					DNSNames:   append([]string(nil), v.DNSNames...),
				}
			}
			pc.state.mu.Unlock()
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
	if s.opts.MTLSAuth == "off" || s.opts.MTLSAuth == "" {
		if s.opts.MTLSClientCA != "" {
			return fmt.Errorf("--mtls-ca is specified but --mtls-auth is off")
		}
		conf.ClientAuth = tls.NoClientCert
		return nil
	}

	if s.opts.MTLSClientCA == "" {
		return fmt.Errorf("--mtls-ca is required when --mtls-auth is %s", s.opts.MTLSAuth)
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
		return fmt.Errorf("--ech-key and --ech-cfg are required to enable ECH")
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
		return fmt.Errorf("failed to decode ech-cfg: %w", err)
	}

	serverKeys := []tls.EncryptedClientHelloKey{{
		Config:      cfg,
		PrivateKey:  key,
		SendAsRetry: true,
	}}
	conf.EncryptedClientHelloKeys = serverKeys
	conf.GetEncryptedClientHelloKeys = func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		if pc, ok := chi.Conn.(*prefixConn); ok && pc.state != nil {
			pc.state.mu.Lock()
			pc.state.outerSNI = chi.ServerName
			pc.state.mu.Unlock()
		}
		return serverKeys, nil
	}
	return nil
}

func newSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("keygen: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
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

func (s *Server) stateFromContext(ctx context.Context) *connectionStateData {
	if ctx == nil {
		return nil
	}
	st, _ := ctx.Value(ctxStateKey{}).(*connectionStateData)
	return st
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
