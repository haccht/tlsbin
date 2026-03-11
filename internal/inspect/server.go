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
	DidResume                   bool    `json:"did_resume"`
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

type ctxConnKey struct{}

func connKey(c net.Conn) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s", c.LocalAddr().String(), c.RemoteAddr().String())
}

type Server struct {
	opts   Options
	oStore sync.Map
	cStore sync.Map
	sStore sync.Map
	fStore sync.Map
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
			return context.WithValue(ctx, ctxConnKey{}, c)
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				key := connKey(c)
				s.oStore.Delete(key)
				s.cStore.Delete(key)
				s.sStore.Delete(key)
				s.fStore.Delete(key)
			}
		},
	}

	log.Printf("Start listening on https://%s", s.opts.Addr)
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return err
	}

	tlsLn := tls.NewListener(newObservedListener(ln, s), conf)
	return srv.Serve(tlsLn)
}

func (s *Server) handleResponse(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS required", http.StatusBadRequest)
		return
	}

	conn := s.connFromContext(r.Context())
	storeKey := connKey(conn)

	resp := inspectResponse{
		ClientHello: s.loadClientHelloInfo(storeKey),
		ServedCert:  s.loadServedCertInfo(storeKey),
		MTLS:        buildMTLSInfo(r.TLS.PeerCertificates),
		Fingerprint: s.loadFingerprintInfo(storeKey),
		Negotiated: negotiatedInfo{
			SNI:                         r.TLS.ServerName,
			ECH:                         buildECHInfo(r.TLS.ECHAccepted, s.loadOuterSNI(storeKey), r.TLS.ServerName),
			ALPN:                        r.TLS.NegotiatedProtocol,
			TLSVersion:                  tls.VersionName(r.TLS.Version),
			CipherSuite:                 tls.CipherSuiteName(r.TLS.CipherSuite),
			DidResume:                   r.TLS.DidResume,
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
		key := connKey(chi.Conn)
		s.cStore.Store(key, clientHelloInfo{
			ServerName:        chi.ServerName,
			SupportedProtos:   chi.SupportedProtos,
			CipherSuites:      mapSliceToString(chi.CipherSuites, toCipherSuiteName),
			SupportedVersions: mapSliceToString(chi.SupportedVersions, toTLSVersionName),
			SignatureSchemes:  mapSliceToString(chi.SignatureSchemes, toSignatureSchemeName),
			Extensions:        mapSliceToString(chi.Extensions, toExtensionName),
		})
		if v := ensureLeaf(&cert); v != nil {
			s.sStore.Store(key, servedCertInfo{
				Subject:    v.Subject.String(),
				Issuer:     v.Issuer.String(),
				Serial:     fmt.Sprintf("%X", v.SerialNumber),
				NotBefore:  v.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:   v.NotAfter.UTC().Format(time.RFC3339),
				PubKeyAlgo: v.PublicKeyAlgorithm.String(),
				DNSNames:   append([]string(nil), v.DNSNames...),
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
		s.oStore.LoadOrStore(connKey(chi.Conn), chi.ServerName)
		return serverKeys, nil
	}
	return nil
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
	conn, _ := ctx.Value(ctxConnKey{}).(net.Conn)
	return conn
}

func (s *Server) loadOuterSNI(key string) string {
	v, _ := s.oStore.Load(key)
	info, _ := v.(string)
	return info
}

func (s *Server) loadFingerprintInfo(key string) fingerprintInfo {
	v, _ := s.fStore.Load(key)
	info, _ := v.(fingerprintInfo)
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
