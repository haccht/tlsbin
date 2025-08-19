package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// GenCertOptions holds the options for the gen-cert command.
type GenCertOptions struct {
	CACert     string        `long:"ca-cert" description:"Path to the CA certificate" default:"ca.crt"`
	CAKey      string        `long:"ca-key" description:"Path to the CA private key" default:"ca.key"`
	CommonName string        `long:"common-name" description:"Common Name for the certificate" default:"localhost"`
	DNSNames   []string      `long:"dns-name" description:"DNS names for the certificate's SAN"`
	IPs        []string      `long:"ip-address" description:"IP addresses for the certificate's SAN"`
	IsClient   bool          `long:"client" description:"Generate a client certificate"`
	ValidFor   time.Duration `long:"valid-for" description:"Duration that certificate is valid for" default:"8760h"` // 1 year
	OutCert    string        `long:"out-cert" description:"Output path for the certificate" default:"server.crt"`
	OutKey     string        `long:"out-key" description:"Output path for the private key" default:"server.key"`
}

// Execute runs the gen-cert command.
func (o *GenCertOptions) Execute(args []string) error {
	// Load CA
	caCertPEM, err := os.ReadFile(o.CACert)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}
	caKeyPEM, err := os.ReadFile(o.CAKey)
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Generate new key for the cert
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(o.ValidFor)

	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if o.IsClient {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	ipAddresses := make([]net.IP, len(o.IPs))
	for i, ipStr := range o.IPs {
		ipAddresses[i] = net.ParseIP(ipStr)
	}
	// ensure localhost is included if no other names are provided
	dnsNames := o.DNSNames
	if len(dnsNames) == 0 && len(ipAddresses) == 0 {
		dnsNames = []string{"localhost"}
	}


	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: o.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		DNSNames: dnsNames,
		IPAddresses: ipAddresses,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(o.OutCert)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", o.OutCert, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Printf("wrote certificate to %s\n", o.OutCert)

	// Write key to file
	keyOut, err := os.OpenFile(o.OutKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", o.OutKey, err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()
	log.Printf("wrote private key to %s\n", o.OutKey)

	return nil
}
