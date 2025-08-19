package cmd

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
	"os"
	"time"
)

// GenCAOptions holds the options for the gen-ca command.
type GenCAOptions struct {
	CommonName   string        `long:"common-name" description:"Common Name for the CA" default:"tlsbin-ca"`
	Organization string        `long:"org" description:"Organization for the CA" default:"tlsbin"`
	ValidFor     time.Duration `long:"valid-for" description:"Duration that certificate is valid for" default:"8760h"` // 1 year
	CertPath     string        `long:"cert-path" description:"Output path for the CA certificate" default:"ca.crt"`
	KeyPath      string        `long:"key-path" description:"Output path for the CA private key" default:"ca.key"`
}

// Execute runs the gen-ca command.
func (o *GenCAOptions) Execute(args []string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(o.ValidFor)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{o.Organization},
			CommonName:   o.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut, err := os.Create(o.CertPath)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", o.CertPath, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Printf("wrote CA certificate to %s\n", o.CertPath)

	keyOut, err := os.OpenFile(o.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", o.KeyPath, err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()
	log.Printf("wrote CA private key to %s\n", o.KeyPath)

	return nil
}
