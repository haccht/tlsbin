package subcmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/c2FmZQ/ech"
)

// ConfigCmd holds the options for the 'config' command.
type ConfigCmd struct {
	ECH  ConfigECHCmd  `command:"ech"  description:"Configure ECH key"`
	MTLS ConfigMTLSCmd `command:"mtls" description:"Configure mTLS key"`
}

// ConfigECHCmd holds the options for the 'config ech' command.
type ConfigECHCmd struct {
	ConfigID   uint8  `long:"config-id" description:"ConfigID for ECH" default:"1"`
	PublicName string `long:"public-name" description:"PublicName for ECH" required:"true"`
}

// Execute runs the gen-ech command.
func (o *ConfigECHCmd) Execute(args []string) error {
	log.Println("Generating a new ECH key pair...")

	key, cfg, err := ech.NewConfig(o.ConfigID, []byte(o.PublicName))
	if err != nil {
		return fmt.Errorf("Failed to generate ECH config: %v", err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key.Bytes())
	cfgB64 := base64.StdEncoding.EncodeToString([]byte(cfg))

	list, err := ech.ConfigList([]ech.Config{cfg})
	if err != nil {
		return fmt.Errorf("Failed to create ECH config list: %v", err)
	}
	listB64 := base64.StdEncoding.EncodeToString(list)

	fmt.Println("")
	fmt.Println("Successfully generated a ECH key pair.")
	fmt.Println("---------------------------------")
	fmt.Println("Add the following flags to the 'server' command to use this static key:")
	fmt.Println("")
	fmt.Printf("  --ech-key=\"%s\" \\\n", keyB64)
	fmt.Printf("  --ech-cfg=\"%s\"\n\n", cfgB64)

	fmt.Println("Add the following HTTPS record to your zone for the backend FQDN:")
	fmt.Println("")
	fmt.Printf("  IN HTTPS 1 . ech=\"%s\"\n", listB64)
	fmt.Println("---------------------------------")

	return nil
}

// ConfigMTLSCmd holds the options for the 'config mtls' command.
type ConfigMTLSCmd struct {
	CommonName   string        `long:"cn" description:"Common Name for the CA" default:"tlsbin.net"`
	Organization string        `long:"org" description:"Organization for the CA" default:"tlsbin"`
	ValidFor     time.Duration `long:"valid-for" description:"Duration the CA certificate is valid for" default:"8760h"` // 1 year
	CACertPath   string        `long:"ca-cert" description:"Path to the CA certificate" default:"ca.crt"`
	CAKeyPath    string        `long:"ca-key" description:"Path to the CA private key" default:"ca.key"`
}

func (o *ConfigMTLSCmd) Execute(args []string) error {
	log.Println("Generating a new CA key pair...")

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
			CommonName:   o.CommonName,
			Organization: []string{o.Organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create a certificate: %w", err)
	}

	certOut, err := os.Create(o.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", o.CACertPath, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(o.CAKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", o.CAKeyPath, err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	fmt.Println("")
	fmt.Println("Successfully generated a CA key pair.")
	fmt.Println("---------------------------------")
	fmt.Println("Generate a client certificate to authenticate client with this CA")
	fmt.Println("")
	fmt.Println("$ openssl genrsa -out client.key 2048")
	fmt.Println("$ openssl req -new -key client.key -out client.csr -subj 'CN=/client-name.tlsbin.net'")
	fmt.Printf("$ openssl x509 -req -CA %s -CAkey %s -CAcreateserial \\\n", o.CACertPath, o.CAKeyPath)
	fmt.Println("    -in client.csr -out client.crt -days 365 -sha256 -extfile <(echo \"extendedKeyUsage = clientAuth\")")
	fmt.Println("---------------------------------")

	return nil
}
