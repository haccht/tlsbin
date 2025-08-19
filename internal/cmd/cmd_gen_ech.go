package cmd

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/c2FmZQ/ech"
)

// GenEchOptions holds the options for the gen-ech command.
type GenEchOptions struct {
	PublicName string `long:"public-name" description:"Public name for ECH" default:"localhost"`
	ConfigID   uint8  `long:"config-id" description:"Config ID of ECH" default:"1"` 
}

// Execute runs the gen-ech command.
func (o *GenEchOptions) Execute(args []string) error {
	fmt.Println("Generating new ECH key pair...")

	_, err := genECHServerKey(o.ConfigID, o.PublicName)
	return err
}

func genECHServerKey(id uint8, name string) (tls.EncryptedClientHelloKey, error) {
	priv, cfg, err := ech.NewConfig(id, []byte(name))
	if err != nil {
		log.Fatalf("Failed to generate ECH config: %v", err)
	}
	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())

	list, err := ech.ConfigList([]ech.Config{cfg})
	if err != nil {
		log.Fatalf("Failed to create ECH config list: %v", err)
	}
	listB64 := base64.StdEncoding.EncodeToString(list)

	fmt.Println("")
	fmt.Println("Successfully generated ECH keys.")
	fmt.Println("---------------------------------")
	fmt.Println("Add the following flags to the 'run' command to use this static key:")
	fmt.Println("")
	fmt.Printf("  --ech-key=\"%s\" \\\n", privB64)
	fmt.Printf("  --ech-config=\"%s\"\n\n", listB64)

	fmt.Println("Add the following HTTPS record to your DNS for the public name:")
	fmt.Printf("\n  %s. IN HTTPS 1 . ech=\"%s\"\n", name, listB64)
	fmt.Println("---------------------------------")

	key := tls.EncryptedClientHelloKey{Config: list, PrivateKey: priv.Bytes()}
	return key, nil
}
