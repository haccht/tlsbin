package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/c2FmZQ/ech"
)

// GenEchOptions holds the options for the gen-ech command.
type GenEchOptions struct {
	PublicName string `long:"public-name" description:"Public name for ECH" default:"localhost"`
}

// Execute runs the gen-ech command.
func (o *GenEchOptions) Execute(args []string) error {
	fmt.Println("Generating new ECH key pair...")

	priv, cfg, err := ech.NewConfig(1, []byte(o.PublicName))
	if err != nil {
		log.Fatalf("Failed to generate ECH config: %v", err)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())

	list, err := ech.ConfigList([]ech.Config{cfg})
	if err != nil {
		log.Fatalf("Failed to create ECH config list: %v", err)
	}
	listB64 := base64.StdEncoding.EncodeToString(list)

	fmt.Println("\nSuccessfully generated ECH keys.")
	fmt.Println("---------------------------------")
	fmt.Println("Add the following flags to the 'run' command to use this static key:")
	fmt.Printf("\n  --ech-key=\"%s\" \\\n", privB64)
	fmt.Printf("  --ech-config-list=\"%s\"\n\n", listB64)

	fmt.Println("Add the following HTTPS record to your DNS for the public name:")
	fmt.Printf("\n  %s. IN HTTPS 1 . ech=\"%s\"\n", o.PublicName, listB64)
	fmt.Println("---------------------------------")

	return nil
}
