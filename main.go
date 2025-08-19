package main

import (
	"os"

	"github.com/haccht/tlsbin/internal/cmd"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	Run     cmd.RunOptions     `command:"run" description:"Run the TLS inspection server"`
	GenEch  cmd.GenEchOptions  `command:"gen-ech" description:"Generate a new key and config for ECH"`
	GenCA   cmd.GenCAOptions   `command:"gen-ca" description:"Generate a new CA certificate and key for mTLS"`
	GenCert cmd.GenCertOptions `command:"gen-cert" description:"Generate a new certificate signed by a CA for mTLS"`
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	parser.SubcommandsOptional = true

	_, err := parser.Parse()
	if err != nil {
		// go-flags automatically prints help on ErrHelp
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		// For other parsing errors, exit
		os.Exit(1)
	}
	if parser.Active == nil {
		parser.WriteHelp(os.Stdout)
		os.Exit(0)
	}
}
