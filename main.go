package main

import (
	"os"

	"github.com/jessevdk/go-flags"
)

type Options struct {
	Run     RunOptions    `command:"run" description:"Run the TLS inspection server"`
	GenEch  GenEchOptions `command:"gen-ech" description:"Generate a new static ECH key and config"`
	GenCA   GenCAOptions  `command:"gen-ca" description:"Generate a new CA certificate and key"`
	GenCert GenCertOptions `command:"gen-cert" description:"Generate a new certificate signed by a CA"`
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)

	// Disable the default "command required" error message
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

	// If no subcommand was specified (because SubcommandsOptional is true),
	// print the help message and exit.
	if parser.Active == nil {
		parser.WriteHelp(os.Stdout)
		os.Exit(0)
	}
}
