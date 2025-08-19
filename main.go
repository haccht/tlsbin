package main

import (
	"os"

	"github.com/haccht/tlsbin/internal/server"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	Run    server.RunOptions    `command:"run" description:"Run the TLS inspection server"`
	GenEch server.GenEchOptions `command:"gen-ech" description:"Generate a new static ECH key and config"`
	GenCA   server.GenCAOptions   `command:"gen-ca" description:"Generate a new CA certificate and key"`
	GenCert server.GenCertOptions `command:"gen-cert" description:"Generate a new certificate signed by a CA"`
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)

	// Make "run" the default command if no command is specified
	// This is a common pattern for go-flags
	if len(os.Args) > 1 {
		// Check if the first argument is a known command
		isKnownCommand := false
		for _, cmd := range parser.Commands() {
			if cmd.Name == os.Args[1] {
				isKnownCommand = true
				break
			}
		}
		// If it's not a command, assume it's an option for the default 'run' command
		if !isKnownCommand {
			// Prepend 'run' to the arguments
			args := make([]string, len(os.Args)+1)
			args[0] = os.Args[0]
			args[1] = "run"
			copy(args[2:], os.Args[1:])
			os.Args = args
		}
	} else {
		// No arguments, default to 'run'
		os.Args = append(os.Args, "run")
	}


	_, err := parser.Parse()
	if err != nil {
		// go-flags prints help message on ErrHelp
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}
}
