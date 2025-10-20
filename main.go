package main

import (
	"os"

	"github.com/haccht/tlsbin/subcmd"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	Server subcmd.ServerCmd `command:"server" description:"Run the TLS inspection server"`
	Config subcmd.ConfigCmd `command:"config" description:"Generate configuration artifacts (mTLS/ECH)"`
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}
}
