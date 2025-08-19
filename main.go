package main

import (
	"os"

	"github.com/haccht/tlsbin/internal/server"
	"github.com/jessevdk/go-flags"
)

func main() {
	var opts server.Options
	_, err := flags.Parse(&opts)
	if err != nil {
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	s := server.New(opts)
	s.ListenAndServe()
}
