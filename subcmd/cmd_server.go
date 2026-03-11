package subcmd

import "github.com/haccht/tlsbin/internal/inspect"

// ServerCmd holds the command-line options for the 'server' command.
type ServerCmd struct {
	Addr          string   `short:"a" long:"addr" description:"Server address" default:"127.0.0.1:8080"`
	TLSCert       string   `long:"tls-cert" description:"TLS certificate file path"`
	TLSKey        string   `long:"tls-key" description:"TLS key file path"`
	TLSMinVersion string   `long:"tls-min-ver" description:"Minimum TLS version" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	TLSMaxVersion string   `long:"tls-max-ver" description:"Maximum TLS version" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	Protocols     []string `long:"alpn" description:"List of application protocols" choice:"http/1.1" choice:"h2"`
	CipherSuites  []string `long:"cipher" description:"List of ciphersuites (TLS1.3 ciphersuites are not configurable)"`
	MTLSAuth      string   `long:"mtls-auth" default:"off" choice:"off" choice:"request" choice:"required" choice:"verify" choice:"verify-if-given" description:"Client cert auth mode"`
	MTLSClientCA  string   `long:"mtls-ca" description:"mTLS Client CA certificate file path"`
	ECHEnabled    bool     `long:"ech-enabled" description:"Enable ECH (Encrypted Client Hello)"`
	ECHKey        string   `long:"ech-key" description:"Base64-encoded ECH private key"`
	ECHConfig     string   `long:"ech-cfg" description:"Base64-encoded ECH configuration"`
}

// Execute is the entry point for the 'server' command.
func (o *ServerCmd) Execute(args []string) error {
	return inspect.New(o.options()).ListenAndServe()
}

func (o *ServerCmd) options() inspect.Options {
	return inspect.Options{
		Addr:          o.Addr,
		TLSCert:       o.TLSCert,
		TLSKey:        o.TLSKey,
		TLSMinVersion: o.TLSMinVersion,
		TLSMaxVersion: o.TLSMaxVersion,
		Protocols:     o.Protocols,
		CipherSuites:  o.CipherSuites,
		MTLSAuth:      o.MTLSAuth,
		MTLSClientCA:  o.MTLSClientCA,
		ECHEnabled:    o.ECHEnabled,
		ECHKey:        o.ECHKey,
		ECHConfig:     o.ECHConfig,
	}
}
