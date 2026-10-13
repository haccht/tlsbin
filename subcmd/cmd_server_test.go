package subcmd

import (
	"reflect"
	"testing"

	"github.com/haccht/tlsbin/internal/inspect"
)

func TestServerCmdOptions(t *testing.T) {
	cmd := ServerCmd{
		Addr:          "127.0.0.1:8443",
		TLSCert:       "server.crt",
		TLSKey:        "server.key",
		TLSMinVersion: "1.2",
		TLSMaxVersion: "1.3",
		Protocols:     []string{"h2", "http/1.1"},
		CipherSuites:  []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		MTLSAuth:      "verify",
		MTLSClientCA:  "ca.crt",
		ECHEnabled:    true,
		ECHKey:        "keyB64",
		ECHConfig:     "cfgB64",
	}

	want := inspect.Options{
		Addr:          "127.0.0.1:8443",
		TLSCert:       "server.crt",
		TLSKey:        "server.key",
		TLSMinVersion: "1.2",
		TLSMaxVersion: "1.3",
		Protocols:     []string{"h2", "http/1.1"},
		CipherSuites:  []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		MTLSAuth:      "verify",
		MTLSClientCA:  "ca.crt",
		ECHEnabled:    true,
		ECHKey:        "keyB64",
		ECHConfig:     "cfgB64",
	}

	got := cmd.options()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cmd.options() = %+v, want %+v", got, want)
	}
}
