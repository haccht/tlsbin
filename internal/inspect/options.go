package inspect

// Options holds the runtime configuration for the inspection server.
type Options struct {
	Addr          string
	TLSCert       string
	TLSKey        string
	TLSMinVersion string
	TLSMaxVersion string
	Protocols     []string
	CipherSuites  []string
	MTLSAuth      string
	MTLSClientCA  string
	ECHEnabled    bool
	ECHKey        string
	ECHConfig     string
}
