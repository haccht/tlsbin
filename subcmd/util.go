package subcmd

import (
	"crypto/tls"
	"fmt"

	"github.com/gaukas/godicttls"
)

var (
	extTypes = godicttls.DictExtTypeValueIndexed
)

func init() {
	// add extension types which is missing in godicttls
	extTypes[0xfe0d] = "encrypted_client_hello"
	extTypes[0xff01] = "renegotiation_info"
}

// strToTLSVersion converts a string representation of a TLS version to its
// corresponding uint16 constant.
func strToTLSVersion(v string) (uint16, error) {
	switch v {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("unsupported TLS version %s", v)
}

// strToCipherSuite converts a string representation of a cipher suite to its
// corresponding uint16 constant.
func strToCipherSuite(v string) (uint16, error) {
	idx, ok := godicttls.DictCipherSuiteNameIndexed[v]
	if !ok {
		return 0, fmt.Errorf("unsupported ciphersuite %s", v)
	}
	return idx, nil
}

// isGREASE checks if a given uint16 value is a GREASE (Generate Random Extensions
// And Sustain Extensibility) value.
func isGREASE(id uint16) bool {
	b := byte(id >> 8)
	return b == byte(id) && (b&0x0f) == 0x0a
}

// toCipherSuiteName converts a uint16 representation of a cipher suite to its
// string name.
func toCipherSuiteName(id uint16) string {
	if isGREASE(id) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", id)
	}
	name, ok := godicttls.DictCipherSuiteValueIndexed[id]
	if !ok {
		name = "Reserved or Unassigned"
	}
	return fmt.Sprintf("%s (0x%04x)", name, id)
}

// toTLSVersionName converts a uint16 representation of a TLS version to its
// string name.
func toTLSVersionName(id uint16) string {
	if isGREASE(id) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", id)
	}
	return fmt.Sprintf("%s (0x%04x)", tls.VersionName(id), id)
}

// toSignatureSchemeName converts a tls.SignatureScheme to its string name.
func toSignatureSchemeName(v tls.SignatureScheme) string {
	return v.String()
}

// toExtensionName converts a uint16 representation of a TLS extension to its
// string name.
func toExtensionName(id uint16) string {
	if isGREASE(id) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", id)
	}
	name, ok := extTypes[id]
	if !ok {
		name = "Reserved or Unassigned"
	}
	return fmt.Sprintf("%s (0x%04x)", name, id)
}

// mapSliceToString applies a function to each element of a slice and returns a
// new slice of strings.
func mapSliceToString[T any](in []T, f func(T) string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}
