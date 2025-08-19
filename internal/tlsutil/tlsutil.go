package tlsutil

import (
	"crypto/tls"
	"fmt"

	"github.com/gaukas/godicttls"
)

var (
	// ExtTypes is a map of TLS extension IDs to their names.
	ExtTypes = godicttls.DictExtTypeValueIndexed
)

func init() {
	// add extension types which is missing in godicttls
	ExtTypes[0xfe0d] = "encrypted_client_hello"
	ExtTypes[0xff01] = "renegotiation_info"
}

// StrToTLSVersion converts a string representation of a TLS version to its uint16 ID.
func StrToTLSVersion(v string) (uint16, error) {
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

// StrToCipherSuite converts a string representation of a cipher suite to its uint16 ID.
func StrToCipherSuite(v string) (uint16, error) {
	idx, ok := godicttls.DictCipherSuiteNameIndexed[v]
	if !ok {
		return 0, fmt.Errorf("unsupported ciphersuite %s", v)
	}
	return idx, nil
}

func isGREASE(id uint16) bool {
	b := byte(id >> 8)
	return b == byte(id) && (b&0x0f) == 0x0a
}

// ToCipherSuiteName converts a cipher suite ID to its string representation.
func ToCipherSuiteName(id uint16) string {
	if isGREASE(id) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", id)
	}
	name, ok := godicttls.DictCipherSuiteValueIndexed[id]
	if !ok {
		name = "Reserved or Unassigned"
	}
	return fmt.Sprintf("%s (0x%04x)", name, id)
}

// ToTLSVersionName converts a TLS version ID to its string representation.
func ToTLSVersionName(id uint16) string {
	if isGREASE(id) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", id)
	}
	return fmt.Sprintf("%s (0x%04x)", tls.VersionName(id), id)
}

// ToSignatureSchemeName converts a signature scheme to its string representation.
func ToSignatureSchemeName(v tls.SignatureScheme) string {
	return v.String()
}

// ToExtensionName converts a TLS extension ID to its string representation.
func ToExtensionName(id uint16) string {
	if isGREASE(id) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", id)
	}
	name, ok := ExtTypes[id]
	if !ok {
		name = "Reserved or Unassigned"
	}
	return fmt.Sprintf("%s (0x%04x)", name, id)
}

// MapToString applies a function to each element of a slice and returns a new slice of strings.
func MapToString[T any](in []T, f func(T) string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}
