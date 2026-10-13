package inspect

import (
	"crypto/tls"
	"fmt"

	"github.com/gaukas/godicttls"
)

var extTypes = godicttls.DictExtTypeValueIndexed

func init() {
	// Add extension types which are missing in godicttls.
	extTypes[0xfe0d] = "encrypted_client_hello"
	extTypes[0xff01] = "renegotiation_info"
}

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

func strToCipherSuite(v string) (uint16, error) {
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

func toTLSVersionName(id uint16) string {
	if isGREASE(id) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", id)
	}
	return fmt.Sprintf("%s (0x%04x)", tls.VersionName(id), id)
}

func toSignatureSchemeName(v tls.SignatureScheme) string {
	return v.String()
}

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

func toCurveIDName(id tls.CurveID) string {
	u16 := uint16(id)
	if isGREASE(u16) {
		return fmt.Sprintf("Reserved (GREASE) (0x%04x)", u16)
	}
	s := id.String()
	if s != fmt.Sprintf("CurveID(%d)", u16) {
		return fmt.Sprintf("%s (0x%04x)", s, u16)
	}
	if name, ok := godicttls.DictSupportedGroupsValueIndexed[u16]; ok {
		return fmt.Sprintf("%s (0x%04x)", name, u16)
	}
	return fmt.Sprintf("%s (0x%04x)", s, u16)
}

func toCurveIDNameFromUint16(id uint16) string {
	return toCurveIDName(tls.CurveID(id))
}

func mapSliceToString[T any](in []T, f func(T) string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}
