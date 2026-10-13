package inspect

import (
	"crypto/tls"
	"testing"
)

func TestStrToTLSVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"1.0", tls.VersionTLS10, false},
		{"1.1", tls.VersionTLS11, false},
		{"1.2", tls.VersionTLS12, false},
		{"1.3", tls.VersionTLS13, false},
		{"1.4", 0, true},
		{"unknown", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := strToTLSVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("strToTLSVersion(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("strToTLSVersion(%q) = 0x%04x, want 0x%04x", tt.input, got, tt.want)
			}
		})
	}
}

func TestStrToCipherSuite(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"TLS_AES_128_GCM_SHA256", 0x1301, false},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02b, false},
		{"INVALID_SUITE", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := strToCipherSuite(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("strToCipherSuite(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("strToCipherSuite(%q) = 0x%04x, want 0x%04x", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsGREASE(t *testing.T) {
	tests := []struct {
		id   uint16
		want bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0x2a2a, true},
		{0x3a3a, true},
		{0x4a4a, true},
		{0x5a5a, true},
		{0x6a6a, true},
		{0x7a7a, true},
		{0x8a8a, true},
		{0x9a9a, true},
		{0xaaaa, true},
		{0xbaba, true},
		{0xcaca, true},
		{0xdada, true},
		{0xeaea, true},
		{0xfafa, true},
		{0x1301, false},
		{0x0000, false},
		{0x0017, false},
	}

	for _, tt := range tests {
		if got := isGREASE(tt.id); got != tt.want {
			t.Errorf("isGREASE(0x%04x) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestToCurveIDName(t *testing.T) {
	tests := []struct {
		id   tls.CurveID
		want string
	}{
		{tls.CurveP256, "CurveP256 (0x0017)"},
		{tls.X25519, "X25519 (0x001d)"},
		{tls.X25519MLKEM768, "X25519MLKEM768 (0x11ec)"},
		{tls.CurveID(0x0a0a), "Reserved (GREASE) (0x0a0a)"},
		{tls.CurveID(30), "x448 (0x001e)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := toCurveIDName(tt.id); got != tt.want {
				t.Errorf("toCurveIDName(%v) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}
