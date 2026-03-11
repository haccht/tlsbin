package inspect

import "testing"

func TestBuildJA3RawAndHash(t *testing.T) {
	hello := &parsedClientHello{
		legacyVersion:   769,
		cipherSuites:    []uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4},
		extensions:      []uint16{0, 10, 11},
		supportedCurves: []uint16{23, 24, 25},
		supportedPoints: []uint8{0},
	}

	raw := buildJA3Raw(hello)
	if want := "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"; raw != want {
		t.Fatalf("unexpected JA3 raw: got %q want %q", raw, want)
	}

	if got, want := md5Hex(raw), "ada70206e40642a3e4461f35503241d5"; got != want {
		t.Fatalf("unexpected JA3 hash: got %q want %q", got, want)
	}
}

func TestBuildJA4(t *testing.T) {
	hello := &parsedClientHello{
		legacyVersion: 0x0303,
		serverName:    "blog.cloudflare.com",
		cipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
			0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
			0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		extensions: []uint16{
			0x001b, 0x0000, 0x0033, 0x0010, 0x1175, 0x0017,
			0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b,
			0xff01, 0x000b, 0x000a, 0x0015,
		},
		supportedVersions: []uint16{0x0304, 0x0303},
		signatureSchemes:  []uint16{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806},
		supportedProtos:   []string{"h2"},
	}

	raw := buildJA4Raw(hello)
	wantRaw := "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,1175,ff01_0403,0503,0603,0804,0805,0806"
	if raw != wantRaw {
		t.Fatalf("unexpected JA4 raw: got %q want %q", raw, wantRaw)
	}

	if got, want := buildJA4(hello), "t13d1516h2_8daaf6152771_9ce86794d805"; got != want {
		t.Fatalf("unexpected JA4: got %q want %q", got, want)
	}
}
