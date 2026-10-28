package inspect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
)

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

func TestObservedListenerSurvivesMalformedConnections(t *testing.T) {
	s := New(Options{Addr: "127.0.0.1:0"})
	conf, err := s.setupTLSConfig()
	if err != nil {
		t.Fatalf("setupTLSConfig() error = %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleResponse)
	srv := &http.Server{
		Handler:   mux,
		TLSConfig: conf,
		ErrorLog:  log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			var state *connectionStateData
			if tc, ok := c.(*tls.Conn); ok {
				if pc, ok := tc.NetConn().(*prefixConn); ok {
					state = pc.state
				}
			}
			return context.WithValue(ctx, ctxStateKey{}, state)
		},
	}

	tlsLn := tls.NewListener(newObservedListener(ln), conf)
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- srv.Serve(tlsLn)
	}()
	defer srv.Close()

	addr := ln.Addr().String()

	// 1. Immediate EOF without sending any bytes.
	c1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial c1 error = %v", err)
	}
	_ = c1.Close()

	// 2. SSLv2 ClientHello (record type 128 = 0x80) with large fake length in bytes 3..4.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial c2 error = %v", err)
	}
	_, _ = c2.Write([]byte{0x80, 0x2e, 0x01, 0xff, 0xff})
	_, _ = io.Copy(io.Discard, c2)
	_ = c2.Close()

	// 3. Idle connection that sends nothing should not block subsequent connections.
	c3, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial c3 error = %v", err)
	}
	defer c3.Close()

	// 4. Valid HTTPS request should succeed and return fingerprints.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "localhost",
			},
		},
	}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTTPS GET error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got inspectResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response error = %v", err)
	}
	if got.Fingerprint.JA3 == "" || got.Fingerprint.JA4 == "" {
		t.Fatalf("expected non-empty fingerprints, got %+v", got.Fingerprint)
	}

	select {
	case err := <-serveErrCh:
		t.Fatalf("srv.Serve exited unexpectedly: %v", err)
	default:
	}
}

func TestCaptureClientHelloNonHandshakeDoesNotReadPayload(t *testing.T) {
	// Record type 128 (0x80) with bytes 3..4 = 0x2000 (8192 bytes), but only 5 bytes available.
	input := []byte{0x80, 0x2e, 0x01, 0x20, 0x00}
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		_, _ = clientConn.Write(input)
	}()

	wrapped, hello, err := captureClientHello(serverConn, &connectionStateData{})
	if err == nil {
		t.Fatal("expected error for non-handshake record type, got nil")
	}
	if hello != nil {
		t.Fatalf("expected nil hello, got %+v", hello)
	}

	replayed := make([]byte, len(input))
	if _, err := io.ReadFull(wrapped, replayed); err != nil {
		t.Fatalf("failed to read replayed bytes: %v", err)
	}
	if !bytes.Equal(replayed, input) {
		t.Fatalf("replayed bytes = %x, want %x", replayed, input)
	}
}
