package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/haccht/tlsbin/internal/server"
)

func TestMain(m *testing.M) {
	// Run the server in the background
	go func() {
		opts := server.RunOptions{
			Addr: "127.0.0.1:8888",
		}
		opts.Execute(nil)
	}()
	// wait for server to start
	time.Sleep(1 * time.Second)

	os.Exit(m.Run())
}

func TestIntegration(t *testing.T) {
	// Create a client that skips certificate verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://127.0.0.1:8888")
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status OK, got %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	if _, ok := data["client_hello"]; !ok {
		t.Error("expected 'client_hello' key in response")
	}
	if _, ok := data["negotiated"]; !ok {
		t.Error("expected 'negotiated' key in response")
	}
}
