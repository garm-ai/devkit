package idp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Serve is what garmstack calls, so the properties the binary relied on
// cobra for have to hold here: a bound address reported back, a server that
// answers, and a cancel that drains rather than cuts.
func TestServeComesUpAndDrains(t *testing.T) {
	addr := make(chan string, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, Config{
			Addr:     "127.0.0.1:0",
			Audience: "garm",
			OnListen: func(a string) { addr <- a },
		})
	}()

	var base string
	select {
	case a := <-addr:
		base = "http://" + a
	case err := <-done:
		t.Fatalf("Serve returned before listening: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Serve never listened")
	}

	resp, err := http.Get(base + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET the key set: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "\"kid\"") {
		t.Fatalf("the key set is %d %s", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v on shutdown, want nil", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Serve did not drain after cancel")
	}
}

// The loopback check is the whole safety story of this server, so it is
// answered before a port is bound or a personas file is read.
func TestServeRefusesANonLoopbackAddress(t *testing.T) {
	err := Serve(t.Context(), Config{Addr: "0.0.0.0:0", PersonasPath: "/no/such/personas.yaml"})
	if err == nil || !strings.Contains(err.Error(), "not a loopback address") {
		t.Fatalf("err = %v, want the bind address refused", err)
	}
}
