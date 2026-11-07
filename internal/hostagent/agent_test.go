package hostagent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityDurableSequenceAndPrivateMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := lockDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	if other, err := lockDirectory(dir); err == nil {
		other.Unlock()
		t.Fatal("second agent acquired the lock")
	}
	state := identity{HostID: "test", Token: strings.Repeat("a", 64), Generation: 1, Sequence: 9}
	if err := saveIdentity(dir, state); err != nil {
		t.Fatal(err)
	}
	var restored identity
	path := filepath.Join(dir, "identity.json")
	if err := secureRead(path, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Sequence != 9 || restored.Token != state.Token {
		t.Fatal("identity/sequence changed")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := secureRead(path, &restored); err == nil {
		t.Fatal("public identity accepted")
	}
}

func TestPanelOriginAndRedirectBoundary(t *testing.T) {
	for _, value := range []string{"http://panel.invalid", "https://user:secret@panel.invalid", "https://panel.invalid/path", "https://panel.invalid?token=secret"} {
		if checkPanel(value) == nil {
			t.Fatalf("accepted unsafe origin %q", value)
		}
	}
	if err := checkPanel("https://panel.invalid"); err != nil {
		t.Fatal(err)
	}
	var targetCalled bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalled = true }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := newClient()
	client.Transport = server.Client().Transport // Test-only CA, no production bypass.
	err := post(context.Background(), client, server.URL, "heartbeat", "sensitive-test-token", struct{}{}, new(any))
	if err == nil || targetCalled || strings.Contains(err.Error(), "sensitive-test-token") {
		t.Fatal("redirect or credential leak")
	}
}

func TestWireAllowsNoSecretInventory(t *testing.T) {
	obs := observation{LocalNodes: []nodeRef{{ServerType: "v2node", ServerID: 7}}, ExternalNodeCount: 2}
	data, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ApiKey", "ApiHost", "host_token", "external_nodes"} {
		if strings.Contains(string(data), key) {
			t.Fatal("wire exposes secret inventory")
		}
	}
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[19] = "2468"
	if processStart([]byte("123 (v2node worker) "+strings.Join(fields, " "))) != "2468" {
		t.Fatal("start time parse failed")
	}
}
