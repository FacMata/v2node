package panel

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

const validNodeConfig = `{"protocol":"anytls","server_port":40086,"network":"tcp","tls":1,"base_config":{"push_interval":60,"pull_interval":"60"}}`

type nodeReply struct {
	status        int
	body          string
	etag          string
	waitForCancel bool
}

func nodeTestClient(t *testing.T, replies []nodeReply) (*Client, <-chan string) {
	t.Helper()
	var calls atomic.Int32
	headers := make(chan string, len(replies))
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(calls.Add(1)) - 1
		headers <- r.Header.Get("If-None-Match")
		if i >= len(replies) {
			t.Error("unexpected extra configuration request")
			w.WriteHeader(500)
			return
		}
		reply := replies[i]
		if reply.waitForCancel {
			<-r.Context().Done()
			return
		}
		w.Header().Set("ETag", reply.etag)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(reply.status)
		w.Write([]byte(reply.body))
	}))
	t.Cleanup(s.Close)
	return &Client{client: resty.New().SetBaseURL(s.URL).SetTimeout(time.Second), APIHost: s.URL, NodeId: 6}, headers
}

func TestNodeConfigFailureCannotPoisonBaseline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply nodeReply
	}{
		{"502", nodeReply{status: 502, body: "error: SECRET_RESPONSE", etag: `"SECRET_ETAG"`}},
		{"503", nodeReply{status: 503, body: "unavailable", etag: `"bad"`}},
		{"invalid_json", nodeReply{status: 200, body: `{"protocol":`, etag: `"bad"`}},
		{"unsupported_protocol", nodeReply{status: 200, body: `{"protocol":"SECRET_PROTOCOL"}`, etag: `"bad"`}},
		{"missing_base_config", nodeReply{status: 200, body: `{"protocol":"anytls","server_port":40086}`, etag: `"bad"`}},
		{"invalid_interval", nodeReply{status: 200, body: strings.Replace(validNodeConfig, `"pull_interval":"60"`, `"pull_interval":null`, 1), etag: `"bad"`}},
		{"invalid_port", nodeReply{status: 200, body: strings.Replace(validNodeConfig, "40086", "0", 1), etag: `"bad"`}},
		{"timeout", nodeReply{waitForCancel: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, headers := nodeTestClient(t, []nodeReply{{status: 200, body: validNodeConfig, etag: `"a"`}, tc.reply, {status: 200, body: validNodeConfig, etag: `"a"`}})
			n, err := c.GetNodeInfo(context.Background())
			if err != nil || n == nil {
				t.Fatalf("initial config: %v %v", n, err)
			}
			if got := <-headers; got != "" {
				t.Fatalf("initial conditional header %q", got)
			}
			hash, etag := c.responseBodyHash, c.nodeEtag
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			n, err = c.GetNodeInfo(ctx)
			if err == nil || n != nil {
				t.Fatalf("invalid response accepted: %v %v", n, err)
			}
			if tc.reply.waitForCancel && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline semantics lost: %v", err)
			}
			if got := <-headers; got != etag {
				t.Fatalf("failed request header %q", got)
			}
			if c.responseBodyHash != hash || c.nodeEtag != etag {
				t.Fatal("failed response changed validated baseline")
			}
			n, err = c.GetNodeInfo(context.Background())
			if err != nil || n != nil {
				t.Fatalf("unchanged recovery would reload: %v %v", n, err)
			}
			if got := <-headers; got != etag {
				t.Fatalf("recovery sent poisoned ETag: %q", got)
			}
		})
	}
}

func TestNodeConfigChangeAndNotModified(t *testing.T) {
	b := strings.Replace(validNodeConfig, "40086", "40087", 1)
	c, headers := nodeTestClient(t, []nodeReply{{status: 200, body: validNodeConfig, etag: `"a"`}, {status: 200, body: b, etag: `"b"`}, {status: 304}})
	for _, port := range []int{40086, 40087} {
		n, err := c.GetNodeInfo(context.Background())
		if err != nil || n == nil || n.Common.ServerPort != port {
			t.Fatalf("valid change not delivered: %v %v", n, err)
		}
	}
	if <-headers != "" || <-headers != `"a"` {
		t.Fatal("unexpected conditional headers")
	}
	hash := c.responseBodyHash
	n, err := c.GetNodeInfo(context.Background())
	if err != nil || n != nil {
		t.Fatalf("304 caused change: %v %v", n, err)
	}
	if <-headers != `"b"` || c.nodeEtag != `"b"` || c.responseBodyHash != hash {
		t.Fatal("304 changed baseline")
	}
}

func TestNodeConfigUninitialized304AndSafeDiagnostics(t *testing.T) {
	var output bytes.Buffer
	logger := log.StandardLogger()
	old := logger.Out
	logger.SetOutput(&output)
	t.Cleanup(func() { logger.SetOutput(old) })
	c, _ := nodeTestClient(t, []nodeReply{{status: 304}, {status: 502, body: "SECRET_RESPONSE", etag: "SECRET_ETAG"}})
	c.APIHost = "https://example.com/?token=SECRET_TOKEN"
	for i := 0; i < 2; i++ {
		n, err := c.GetNodeInfo(context.Background())
		if err == nil || n != nil || c.responseBodyHash != "" || c.nodeEtag != "" {
			t.Fatalf("invalid initial response accepted: %v %v", n, err)
		}
	}
	for _, s := range []string{"event=node_config_rejected", "node_id=6", "stage=http_status", "http_status=502", "stage=uninitialized_304"} {
		if !strings.Contains(output.String(), s) {
			t.Fatalf("missing diagnostic %q: %s", s, output.String())
		}
	}
	if strings.Contains(output.String(), "SECRET_") || strings.Contains(output.String(), "example.com") {
		t.Fatal("diagnostics exposed response or URL")
	}
}
