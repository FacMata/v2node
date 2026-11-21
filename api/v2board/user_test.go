package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/vmihailenco/msgpack/v5"
)

func TestUserListRequiresSuccessfulResponseWithUsersArray(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   any
		valid  bool
	}{
		{"error status with decodable users", 502, map[string]any{"users": []any{}}, false},
		{"missing users", 200, map[string]any{}, false},
		{"null users", 200, map[string]any{"users": nil}, false},
		{"explicit empty users", 200, map[string]any{"users": []any{}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := msgpack.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/x-msgpack")
				w.WriteHeader(tc.status)
				w.Write(payload)
			}))
			defer s.Close()
			c := &Client{client: resty.New().SetBaseURL(s.URL)}
			users, err := c.GetUserList(context.Background())
			if tc.valid {
				if err != nil || users == nil || len(users) != 0 {
					t.Fatalf("users=%v err=%v", users, err)
				}
			} else if err == nil || users != nil {
				t.Fatalf("unusable snapshot accepted: users=%v err=%v", users, err)
			}
		})
	}
}

func TestAliveListDistinguishesFailedSnapshotFromZeroCounts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		valid  bool
	}{
		{"origin error", 502, `{"alive":{}}`, false},
		{"invalid JSON", 200, `<html>`, false},
		{"no alive field", 200, `{}`, false},
		{"explicit zero counts", 200, `{"alive":{}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer s.Close()
			c := &Client{client: resty.New().SetBaseURL(s.URL)}
			got, err := c.GetUserAlive(context.Background())
			if tc.valid {
				if err != nil || got == nil || len(got) != 0 {
					t.Fatalf("got=%v err=%v", got, err)
				}
			} else if err == nil || got != nil {
				t.Fatalf("unusable snapshot accepted: got=%v err=%v", got, err)
			}
		})
	}
}

func TestUserETagRequiresSuccessfulApplication(t *testing.T) {
	const version = `"users-v1"`
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == version {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", version)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[{"id":1,"uuid":"test","device_limit":1}]}`))
	}))
	defer s.Close()
	c := &Client{client: resty.New().SetBaseURL(s.URL)}
	for i := 0; i < 2; i++ {
		users, err := c.GetUserList(context.Background())
		if err != nil || len(users) != 1 {
			t.Fatalf("unconfirmed download %d: %v %v", i, users, err)
		}
	}
	c.ConfirmUserList()
	users, err := c.GetUserList(context.Background())
	if err != nil || users != nil {
		t.Fatalf("confirmed version should return 304: %v %v", users, err)
	}
}
