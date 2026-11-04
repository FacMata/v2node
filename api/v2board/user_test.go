package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
)

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
