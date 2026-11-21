package dispatcher

import (
	"context"
	"io"
	stdnet "net"
	"strings"
	"testing"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/limiter"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestAnyTLSClosesCachedTransportOnlyForMissingUser(t *testing.T) {
	for _, tc := range []struct {
		name           string
		protocol       string
		remove         bool
		reason         string
		closeTransport bool
	}{
		{"revoked", "anytls", true, "user_missing", true},
		{"device limit", "anytls", false, "device_limit", false},
		{"other protocol", "vless", true, "user_missing", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limiter.Init()
			const tag = "node"
			user := panel.UserInfo{Id: 1, Uuid: "user", DeviceLimit: 1}
			l := limiter.AddLimiter(tc.protocol, tag, []panel.UserInfo{user}, map[int]int{user.Id: 1})
			if tc.remove {
				l.UpdateUser(tag, nil, []panel.UserInfo{user}, nil)
			}
			server, client := stdnet.Pipe()
			defer server.Close()
			defer client.Close()
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
				Source: net.TCPDestination(net.ParseAddress("192.0.2.1"), 12345),
				Tag:    tag,
				Name:   tc.protocol,
				User:   &protocol.MemoryUser{Email: format.UserTag(tag, user.Uuid)},
				Conn:   server,
			})
			_, _, _, err := (&DefaultDispatcher{}).getLink(ctx, false)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("want %s, got %v", tc.reason, err)
			}
			if tc.closeTransport {
				client.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := client.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("old transport still open: %v", err)
				}
			} else if err := server.SetDeadline(time.Time{}); err != nil {
				t.Fatalf("transport was closed: %v", err)
			}
		})
	}
}
