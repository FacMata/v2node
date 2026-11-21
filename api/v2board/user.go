package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/vmihailenco/msgpack/v5"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	TrafficBudget bool   `json:"traffic_budget" msgpack:"traffic_budget"`
	Id            int    `json:"id" msgpack:"id"`
	Uuid          string `json:"uuid" msgpack:"uuid"`
	SpeedLimit    int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit   int    `json:"device_limit" msgpack:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList(ctx context.Context) ([]UserInfo, error) {
	const path = "/api/v1/server/UniProxy/user"
	r, err := c.client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.userEtag).
		SetHeader("X-Response-Format", "msgpack").
		SetHeader("X-Traffic-Budget", "1").
		SetDoNotParseResponse(true).
		Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("received nil response or raw response")
	}
	defer r.RawResponse.Body.Close()

	if r.StatusCode() == http.StatusNotModified {
		return nil, nil
	}
	if r.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("user list returned HTTP %d", r.StatusCode())
	}
	userlist := &UserListBody{}
	if strings.Contains(r.Header().Get("Content-Type"), "application/x-msgpack") {
		decoder := msgpack.NewDecoder(r.RawResponse.Body)
		if err := decoder.Decode(userlist); err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
	} else {
		dec := jsontext.NewDecoder(r.RawResponse.Body)
		for {
			tok, err := dec.ReadToken()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: %w", err)
			}
			if tok.Kind() == '"' && tok.String() == "users" {
				break
			}
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		if tok.Kind() != '[' {
			return nil, fmt.Errorf(`decode user list error: expected "users" array`)
		}
		userlist.Users = []UserInfo{}
		for dec.PeekKind() != ']' {
			val, err := dec.ReadValue()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: read user object: %w", err)
			}
			var u UserInfo
			if err := json.Unmarshal(val, &u); err != nil {
				return nil, fmt.Errorf("decode user list error: unmarshal user error: %w", err)
			}
			userlist.Users = append(userlist.Users, u)
		}
	}
	if userlist.Users == nil {
		return nil, fmt.Errorf(`decode user list error: expected "users" array`)
	}
	c.pendingUserEtag = r.Header().Get("ETag")
	return userlist.Users, nil
}

// ConfirmUserList advances the conditional request version only after the
// controller has installed the downloaded users successfully.
func (c *Client) ConfirmUserList() { c.userEtag = c.pendingUserEtag }

// GetUserAlive will fetch the alive_ip count for users
func (c *Client) GetUserAlive(ctx context.Context) (map[int]int, error) {
	const path = "/api/v1/server/UniProxy/alivelist"
	r, err := c.client.R().
		SetContext(ctx).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		var requestErr *url.Error
		if errors.As(err, &requestErr) {
			return nil, requestErr.Err
		}
		return nil, err
	}
	if r.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("alive list returned HTTP %d", r.StatusCode())
	}
	var snapshot AliveMap
	if err := json.Unmarshal(r.Body(), &snapshot); err != nil {
		return nil, fmt.Errorf("decode alive list: %w", err)
	}
	if snapshot.Alive == nil {
		return nil, fmt.Errorf(`decode alive list: expected "alive" object`)
	}
	return snapshot.Alive, nil
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

// ReportUserTraffic reports the user traffic
func (c *Client) ReportUserTraffic(ctx context.Context, userTraffic []UserTraffic) error {
	data := make(map[int][]int64, len(userTraffic))
	for i := range userTraffic {
		data[userTraffic[i].UID] = []int64{userTraffic[i].Upload, userTraffic[i].Download}
	}
	const path = "/api/v1/server/UniProxy/push"
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) ReportNodeOnlineUsers(ctx context.Context, data *map[int][]string) error {
	const path = "/api/v1/server/UniProxy/alive"
	_, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)

	if err != nil {
		return err
	}

	return nil
}
