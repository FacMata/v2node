package panel

import (
	"context"
	"fmt"
	"github.com/wyx2685/v2node/common/budget"
)

func (c *Client) RequestBudget(ctx context.Context, user int, requestID string, minimum int64) (budget.Grant, error) {
	var result struct {
		Data budget.Grant `json:"data"`
	}
	r, err := c.client.R().SetContext(ctx).SetBody(map[string]any{"user_id": user, "request_id": requestID, "minimum_bytes": minimum}).SetResult(&result).
		Post("/api/v1/server/UniProxy/budget")
	if err != nil {
		return budget.Grant{}, err
	}
	if r.StatusCode() != 200 {
		return budget.Grant{}, fmt.Errorf("traffic authorization HTTP %d", r.StatusCode())
	}
	return result.Data, nil
}

func (c *Client) SettleBudget(ctx context.Context, id string, up, down int64, close bool) error {
	var result struct {
		Data    bool `json:"data"`
		Revoked bool `json:"revoked"`
	}
	r, err := c.client.R().SetContext(ctx).SetBody(map[string]any{"authorization_id": id, "upload": up, "download": down, "close": close}).SetResult(&result).
		Post("/api/v1/server/UniProxy/settle")
	if err != nil {
		return err
	}
	if r.StatusCode() != 200 {
		return fmt.Errorf("traffic settlement HTTP %d", r.StatusCode())
	}
	if !result.Data {
		return fmt.Errorf("invalid traffic settlement acknowledgement")
	}
	if result.Revoked && !close {
		return budget.ErrRevoked
	}
	return nil
}
