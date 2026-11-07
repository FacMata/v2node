package panel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ManagedEnvelope struct {
	Schema     int             `json:"schema_version"`
	Mode       string          `json:"mode"`
	Revision   int64           `json:"revision"`
	Attempt    int             `json:"attempt"`
	Generation int             `json:"credential_generation"`
	Scope      string          `json:"scope"`
	Digest     string          `json:"payload_digest"`
	Payload    json.RawMessage `json:"payload"`
}
type ManagedConfigState struct {
	CurrentDigest    string    `json:"current_digest"`
	CredentialHash   string    `json:"credential_hash"`
	Current          *NodeInfo `json:"current"`
	Baseline         *NodeInfo `json:"baseline"`
	Previous         *NodeInfo `json:"previous"`
	CurrentRevision  int64     `json:"current_revision"`
	PreviousRevision int64     `json:"previous_revision"`
	Revision         int64     `json:"revision"`
	Attempt          int       `json:"attempt"`
	Generation       int       `json:"credential_generation"`
	Digest           string    `json:"digest"`
	Result           string    `json:"result"`
	Leaf             *string   `json:"leaf"`
	Sequence         int64     `json:"report_seq"`
	Inflight         bool      `json:"inflight"`
}

func (c *Client) ManagedState() *ManagedConfigState { return c.managed }

func (c *Client) StoreManaged(s *ManagedConfigState) error {
	tokenHash := sha256.Sum256([]byte(c.ConfigToken))
	s.CredentialHash = hex.EncodeToString(tokenHash[:])
	if err := os.MkdirAll(c.ConfigDirectory, 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(c.ConfigDirectory, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(c.ConfigDirectory, "current.json")); err != nil {
		return err
	}
	d, err := os.Open(c.ConfigDirectory)
	if err != nil {
		return err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return err
	}
	c.managed = s
	return nil
}

func (c *Client) managedRequest(ctx context.Context, path string, body any, result any) error {
	origin, err := url.Parse(c.APIHost)
	if err != nil || origin.Scheme != "https" {
		return errors.New("managed config requires HTTPS")
	}
	endpoint := strings.TrimRight(c.APIHost, "/") + "/api/v2/server/config" + path + "?node_id=" + fmt.Sprint(c.NodeId)
	var data []byte
	method := "GET"
	if body != nil {
		method = "POST"
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.ConfigToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("managed config redirect refused") }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("managed configuration endpoint unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("managed config HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(result); err != nil {
		return errors.New("invalid managed configuration response")
	}
	return nil
}

func (c *Client) FetchManaged(ctx context.Context) (*ManagedEnvelope, *NodeInfo, error) {
	var envelope ManagedEnvelope
	if err := c.managedRequest(ctx, "", nil, &envelope); err != nil {
		return nil, nil, err
	}
	if envelope.Schema != 1 || envelope.Generation < 1 {
		return nil, nil, errors.New("unsupported managed config schema")
	}
	if envelope.Mode == "managed" {
		hash := sha256.Sum256(envelope.Payload)
		if envelope.Digest != hex.EncodeToString(hash[:]) || envelope.Scope != "inbound" {
			return nil, nil, errors.New("managed config digest or scope mismatch")
		}
	} else if envelope.Mode != "bootstrap" {
		return nil, nil, errors.New("unknown config enrollment mode")
	}
	info, err := c.parseNodeInfo(envelope.Payload)
	if err != nil {
		return &envelope, nil, err
	}
	return &envelope, info, nil
}

func (c *Client) ManagedStartup(ctx context.Context) (*NodeInfo, error) {
	if c.managed != nil {
		return c.managed.Current, nil
	}
	raw, err := os.ReadFile(filepath.Join(c.ConfigDirectory, "current.json"))
	if err == nil {
		var state ManagedConfigState
		if err := json.Unmarshal(raw, &state); err != nil {
			return nil, err
		}
		if state.Current == nil || state.Baseline == nil {
			return nil, errors.New("managed baseline missing")
		}
		tokenHash := sha256.Sum256([]byte(c.ConfigToken))
		if state.CredentialHash != hex.EncodeToString(tokenHash[:]) {
			envelope, _, err := c.FetchManaged(ctx)
			if err != nil {
				return nil, err
			}
			if envelope.Generation < state.Generation || (envelope.Generation == state.Generation && state.CredentialHash != "") {
				return nil, errors.New("credential rotation did not advance generation")
			}
			if envelope.Generation != state.Generation {
				state.Generation = envelope.Generation
				state.Sequence = 0
			}
			if err := c.StoreManaged(&state); err != nil {
				return nil, err
			}
		}
		if state.Inflight {
			if state.Previous == nil {
				return nil, errors.New("inflight configuration has no recovery baseline")
			}
			state.Current = state.Previous
			state.CurrentRevision = state.PreviousRevision
			state.Result = "rolled_back"
		}
		c.managed = &state
		return state.Current, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	envelope, info, err := c.FetchManaged(ctx)
	if err != nil {
		return nil, err
	}
	if envelope.Mode != "bootstrap" {
		return nil, errors.New("BASELINE_REQUIRED: managed state cannot be recreated from desired config")
	}
	c.bootstrapGeneration = envelope.Generation
	return info, nil
}

func (c *Client) ConfigGeneration() int {
	if c.managed != nil {
		return c.managed.Generation
	}
	return c.bootstrapGeneration
}

// ManagedAckPayload persists the sequence while the controller owns its local
// lifecycle lock. The subsequent network send does not mutate persisted state.
func (c *Client) ManagedAckPayload() (map[string]any, error) {
	s := c.managed
	if s == nil {
		return nil, errors.New("managed state not initialized")
	}
	s.Sequence++
	if err := c.StoreManaged(s); err != nil {
		return nil, err
	}
	var digest *string
	if s.Digest != "" {
		digest = &s.Digest
	}
	return map[string]any{"node_id": c.NodeId, "credential_generation": s.Generation,
		"report_seq": s.Sequence, "boot_id": c.ConfigBootID, "revision": s.Revision, "attempt": s.Attempt, "payload_digest": digest,
		"reported_current": s.CurrentRevision, "observed_leaf_sha256": s.Leaf, "result": s.Result}, nil
}

func (c *Client) SendManagedAck(ctx context.Context, payload map[string]any) error {
	var response any
	return c.managedRequest(ctx, "/ack", payload, &response)
}
