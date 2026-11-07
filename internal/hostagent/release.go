package hostagent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/wyx2685/v2node/common/management"
)

type ReleaseManifest struct {
	Schema          int            `json:"schema_version"`
	Version         string         `json:"release_version"`
	Commit          string         `json:"source_commit"`
	Channel         string         `json:"channel"`
	Sequence        int64          `json:"release_sequence"`
	MinAgentVersion string         `json:"min_agent_version"`
	StateSchema     int            `json:"state_schema"`
	Assets          []ReleaseAsset `json:"assets"`
}
type ReleaseAsset struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}
type releaseWire struct {
	ID        string `json:"id"`
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
	SHA256    string `json:"manifest_sha256"`
}

func verifyRelease(w releaseWire, publicKey string) (*ReleaseManifest, error) {
	key, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid pinned release key")
	}
	sig, err := base64.StdEncoding.DecodeString(w.Signature)
	hash := sha256.Sum256([]byte(w.Manifest))
	if err != nil || hex.EncodeToString(hash[:]) != w.SHA256 || !ed25519.Verify(key, []byte(w.Manifest), sig) {
		return nil, errors.New("release signature or manifest digest mismatch")
	}
	var m ReleaseManifest
	if err := json.Unmarshal([]byte(w.Manifest), &m); err != nil {
		return nil, err
	}
	if m.Schema != 1 || m.StateSchema != 1 || m.Channel != "stable" || m.Sequence < 1 || !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(m.Version) {
		return nil, errors.New("unsupported release manifest")
	}
	if len(m.Assets) != 1 || m.Assets[0].OS != "linux" || m.Assets[0].Arch != "amd64" || m.Assets[0].Filename != "v2node-linux-amd64" || m.Assets[0].Size < 1 || m.Assets[0].Size > 536870912 {
		return nil, errors.New("unsupported release asset")
	}
	return &m, nil
}

func versionLess(a, b string) (bool, error) {
	left, right := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	if len(left) != 3 || len(right) != 3 {
		return false, errors.New("managed releases require numeric semantic versions")
	}
	for i := 0; i < 3; i++ {
		x, e := strconv.Atoi(left[i])
		if e != nil {
			return false, e
		}
		y, e := strconv.Atoi(right[i])
		if e != nil {
			return false, e
		}
		if x != y {
			return x < y, nil
		}
	}
	return false, nil
}

func downloadRelease(ctx context.Context, layout string, m *ReleaseManifest) (string, error) {
	asset := m.Assets[0]
	directory := filepath.Join(layout, "releases", m.Version)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	target := filepath.Join(directory, "v2node")
	if f, err := os.Open(target); err == nil {
		hash, hashErr := digest(f)
		f.Close()
		if hashErr == nil && hash == asset.SHA256 {
			return target, nil
		}
		return "", errors.New("immutable release directory contains different bytes")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	endpoint := "https://github.com/FacMata/v2node/releases/download/" + m.Version + "/" + asset.Filename
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" || (req.URL.Hostname() != "github.com" && req.URL.Hostname() != "release-assets.githubusercontent.com" && req.URL.Hostname() != "objects.githubusercontent.com") {
			return errors.New("untrusted release redirect")
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("release download HTTP %d", resp.StatusCode)
	}
	f, err := os.CreateTemp(directory, ".download-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(resp.Body, asset.Size+1))
	if err != nil {
		f.Close()
		return "", err
	}
	if n != asset.Size || hex.EncodeToString(hash.Sum(nil)) != asset.SHA256 {
		f.Close()
		return "", errors.New("release binary size or digest mismatch")
	}
	if err := f.Chmod(0755); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(f.Name(), target); err != nil {
		return "", err
	}
	if err := management.Write(filepath.Join(directory, "manifest.json"), m); err != nil {
		return "", err
	}
	return target, nil
}

// SignRelease is an offline/CI authoring tool; it never installs or publishes.
func SignRelease(binary, keyFile, output, version, commit, minimum string, sequence int64) error {
	encoded, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("signing key must be a base64 Ed25519 private key")
	}
	f, err := os.Open(binary)
	if err != nil {
		return err
	}
	defer f.Close()
	hash, err := digest(f)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	m := ReleaseManifest{Schema: 1, Version: version, Commit: commit, Channel: "stable", Sequence: sequence, MinAgentVersion: minimum, StateSchema: 1,
		Assets: []ReleaseAsset{{OS: "linux", Arch: "amd64", Filename: "v2node-linux-amd64", SHA256: hash, Size: info.Size()}}}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, raw, 0644); err != nil {
		return err
	}
	return os.WriteFile(output+".sig", []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))), 0644)
}
