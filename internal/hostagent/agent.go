// Package hostagent implements the independent managed-host control process.
package hostagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wyx2685/v2node/common/management"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/google/uuid"
)

type Enrollment struct {
	PanelURL         string   `json:"panel_url"`
	HostID           string   `json:"host_id"`
	EnrollmentCode   string   `json:"enrollment_code"`
	AllowedAPIHosts  []string `json:"allowed_api_hosts"`
	ServerConfig     string   `json:"server_config"`
	ManagedDirectory string   `json:"managed_directory"`
}

type identity struct {
	PanelURL        string   `json:"panel_url"`
	HostID          string   `json:"host_id"`
	Token           string   `json:"host_token"`
	Generation      int64    `json:"credential_generation"`
	Sequence        int64    `json:"report_seq"`
	AllowedAPIHosts []string `json:"allowed_api_hosts"`
	ServerConfig    string   `json:"server_config"`
}

type nodeRef struct {
	ServerType string `json:"server_type"`
	ServerID   int    `json:"server_id"`
}

type observation struct {
	ProcessID         int       `json:"-"`
	ProtocolVersion   int       `json:"protocol_version"`
	Generation        int64     `json:"credential_generation"`
	Sequence          int64     `json:"report_seq"`
	BootID            string    `json:"agent_boot_id"`
	AgentVersion      string    `json:"agent_version"`
	OS                string    `json:"os"`
	Arch              string    `json:"arch"`
	InitSystem        string    `json:"init_system"`
	ServiceState      string    `json:"service_state"`
	ServiceSHA256     *string   `json:"service_sha256"`
	ConfigSHA256      *string   `json:"config_sha256"`
	LocalNodes        []nodeRef `json:"local_nodes"`
	ExternalNodeCount int       `json:"external_node_count"`
	UnmappedNodeCount int       `json:"unmapped_node_count"`
	Capabilities      []string  `json:"capabilities"`
	ServiceVersion    *string   `json:"service_version"`
	ServiceBootID     *string   `json:"service_boot_id"`
	LocalHealth       string    `json:"local_health"`
	MaintenanceState  string    `json:"maintenance_state"`
	PreviousSHA       *string   `json:"previous_sha256"`
}

func newClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("host control redirects are forbidden")
	}}
}

func checkPanel(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("panel_url must be an HTTPS origin without credentials, path or query")
	}
	return nil
}

func secureRead(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("identity and enrollment files must be regular files accessible only to their owner")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 65537))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid host identity JSON")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected data after identity JSON")
	}
	return nil
}

func lockDirectory(dir string) (*flock.Flock, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory must be private (0700)")
	}
	lock := flock.New(filepath.Join(dir, "agent.lock"))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, errors.New("another host agent owns this state directory")
	}
	return lock, nil
}

func saveIdentity(dir string, state identity) error {
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".identity-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(dir, "identity.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func post(ctx context.Context, client *http.Client, panel, path, token string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(panel, "/")+"/api/v2/server/managed-host/"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("host control request failed; identity and sequence were preserved")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// Never echo response bodies: intermediaries can reflect credentials.
		return fmt.Errorf("host control rejected request (HTTP %d)", response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 65537)).Decode(output); err != nil {
		return errors.New("invalid host control response")
	}
	return nil
}

func supported() error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("host agent currently supports Linux amd64/systemd only")
	}
	return nil
}

func Enroll(ctx context.Context, dir, enrollmentFile, version string) error {
	if err := supported(); err != nil {
		return err
	}
	lock, err := lockDirectory(dir)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	if _, err := os.Lstat(filepath.Join(dir, "identity.json")); !os.IsNotExist(err) {
		return errors.New("identity already exists or cannot be inspected; enrollment will not overwrite it")
	}
	var input Enrollment
	if err := secureRead(enrollmentFile, &input); err != nil {
		return err
	}
	if err := checkPanel(input.PanelURL); err != nil {
		return err
	}
	if _, err := uuid.Parse(input.HostID); err != nil {
		return errors.New("invalid host ID")
	}
	if len(input.EnrollmentCode) != 64 {
		return errors.New("invalid enrollment code")
	}
	if _, err := hex.DecodeString(input.EnrollmentCode); err != nil {
		return errors.New("invalid enrollment code")
	}
	if !filepath.IsAbs(input.ServerConfig) || len(input.AllowedAPIHosts) == 0 {
		return errors.New("absolute server_config and approved allowed_api_hosts are required")
	}
	installation, err := loadInstallation(dir)
	if err != nil {
		return err
	}
	if installation != nil && input.ManagedDirectory != installation.ManagedDirectory {
		return errors.New("prepared enrollment must use the installation managed_directory")
	}
	for _, origin := range input.AllowedAPIHosts {
		if err := checkPanel(origin); err != nil {
			return err
		}
	}
	var result struct {
		Data struct {
			HostID      string `json:"host_id"`
			Token       string `json:"host_token"`
			Generation  int64  `json:"credential_generation"`
			Protocol    int    `json:"protocol_version"`
			ReportToken string `json:"service_report_token"`
		} `json:"data"`
	}
	err = post(ctx, newClient(), input.PanelURL, "enroll", "", map[string]any{
		"protocol_version": 2, "host_id": input.HostID, "enrollment_code": input.EnrollmentCode,
		"agent_version": version, "os": runtime.GOOS, "arch": runtime.GOARCH, "init_system": "systemd",
	}, &result)
	if err != nil {
		return err
	}
	if result.Data.HostID != input.HostID || result.Data.Protocol != 2 || result.Data.Generation < 1 || len(result.Data.Token) != 64 {
		return errors.New("invalid enrollment response; re-enrollment requires administrator action")
	}
	if _, err := hex.DecodeString(result.Data.Token); err != nil {
		return errors.New("invalid host token")
	}
	if input.ManagedDirectory != "" {
		if !filepath.IsAbs(input.ManagedDirectory) || len(result.Data.ReportToken) != 64 {
			return errors.New("invalid managed reporting identity")
		}
		if err := os.MkdirAll(input.ManagedDirectory, 0700); err != nil {
			return err
		}
		if err := management.Write(filepath.Join(input.ManagedDirectory, "report-identity.json"), management.ReportIdentity{PanelURL: input.PanelURL, Token: result.Data.ReportToken, Generation: result.Data.Generation}); err != nil {
			return err
		}
	}
	return saveIdentity(dir, identity{PanelURL: input.PanelURL, HostID: input.HostID, Token: result.Data.Token,
		Generation: result.Data.Generation, AllowedAPIHosts: input.AllowedAPIHosts, ServerConfig: input.ServerConfig})
}

func Run(ctx context.Context, dir, version string, once bool) error {
	if err := supported(); err != nil {
		return err
	}
	lock, err := lockDirectory(dir)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	var state identity
	if err := secureRead(filepath.Join(dir, "identity.json"), &state); err != nil {
		return err
	}
	if err := checkPanel(state.PanelURL); err != nil {
		return err
	}
	if state.Generation < 1 || state.Sequence < 0 || len(state.Token) != 64 {
		return errors.New("invalid persisted identity")
	}
	boot := uuid.NewString()
	client := newClient()
	installation, err := loadInstallation(dir)
	if err != nil {
		return err
	}
	if installation != nil {
		installation.AgentVersion = version
		var prior journal
		if err := management.Read(filepath.Join(installation.ManagedDirectory, "operation.json"), &prior); err != nil && !os.IsNotExist(err) {
			return err
		} else if err == nil && prior.Status == "" && prior.Phase != "intent" {
			if err := execute(context.WithoutCancel(ctx), client, state, installation, prior.Operation); err != nil {
				return err
			}
		}
	}
	var worker chan error
	defer func() {
		if worker != nil {
			<-worker
		}
	}()
	for {
		obs, err := observe(ctx, state)
		if err != nil {
			return err
		}
		if state.Sequence >= 9007199254740991 {
			return errors.New("report sequence exhausted; re-enrollment required")
		}
		state.Sequence++
		if err := saveIdentity(dir, state); err != nil {
			return err
		}
		obs.ProtocolVersion, obs.Generation, obs.Sequence = 2, state.Generation, state.Sequence
		obs.BootID, obs.AgentVersion = boot, version
		obs.OS, obs.Arch, obs.InitSystem = runtime.GOOS, runtime.GOARCH, "systemd"
		obs.Capabilities = []string{}
		obs.LocalHealth = "unknown"
		obs.MaintenanceState = "unknown"
		if installation != nil {
			obs.MaintenanceState = "idle"
			frozen, err := management.Frozen(installation.ManagedDirectory)
			if err != nil {
				return err
			}
			if frozen {
				obs.MaintenanceState = "busy"
			}
			var ready management.Ready
			if err := management.Read(filepath.Join(installation.ManagedDirectory, "ready.json"), &ready); err == nil && obs.ServiceSHA256 != nil && ready.SHA256 == *obs.ServiceSHA256 && ready.PID == obs.ProcessID {
				obs.ConfigSHA256 = &ready.ConfigSHA256
				obs.ServiceVersion = &ready.Version
				obs.ServiceBootID = &ready.BootID
				obs.LocalHealth = "ready"
			}
			obs.Capabilities = []string{"start_service", "stop_service", "restart_service", "collect_diag"}
			if obs.LocalHealth == "ready" {
				obs.Capabilities = append(obs.Capabilities, "upgrade")
				if previous, err := os.Open(filepath.Join(installation.Layout, "previous")); err == nil {
					hash, e := digest(previous)
					previous.Close()
					if e == nil {
						obs.PreviousSHA = &hash
						obs.Capabilities = append(obs.Capabilities, "rollback")
					}
				}
			}
		}
		var reply struct {
			Data struct {
				Accepted   bool  `json:"accepted"`
				ServerTime int64 `json:"server_time"`
			} `json:"data"`
		}
		if err := post(ctx, client, state.PanelURL, "heartbeat", state.Token, obs, &reply); err != nil {
			return err
		}
		if !reply.Data.Accepted {
			return errors.New("heartbeat sequence was not accepted; reconcile identity before restarting")
		}
		if once {
			return nil
		}
		if worker != nil {
			select {
			case err := <-worker:
				worker = nil
				if err != nil {
					return err
				}
			default:
			}
		}
		if installation != nil && worker == nil {
			var pending struct {
				Data *operation `json:"data"`
			}
			if err := post(ctx, client, state.PanelURL, "claim", state.Token, map[string]any{"protocol_version": 2, "active_operation_id": nil}, &pending); err != nil {
				return err
			}
			if pending.Data != nil {
				worker = make(chan error, 1)
				jobState := state
				job := *pending.Data
				result := worker
				go func() {
					operationContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Minute)
					defer cancel()
					result <- execute(operationContext, newClient(), jobState, installation, job)
				}()
			}
		}
		timer := time.NewTimer(30 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func digest(r io.Reader) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
