package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	log "github.com/sirupsen/logrus"
)

type ReportIdentity struct {
	PanelURL   string `json:"panel_url"`
	Token      string `json:"service_report_token"`
	Generation int64  `json:"credential_generation"`
	Sequence   int64  `json:"report_seq"`
}

// ReportLoop sends process-owned readiness; the management heartbeat cannot
// substitute for this independently scoped reporting credential.
func ReportLoop(ctx context.Context, dir string) error {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, "report-identity.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	for {
		err := reportOnce(ctx, client, dir, path)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			log.Warn("Managed business confirmation unavailable; next scheduled report will try again")
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

func reportOnce(ctx context.Context, client *http.Client, dir, path string) error {
	lock := flock.New(filepath.Join(dir, "report.lock"))
	ok, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("service reporter already running")
	}
	defer lock.Unlock()
	var ready Ready
	if err := Read(filepath.Join(dir, "ready.json"), &ready); err != nil {
		return err
	}
	if ready.PID != os.Getpid() {
		return errors.New("readiness does not belong to this process")
	}
	var identity ReportIdentity
	if err := Read(path, &identity); err != nil {
		return err
	}
	identity.Sequence++
	if err := Write(path, identity); err != nil {
		return err
	}
	data, err := json.Marshal(map[string]any{"protocol_version": 2, "credential_generation": identity.Generation,
		"report_seq": identity.Sequence, "service_boot_id": ready.BootID, "service_version": ready.Version,
		"service_sha256": ready.SHA256, "config_sha256": ready.ConfigSHA256, "local_ready": true})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(identity.PanelURL, "/")+"/api/v2/server/instance-status", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+identity.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("business readiness report unavailable")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != 200 {
		return errors.New("business readiness report rejected")
	}
	return nil
}
