package hostagent

import (
	"context"
	"errors"
	"fmt"
	"github.com/gofrs/flock"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/wyx2685/v2node/common/management"
)

type Installation struct {
	Layout           string `json:"layout"`
	ManagedDirectory string `json:"managed_directory"`
	PublicKey        string `json:"release_public_key"`
	AgentVersion     string `json:"-"`
}
type operation struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	Expires int64  `json:"expires_at"`
	Params  struct {
		ReleaseID *string `json:"release_id"`
		FromSHA   *string `json:"from_sha256"`
		ConfigSHA *string `json:"config_sha256"`
		Topology  string  `json:"topology_digest"`
	} `json:"params"`
	Release *releaseWire `json:"release"`
}
type operationResult struct {
	Code         string  `json:"code"`
	Message      string  `json:"message"`
	FromVersion  *string `json:"from_version"`
	ToVersion    *string `json:"to_version"`
	ServiceState string  `json:"service_state"`
	Health       string  `json:"local_health"`
	Diagnostic   *string `json:"diagnostic_summary"`
	BootID       *string `json:"service_boot_id"`
	SHA          *string `json:"service_sha256"`
}
type journal struct {
	Operation  operation       `json:"operation"`
	Phase      string          `json:"phase"`
	Sequence   int64           `json:"event_seq"`
	BeginID    *string         `json:"begin_id"`
	From       string          `json:"from"`
	To         string          `json:"to"`
	FromSHA    string          `json:"from_sha256"`
	Recoveries int             `json:"recoveries"`
	Status     string          `json:"status"`
	Result     operationResult `json:"result"`
}

func loadInstallation(dir string) (*Installation, error) {
	var cfg Installation
	err := secureRead(filepath.Join(dir, "installation.json"), &cfg)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(cfg.Layout) || !filepath.IsAbs(cfg.ManagedDirectory) || cfg.PublicKey == "" {
		return nil, errors.New("invalid managed installation")
	}
	return &cfg, nil
}

func changeLink(link, target string) error {
	temp := link + ".next"
	if info, err := os.Lstat(temp); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("staged release reference is not a symlink")
		}
		if err := os.Remove(temp); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(target, temp); err != nil {
		return err
	}
	if err := os.Rename(temp, link); err != nil {
		os.Remove(temp)
		return err
	}
	d, err := os.Open(filepath.Dir(link))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func service(ctx context.Context, verb string) error {
	if verb != "start" && verb != "stop" && verb != "restart" && verb != "daemon-reload" {
		return errors.New("unsupported service action")
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	args := []string{verb, "v2node.service"}
	if verb == "daemon-reload" {
		args = []string{verb}
	}
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", args...).Run(); err != nil {
		return fmt.Errorf("systemd %s failed", verb)
	}
	return nil
}

func maintenanceRestartPolicy(ctx context.Context, hold bool) error {
	dir := "/etc/systemd/system/v2node.service.d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	path := filepath.Join(dir, "90-managed-operation.conf")
	if hold {
		if err := os.WriteFile(path, []byte("[Service]\nRestart=no\n"), 0644); err != nil {
			return err
		}
	} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return service(ctx, "daemon-reload")
}

func readyFor(ctx context.Context, cfg *Installation, expected string, oldBoot string) (*management.Ready, error) {
	startupDeadline := time.Now().Add(120 * time.Second)
	deadline := startupDeadline.Add(60 * time.Second)
	var stable time.Time
	var prior string
	for time.Now().Before(deadline) {
		if stable.IsZero() && time.Now().After(startupDeadline) {
			return nil, errors.New("business startup deadline exceeded")
		}
		var ready management.Ready
		err := management.Read(filepath.Join(cfg.ManagedDirectory, "ready.json"), &ready)
		if err == nil && ready.SHA256 == expected && ready.BootID != oldBoot {
			check, cancel := context.WithTimeout(ctx, 5*time.Second)
			pid, probeErr := exec.CommandContext(check, "/usr/bin/systemctl", "show", "v2node.service", "--property=MainPID", "--value").Output()
			cancel()
			if probeErr == nil && strings.TrimSpace(string(pid)) == fmt.Sprint(ready.PID) {
				if prior != ready.BootID {
					prior = ready.BootID
					stable = time.Now()
				}
				if time.Since(stable) >= 60*time.Second {
					return &ready, nil
				}
			} else {
				stable = time.Time{}
				prior = ""
			}
		} else {
			stable = time.Time{}
			prior = ""
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, errors.New("business readiness deadline exceeded")
}

func persistJournal(cfg *Installation, j *journal) error {
	return management.Write(filepath.Join(cfg.ManagedDirectory, "operation.json"), j)
}

func nextEvent(cfg *Installation) (int64, error) {
	lock := flock.New(filepath.Join(cfg.ManagedDirectory, "events.lock"))
	if err := lock.Lock(); err != nil {
		return 0, err
	}
	defer lock.Unlock()
	path := filepath.Join(cfg.ManagedDirectory, "events.json")
	var sequence int64
	if err := management.Read(path, &sequence); err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	sequence++
	return sequence, management.Write(path, sequence)
}

func sendResult(ctx context.Context, client *http.Client, state identity, cfg *Installation, j *journal) error {
	seq, err := nextEvent(cfg)
	if err != nil {
		return err
	}
	j.Sequence = seq
	if err := persistJournal(cfg, j); err != nil {
		return err
	}
	var response any
	return post(ctx, client, state.PanelURL, "result", state.Token, map[string]any{"protocol_version": 2, "operation_id": j.Operation.ID,
		"event_seq": j.Sequence, "begin_id": j.BeginID, "status": j.Status, "result": j.Result}, &response)
}

func execute(ctx context.Context, client *http.Client, state identity, cfg *Installation, op operation) error {
	gate, err := management.Gate(cfg.ManagedDirectory)
	if err != nil {
		return err
	}
	defer gate.Unlock()
	progressCtx, stopProgress := context.WithCancel(ctx)
	defer stopProgress()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-progressCtx.Done():
				return
			case <-ticker.C:
				var current journal
				if management.Read(filepath.Join(cfg.ManagedDirectory, "operation.json"), &current) != nil || current.Operation.ID != op.ID || current.Status != "" {
					continue
				}
				seq, err := nextEvent(cfg)
				if err != nil {
					continue
				}
				phase := "precheck"
				switch current.Phase {
				case "intent":
					phase = "download"
				case "begun", "switched":
					phase = "health"
				case "recovering":
					phase = "rollback"
				}
				var reply any
				_ = post(progressCtx, newClient(), state.PanelURL, "progress", state.Token, map[string]any{"protocol_version": 2, "operation_id": op.ID, "event_seq": seq, "phase": phase}, &reply)
			}
		}
	}()
	path := filepath.Join(cfg.ManagedDirectory, "operation.json")
	var j journal
	err = management.Read(path, &j)
	if err == nil && j.Operation.ID == op.ID && j.Status != "" {
		return sendResult(ctx, client, state, cfg, &j)
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && j.Status == "" && j.Operation.ID != op.ID {
		return errors.New("another operation requires recovery")
	}
	if j.Operation.ID == op.ID && j.Status == "" && j.Phase != "intent" {
		return recoverOperation(ctx, client, state, cfg, &j)
	}
	j = journal{Operation: op, Phase: "intent", Result: operationResult{Code: "NOT_STARTED", Message: "Operation not started", ServiceState: "unknown", Health: "unknown"}}
	from, err := filepath.EvalSymlinks(filepath.Join(cfg.Layout, "current"))
	if err != nil {
		return err
	}
	f, err := os.Open(from)
	if err != nil {
		return err
	}
	hash, err := digest(f)
	f.Close()
	if err != nil {
		return err
	}
	j.From, j.FromSHA = from, hash
	if err := persistJournal(cfg, &j); err != nil {
		return err
	}
	fail := func(code string, cause error) error {
		j.Phase = "not_started"
		j.Status = "failed"
		j.Result.Code = code
		j.Result.Message = cause.Error()
		if e := persistJournal(cfg, &j); e != nil {
			return e
		}
		return sendResult(ctx, client, state, cfg, &j)
	}
	if op.Expires <= time.Now().Unix() {
		return fail("WINDOW_EXPIRED", errors.New("execution window expired"))
	}
	var ready management.Ready
	if err := management.Read(filepath.Join(cfg.ManagedDirectory, "ready.json"), &ready); err != nil && op.Action != "start_service" {
		return fail("NOT_READY", errors.New("business readiness unavailable"))
	}
	if op.Params.FromSHA != nil && hash != *op.Params.FromSHA {
		return fail("TOPOLOGY_CHANGED", errors.New("running release changed"))
	}
	if op.Params.ConfigSHA != nil && ready.ConfigSHA256 != *op.Params.ConfigSHA {
		return fail("CONFIG_CHANGED", errors.New("frozen startup inputs changed"))
	}
	j.Result.FromVersion = &ready.Version
	if op.Action == "upgrade" {
		if op.Release == nil {
			return fail("RELEASE_REQUIRED", errors.New("signed release required"))
		}
		m, err := verifyRelease(*op.Release, cfg.PublicKey)
		if err != nil {
			return fail("SIGNATURE_INVALID", err)
		}
		tooOld, err := versionLess(cfg.AgentVersion, m.MinAgentVersion)
		if err != nil || tooOld {
			return fail("INCOMPATIBLE_RELEASE", errors.New("agent does not meet signed minimum version"))
		}
		downgrade, err := versionLess(m.Version, ready.Version)
		if err != nil || downgrade {
			return fail("INCOMPATIBLE_RELEASE", errors.New("upgrade cannot downgrade the running release"))
		}
		downloadCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		j.To, err = downloadRelease(downloadCtx, cfg.Layout, m)
		cancel()
		if err != nil {
			return fail("DOWNLOAD_FAILED", err)
		}
		j.Result.ToVersion = &m.Version
	} else if op.Action == "rollback" {
		if op.Release == nil {
			return fail("NO_SAFE_ROLLBACK", errors.New("approved rollback release required"))
		}
		manifest, verifyErr := verifyRelease(*op.Release, cfg.PublicKey)
		if verifyErr != nil {
			return fail("SIGNATURE_INVALID", verifyErr)
		}
		j.Result.ToVersion = &manifest.Version
		j.To, err = filepath.EvalSymlinks(filepath.Join(cfg.Layout, "previous"))
		if err != nil {
			return fail("NO_SAFE_ROLLBACK", errors.New("previous release unavailable"))
		}
		f, e := os.Open(j.To)
		if e != nil {
			return fail("NO_SAFE_ROLLBACK", e)
		}
		previousHash, e := digest(f)
		f.Close()
		if e != nil || previousHash != manifest.Assets[0].SHA256 {
			return fail("NO_SAFE_ROLLBACK", errors.New("previous bytes do not match approved release"))
		}
	}
	var authorization struct {
		Data struct {
			ID    string `json:"begin_id"`
			Until int64  `json:"authorized_until"`
		} `json:"data"`
	}
	if err := post(ctx, client, state.PanelURL, "begin", state.Token, map[string]any{"protocol_version": 2, "operation_id": op.ID, "observed_service_sha256": op.Params.FromSHA, "config_sha256": op.Params.ConfigSHA, "topology_digest": op.Params.Topology}, &authorization); err != nil {
		return fail("BEGIN_REJECTED", err)
	}
	if authorization.Data.Until <= time.Now().Unix() || authorization.Data.Until > time.Now().Unix()+35 {
		return fail("CLOCK_OR_WINDOW_INVALID", errors.New("start authorization expired or clock differs"))
	}
	j.BeginID = &authorization.Data.ID
	j.Phase = "begun"
	if err := persistJournal(cfg, &j); err != nil {
		return err
	}
	if op.Action != "collect_diag" {
		if err := maintenanceRestartPolicy(ctx, true); err != nil {
			return err
		}
	}
	expected := hash
	if j.To != "" {
		f, err := os.Open(j.To)
		if err != nil {
			return err
		}
		expected, err = digest(f)
		f.Close()
		if err != nil {
			return err
		}
		j.Phase = "switched"
		if err := persistJournal(cfg, &j); err != nil {
			return err
		}
		if err := changeLink(filepath.Join(cfg.Layout, "current"), j.To); err != nil {
			return err
		}
	}
	verb := "restart"
	if op.Action == "start_service" {
		verb = "start"
	}
	if op.Action == "stop_service" {
		verb = "stop"
	}
	if op.Action == "collect_diag" {
		j.Result.Message = "Local service observation collected"
		summary := fmt.Sprintf("pid=%d version=%s config_sha256=%s", ready.PID, ready.Version, ready.ConfigSHA256)
		j.Result.Diagnostic = &summary
	} else if err := service(ctx, verb); err != nil {
		return recoverOperation(ctx, client, state, cfg, &j)
	}
	var newReady *management.Ready
	if op.Action != "stop_service" && op.Action != "collect_diag" {
		newReady, err = readyFor(ctx, cfg, expected, ready.BootID)
		if err != nil {
			return recoverOperation(ctx, client, state, cfg, &j)
		}
		if j.Result.ToVersion != nil && newReady.Version != *j.Result.ToVersion {
			return recoverOperation(ctx, client, state, cfg, &j)
		}
	} else if op.Action == "collect_diag" {
		newReady = &ready
	}
	if j.To != "" {
		if err := changeLink(filepath.Join(cfg.Layout, "previous"), j.From); err != nil {
			return err
		}
	}
	j.Status = "succeeded"
	j.Phase = "committed"
	j.Result.Code = "OK"
	j.Result.Message = "Operation completed locally"
	if newReady != nil {
		j.Result.Health = "ready"
		j.Result.ServiceState = "running"
		j.Result.BootID = &newReady.BootID
		j.Result.SHA = &newReady.SHA256
		j.Result.ToVersion = &newReady.Version
	} else {
		j.Result.ServiceState = "stopped"
	}
	if err := persistJournal(cfg, &j); err != nil {
		return err
	}
	if op.Action != "collect_diag" {
		if err := maintenanceRestartPolicy(ctx, false); err != nil {
			return err
		}
	}
	return sendResult(ctx, client, state, cfg, &j)
}

func recoverOperation(ctx context.Context, client *http.Client, state identity, cfg *Installation, j *journal) error {
	if j.Operation.Action == "start_service" {
		if err := service(ctx, "stop"); err != nil {
			return err
		}
		j.Phase = "not_started"
		j.Status = "failed"
		j.Result.Code = "START_FAILED"
		j.Result.Message = "Service start failed; original stopped state retained"
		j.Result.ServiceState = "stopped"
		if err := persistJournal(cfg, j); err != nil {
			return err
		}
		if err := maintenanceRestartPolicy(ctx, false); err != nil {
			return err
		}
		return sendResult(ctx, client, state, cfg, j)
	}
	j.Phase = "recovering"
	if j.Recoveries >= 3 {
		j.Status = "rollback_failed"
		j.Phase = "rollback_failed"
		j.Result.Code = "RECOVERY_EXHAUSTED"
		j.Result.Message = "Recovery requires maintenance"
		_ = service(ctx, "stop")
		if err := persistJournal(cfg, j); err != nil {
			return err
		}
		return sendResult(ctx, client, state, cfg, j)
	}
	j.Recoveries++
	if err := persistJournal(cfg, j); err != nil {
		return err
	}
	f, err := os.Open(j.From)
	if err != nil {
		return err
	}
	hash, err := digest(f)
	f.Close()
	if err != nil || hash != j.FromSHA {
		return errors.New("recovery binary does not match recorded digest")
	}
	if err := changeLink(filepath.Join(cfg.Layout, "current"), j.From); err != nil {
		return err
	}
	if err := service(ctx, "restart"); err != nil {
		return err
	}
	ready, err := readyFor(ctx, cfg, j.FromSHA, "")
	if err != nil {
		j.Status = "rollback_failed"
		j.Phase = "rollback_failed"
		j.Result.Code = "RECOVERY_FAILED"
		j.Result.Message = "Original release did not become ready"
		_ = service(ctx, "stop")
	} else {
		j.Status = "rolled_back"
		j.Phase = "rolled_back"
		j.Result.Code = "RESTORED"
		j.Result.Message = "Original release restored"
		j.Result.ServiceState = "running"
		j.Result.Health = "ready"
		j.Result.BootID = &ready.BootID
		j.Result.SHA = &ready.SHA256
	}
	if err := persistJournal(cfg, j); err != nil {
		return err
	}
	if j.Status == "rolled_back" {
		if err := maintenanceRestartPolicy(ctx, false); err != nil {
			return err
		}
	}
	return sendResult(ctx, client, state, cfg, j)
}
