// Package management owns the shared on-disk maintenance boundary. It is inert
// unless server was explicitly started with a managed directory.
package management

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/google/uuid"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
)

var Directory string

type Snapshot struct {
	Config *conf.Conf        `json:"config"`
	Nodes  []*panel.NodeInfo `json:"nodes"`
}

type Ready struct {
	PID          int    `json:"pid"`
	BootID       string `json:"service_boot_id"`
	Version      string `json:"service_version"`
	SHA256       string `json:"service_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	At           int64  `json:"ready_at"`
}

func Write(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
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
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func Read(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func Frozen(dir string) (bool, error) {
	var journal struct {
		Phase string `json:"phase"`
	}
	err := Read(filepath.Join(dir, "operation.json"), &journal)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch journal.Phase {
	case "committed", "rolled_back", "not_started":
		return false, nil
	default:
		return true, nil
	}
}

func Gate(dir string) (*flock.Flock, error) {
	if dir == "" {
		return nil, nil
	}
	lock := flock.New(filepath.Join(dir, "maintenance.lock"))
	ok, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("maintenance in progress")
	}
	return lock, nil
}

func LoadFrozen(dir string) (*Snapshot, error) {
	var snapshot Snapshot
	if err := Read(filepath.Join(dir, "startup.json"), &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Config == nil || len(snapshot.Nodes) != len(snapshot.Config.NodeConfigs) {
		return nil, errors.New("invalid frozen startup snapshot")
	}
	return &snapshot, nil
}

func Publish(dir, version string, cfg *conf.Conf, nodes []*panel.NodeInfo) (*Ready, error) {
	if dir == "" {
		return nil, nil
	}
	snapshot := Snapshot{Config: cfg, Nodes: nodes}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// /proc/self/exe observes the running inode, even after a release link changed.
	if _, err := os.Stat("/proc/self/exe"); err == nil {
		exe = "/proc/self/exe"
	}
	bytes, err := os.ReadFile(exe)
	if err != nil {
		return nil, err
	}
	exeHash := sha256.Sum256(bytes)
	ready := &Ready{PID: os.Getpid(), BootID: uuid.NewString(), Version: version,
		SHA256: hex.EncodeToString(exeHash[:]), ConfigSHA256: hex.EncodeToString(hash[:]), At: time.Now().Unix()}
	if err := Write(filepath.Join(dir, "startup.json"), snapshot); err != nil {
		return nil, err
	}
	if err := Write(filepath.Join(dir, "ready.json"), ready); err != nil {
		return nil, err
	}
	return ready, nil
}

func UpdateNode(dir string, index int, info *panel.NodeInfo) error {
	if dir == "" {
		return nil
	}
	snapshot, err := LoadFrozen(dir)
	if err != nil {
		return err
	}
	if index < 0 || index >= len(snapshot.Nodes) {
		return errors.New("node snapshot index mismatch")
	}
	snapshot.Nodes[index] = info
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(raw)
	var ready Ready
	if err := Read(filepath.Join(dir, "ready.json"), &ready); err != nil {
		return err
	}
	if err := Write(filepath.Join(dir, "startup.json"), snapshot); err != nil {
		return err
	}
	ready.ConfigSHA256 = hex.EncodeToString(hash[:])
	return Write(filepath.Join(dir, "ready.json"), ready)
}
