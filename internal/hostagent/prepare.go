package hostagent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wyx2685/v2node/common/management"
)

// Prepare installs a verified bridge layout and unit definitions, but never
// restarts an existing service. Activation is a separate maintenance action.
func Prepare(stateDir, layout, managedDir, binary, manifest, signature, keyFile, serverConfig string) error {
	if err := supported(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("preparing system units requires root")
	}
	for _, p := range []string{stateDir, layout, managedDir, serverConfig} {
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "\n\r\"\\% ") {
			return errors.New("installation paths must be absolute without whitespace or systemd expansion characters")
		}
	}
	lock, err := lockDirectory(stateDir)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	if _, err := os.Stat(filepath.Join(stateDir, "installation.json")); !os.IsNotExist(err) {
		return errors.New("installation already prepared or cannot be inspected")
	}
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(signature)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(raw)
	m, err := verifyRelease(releaseWire{Manifest: string(raw), Signature: strings.TrimSpace(string(sig)), SHA256: hex.EncodeToString(hash[:])}, strings.TrimSpace(string(key)))
	if err != nil {
		return err
	}
	bytes, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	binaryHash := sha256.Sum256(bytes)
	if int64(len(bytes)) != m.Assets[0].Size || hex.EncodeToString(binaryHash[:]) != m.Assets[0].SHA256 {
		return errors.New("bridge binary does not match signed manifest")
	}
	if err := os.MkdirAll(managedDir, 0700); err != nil {
		return err
	}
	versionDir := filepath.Join(layout, "releases", m.Version)
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		return err
	}
	var existingBusiness []byte
	for _, name := range []string{"v2node.service", "v2node-agent.service"} {
		old, err := os.ReadFile(filepath.Join("/etc/systemd/system", name))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			if name == "v2node.service" {
				existingBusiness = old
			}
			if err := os.WriteFile(filepath.Join(stateDir, name+".before-managed"), old, 0600); err != nil {
				return err
			}
		}
	}
	if err := os.WriteFile(filepath.Join(versionDir, "v2node"), bytes, 0755); err != nil {
		return err
	}
	if err := management.Write(filepath.Join(versionDir, "manifest.json"), m); err != nil {
		return err
	}
	for _, name := range []string{"current", "agent-current"} {
		if _, err := os.Lstat(filepath.Join(layout, name)); !os.IsNotExist(err) {
			return errors.New("release links already exist")
		}
		if err := changeLink(filepath.Join(layout, name), filepath.Join(versionDir, "v2node")); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/usr/local/v2node", 0755); err != nil {
		return err
	}
	business := "[Unit]\nDescription=v2node managed proxy service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nWorkingDirectory=/usr/local/v2node\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n"
	dropin := fmt.Sprintf("[Unit]\nStartLimitIntervalSec=300\nStartLimitBurst=3\n[Service]\nExecStart=\nExecStart=%s/current server --config %s --managed-dir %s\nRestart=on-failure\nRestartSec=10\nTimeoutStopSec=120\n", layout, serverConfig, managedDir)
	if !strings.Contains(string(existingBusiness), "XRAY_LOCATION_ASSET") {
		dropin += "Environment=XRAY_LOCATION_ASSET=/usr/local/v2node\n"
	}
	agent := fmt.Sprintf("[Unit]\nDescription=v2node management agent\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=%s/agent-current agent run --state-dir %s\nRestart=on-failure\nRestartSec=30\nTimeoutStopSec=1500\n\n[Install]\nWantedBy=multi-user.target\n", layout, stateDir)
	if existingBusiness == nil {
		if err := os.WriteFile("/etc/systemd/system/v2node.service", []byte(business), 0644); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/etc/systemd/system/v2node.service.d", 0755); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/systemd/system/v2node.service.d/50-managed-exec.conf", []byte(dropin), 0644); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/systemd/system/v2node-agent.service", []byte(agent), 0644); err != nil {
		return err
	}
	return management.Write(filepath.Join(stateDir, "installation.json"), Installation{Layout: layout, ManagedDirectory: managedDir, PublicKey: strings.TrimSpace(string(key))})
}
