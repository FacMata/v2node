package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func observe(ctx context.Context, state identity) (observation, error) {
	result := observation{ServiceState: "unknown", LocalNodes: []nodeRef{}}
	// Only parse inventory; never instantiate the proxy core, budgets or telemetry queues.
	data, err := os.ReadFile(state.ServerConfig)
	if err != nil {
		return result, errors.New("cannot read local server inventory")
	}
	var config struct {
		Nodes []struct {
			APIHost string `json:"ApiHost"`
			ID      int    `json:"NodeID"`
		} `json:"Nodes"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return result, errors.New("server inventory must be valid JSON")
	}
	seen := make(map[int]bool)
	for _, node := range config.Nodes {
		local := false
		for _, origin := range state.AllowedAPIHosts {
			if strings.TrimRight(node.APIHost, "/") == strings.TrimRight(origin, "/") {
				local = true
				break
			}
		}
		if !local {
			result.ExternalNodeCount++
			continue
		}
		if node.ID <= 0 || seen[node.ID] {
			result.UnmappedNodeCount++
			continue
		}
		seen[node.ID] = true
		result.LocalNodes = append(result.LocalNodes, nodeRef{ServerType: "v2node", ServerID: node.ID})
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(probeCtx, "/usr/bin/systemctl", "show", "v2node.service", "--property=ActiveState,MainPID,LoadState").Output()
	if err != nil {
		return result, errors.New("cannot inspect v2node.service with systemd")
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = value
		}
	}
	if fields["LoadState"] != "loaded" {
		return result, errors.New("v2node.service is not loaded")
	}
	switch fields["ActiveState"] {
	case "active":
		result.ServiceState = "running"
	case "inactive":
		result.ServiceState = "stopped"
	case "failed":
		result.ServiceState = "failed"
	}
	if result.ServiceState != "running" {
		return result, nil
	}
	pid, err := strconv.Atoi(fields["MainPID"])
	if err != nil || pid <= 0 {
		return result, errors.New("running service has no usable MainPID")
	}
	proc := "/proc/" + strconv.Itoa(pid)
	before, err := os.ReadFile(proc + "/stat")
	if err != nil {
		return result, errors.New("cannot inspect running process identity")
	}
	exe, err := os.Open(proc + "/exe")
	if err != nil {
		return result, errors.New("cannot inspect running executable")
	}
	defer exe.Close()
	sha, err := digest(exe)
	if err != nil {
		return result, err
	}
	after, err := os.ReadFile(proc + "/stat")
	if err != nil || processStart(before) == "" || processStart(before) != processStart(after) {
		return result, errors.New("service process changed during observation")
	}
	checkCtx, finish := context.WithTimeout(ctx, 5*time.Second)
	defer finish()
	current, err := exec.CommandContext(checkCtx, "/usr/bin/systemctl", "show", "v2node.service", "--property=MainPID", "--value").Output()
	if err != nil || strings.TrimSpace(string(current)) != strconv.Itoa(pid) {
		return result, errors.New("systemd MainPID changed during observation")
	}
	// This proves only executable bytes, not a release version or application readiness.
	result.ServiceSHA256 = &sha
	result.ProcessID = pid
	return result, nil
}

func processStart(stat []byte) string {
	end := strings.LastIndex(string(stat), ")")
	if end < 0 {
		return ""
	}
	fields := strings.Fields(string(stat)[end+1:])
	if len(fields) < 20 {
		return ""
	}
	return fields[19] // /proc stat field 22, with pid/comm removed.
}
