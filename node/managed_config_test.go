package node

import (
	"path/filepath"
	"strings"
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/management"
	"github.com/wyx2685/v2node/conf"
)

func TestPublicationOnlyRevisionDoesNotReplaceInbound(t *testing.T) {
	prior := management.Directory
	management.Directory = t.TempDir()
	defer func() { management.Directory = prior }()
	client, err := panel.New(&conf.NodeConfig{APIHost: "https://panel.invalid", NodeID: 7, ConfigToken: strings.Repeat("a", 64), ConfigDirectory: filepath.Join(t.TempDir(), "node")})
	if err != nil {
		t.Fatal(err)
	}
	info := &panel.NodeInfo{Id: 7, Type: "anytls", Security: panel.Tls, Tag: "test", Common: &panel.CommonNode{Protocol: "anytls"}}
	hash := strings.Repeat("b", 64)
	state := &panel.ManagedConfigState{Current: info, Baseline: info, CurrentRevision: 1, Revision: 1, Attempt: 1, Generation: 1, CurrentDigest: hash, Digest: hash, Result: "applied"}
	if err := client.StoreManaged(state); err != nil {
		t.Fatal(err)
	}
	controller := &Controller{apiClient: client, info: info} // No core: replacing an inbound here would fail.
	envelope := &panel.ManagedEnvelope{Mode: "managed", Revision: 2, Attempt: 1, Generation: 1, Digest: hash}
	if err := controller.applyManagedConfig(envelope, info, nil); err != nil {
		t.Fatal(err)
	}
	if client.ManagedState().CurrentRevision != 2 || client.ManagedState().Current != info || client.ManagedState().Result != "applied" {
		t.Fatal("metadata revision changed runtime inputs")
	}
	changed, err := cloneInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	changed.Common.Protocol = "trojan"
	envelope.Revision = 3
	envelope.Digest = strings.Repeat("c", 64)
	if err := controller.applyManagedConfig(envelope, changed, nil); err != nil {
		t.Fatal(err)
	}
	if client.ManagedState().CurrentRevision != 2 || client.ManagedState().Result != "failed" {
		t.Fatal("core-wide candidate crossed inbound boundary")
	}
}
