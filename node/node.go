package node

import (
	"context"
	"errors"
	"fmt"
	"github.com/wyx2685/v2node/common/management"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/core"
)

type Node struct {
	controllers []*Controller
	NodeInfos   []*panel.NodeInfo
}

func New(nodes []conf.NodeConfig) (*Node, error) {
	n := &Node{
		controllers: make([]*Controller, len(nodes)),
		NodeInfos:   make([]*panel.NodeInfo, len(nodes)),
	}
	for i, node := range nodes {
		p, err := panel.New(&node)
		if err != nil {
			return nil, err
		}
		info, err := p.GetNodeInfo(context.Background())
		if err != nil {
			return nil, err
		}
		n.controllers[i] = NewController(p, &node, info)
		n.NodeInfos[i] = info
	}
	return n, nil
}

// NewFrozen preserves all panels' immutable inbound inputs during a binary
// operation; Controller.Start still loads current users and budget state.
func NewFrozen(nodes []conf.NodeConfig, infos []*panel.NodeInfo) (*Node, error) {
	if len(nodes) != len(infos) {
		return nil, fmt.Errorf("frozen node count mismatch")
	}
	n := &Node{controllers: make([]*Controller, len(nodes)), NodeInfos: infos}
	for i, cfg := range nodes {
		if infos[i] == nil {
			return nil, fmt.Errorf("missing frozen node information")
		}
		client, err := panel.New(&cfg)
		if err != nil {
			return nil, err
		}
		if cfg.ConfigToken != "" {
			current, err := client.ManagedStartup(context.Background())
			if err != nil {
				return nil, err
			}
			infos[i] = current
		}
		n.controllers[i] = NewController(client, &cfg, infos[i])
	}
	return n, nil
}

func (n *Node) Start(nodes []conf.NodeConfig, core *core.V2Core) error {
	for i, node := range nodes {
		index := i
		n.controllers[i].onConfigApplied = func(info *panel.NodeInfo) error {
			n.NodeInfos[index] = info
			return management.UpdateNode(management.Directory, index, info)
		}
		err := n.controllers[i].Start(core)
		if err != nil {
			return fmt.Errorf("start node controller [%s-%d] error: %s",
				node.APIHost,
				node.NodeID,
				err)
		}
		n.NodeInfos[i] = n.controllers[i].info
	}
	return nil
}

func (n *Node) Close() error {
	var err error
	for _, c := range n.controllers {
		if closeErr := c.Close(); closeErr != nil {
			log.Errorf("close controller failed: %v", closeErr)
			err = errors.Join(err, closeErr)
		}
	}
	n.controllers = nil
	return err
}
