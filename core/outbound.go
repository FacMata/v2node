package core

import (
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// build default freedom outbund
func buildDefaultOutbound(domainStrategy string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = "Default"
	//sendthrough := "origin"
	//outboundDetourConfig.SendThrough = &sendthrough

	outboundDetourConfig.StreamSetting = &conf.StreamConfig{
		SocketSettings: &conf.SocketConfig{
			DomainStrategy: domainStrategy,
		},
	}
	return outboundDetourConfig.Build()
}

// build block outbund
func buildBlockOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "blackhole"
	outboundDetourConfig.Tag = "block"
	return outboundDetourConfig.Build()
}

// build dns outbound
func buildDnsOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "dns"
	outboundDetourConfig.Tag = "dns_out"
	return outboundDetourConfig.Build()
}
