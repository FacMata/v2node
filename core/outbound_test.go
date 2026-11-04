package core

import (
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/transport/internet"
)

func TestDefaultOutboundHonorsDNSFamily(t *testing.T) {
	out, err := buildDefaultOutbound("UseIPv4")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := out.SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	sender := settings.(*proxyman.SenderConfig)
	if sender.StreamSettings.SocketSettings.DomainStrategy != internet.DomainStrategy_USE_IP4 {
		t.Fatal("default outbound did not preserve IPv4-only strategy")
	}
}
