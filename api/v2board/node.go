package panel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	log "github.com/sirupsen/logrus"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	Tag          string
	Common       *CommonNode
}

type CommonNode struct {
	Protocol   string      `json:"protocol"`
	ListenIP   string      `json:"listen_ip"`
	ServerPort int         `json:"server_port"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
	//vless vmess trojan
	Tls                  int         `json:"tls"`
	TlsSettings          TlsSettings `json:"tls_settings"`
	CertInfo             *CertInfo
	Network              string          `json:"network"`
	NetworkSettings      json.RawMessage `json:"network_settings"`
	TrustedXForwardedFor []string        `json:"trusted_x_forwarded_for"`
	Encryption           string          `json:"encryption"`
	EncryptionSettings   EncSettings     `json:"encryption_settings"`
	ServerName           string          `json:"server_name"`
	Flow                 string          `json:"flow"`
	//shadowsocks
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
	//tuic
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
	//anytls
	PaddingScheme []string `json:"padding_scheme,omitempty"`
	//hysteria hysteria2
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	Obfs                    string `json:"obfs"`
	ObfsPassword            string `json:"obfs_password"`
	Ignore_Client_Bandwidth bool   `json:"ignore_client_bandwidth"`
}

type Route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue *string  `json:"action_value"`
}

type BaseConfig struct {
	PushInterval           any `json:"push_interval"`
	PullInterval           any `json:"pull_interval"`
	DeviceOnlineMinTraffic int `json:"device_online_min_traffic"`
	NodeReportMinTraffic   int `json:"node_report_min_traffic"`
}

type TlsSettings struct {
	ServerName       string   `json:"server_name"`
	ServerNames      []string `json:"server_names"`
	Dest             string   `json:"dest"`
	ServerPort       string   `json:"server_port"`
	ShortId          string   `json:"short_id"`
	ShortIds         []string `json:"short_ids"`
	PrivateKey       string   `json:"private_key"`
	Mldsa65Seed      string   `json:"mldsa65Seed"`
	Xver             uint64   `json:"xver,string"`
	CertMode         string   `json:"cert_mode"`
	CertFile         string   `json:"cert_file"`
	KeyFile          string   `json:"key_file"`
	TlsCert          string   `json:"tls_cert"`
	TlsKey           string   `json:"tls_key"`
	Provider         string   `json:"provider"`
	DNSEnv           string   `json:"dns_env"`
	RejectUnknownSni string   `json:"reject_unknown_sni"`
}

type CertInfo struct {
	CertMode         string
	CertFile         string
	KeyFile          string
	TlsCert          string
	TlsKey           string
	Email            string
	CertDomain       string
	DNSEnv           map[string]string
	Provider         string
	RejectUnknownSni bool
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

func (c *Client) GetNodeInfo(ctx context.Context) (node *NodeInfo, err error) {
	if c.ConfigToken != "" {
		return c.ManagedStartup(ctx)
	}
	const path = "/api/v2/server/config"
	r, err := c.client.
		R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}
	defer func() {
		if r.RawBody() != nil {
			r.RawBody().Close()
		}
	}()

	if r.StatusCode() == http.StatusNotModified {
		if c.responseBodyHash == "" {
			return nil, c.rejectNodeConfig("uninitialized_304", r.StatusCode())
		}
		return nil, nil
	}
	if r.StatusCode() != http.StatusOK {
		return nil, c.rejectNodeConfig("http_status", r.StatusCode())
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	node, err = c.parseNodeInfo(r.Body())
	if err != nil {
		return nil, err
	}
	// Only a successfully parsed and validated response may become the baseline.
	// Otherwise an error page followed by the unchanged config would cause reload.
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")
	return node, nil
}

func (c *Client) parseNodeInfo(body []byte) (node *NodeInfo, err error) {
	node = &NodeInfo{
		Id: c.NodeId,
	}
	// parse protocol params
	cm := &CommonNode{}
	err = json.Unmarshal(body, cm)
	if err != nil {
		return nil, c.rejectNodeConfig("json_decode", http.StatusOK)
	}
	switch cm.Protocol {
	case "vmess", "trojan", "hysteria2", "tuic", "anytls", "vless":
		node.Type = cm.Protocol
		node.Security = cm.Tls
	case "shadowsocks":
		node.Type = cm.Protocol
		node.Security = 0
	default:
		return nil, c.rejectNodeConfig("protocol", http.StatusOK)
	}
	if cm.ServerPort < 1 || cm.ServerPort > 65535 {
		return nil, c.rejectNodeConfig("server_port", http.StatusOK)
	}
	if cm.BaseConfig == nil {
		return nil, c.rejectNodeConfig("base_config", http.StatusOK)
	}
	node.PushInterval, err = intervalToTime(cm.BaseConfig.PushInterval)
	if err != nil {
		return nil, c.rejectNodeConfig("push_interval", http.StatusOK)
	}
	node.PullInterval, err = intervalToTime(cm.BaseConfig.PullInterval)
	if err != nil {
		return nil, c.rejectNodeConfig("pull_interval", http.StatusOK)
	}
	node.Tag = fmt.Sprintf("[%s]-%s:%d", c.APIHost, node.Type, node.Id)
	cf := cm.TlsSettings.CertFile
	kf := cm.TlsSettings.KeyFile
	if cf == "" {
		cf = filepath.Join("/etc/v2node/", cm.Protocol+strconv.Itoa(c.NodeId)+".cer")
	}
	if kf == "" {
		kf = filepath.Join("/etc/v2node/", cm.Protocol+strconv.Itoa(c.NodeId)+".key")
	}
	cm.CertInfo = &CertInfo{
		CertMode:         cm.TlsSettings.CertMode,
		CertFile:         cf,
		KeyFile:          kf,
		Email:            "node@v2board.com",
		CertDomain:       cm.TlsSettings.PrimaryServerName(),
		DNSEnv:           make(map[string]string),
		Provider:         cm.TlsSettings.Provider,
		RejectUnknownSni: cm.TlsSettings.RejectUnknownSni == "1",
	}
	if cm.CertInfo.CertMode == "dns" && cm.TlsSettings.DNSEnv != "" {
		envs := strings.Split(cm.TlsSettings.DNSEnv, ",")
		for _, env := range envs {
			kv := strings.SplitN(env, "=", 2)
			if len(kv) == 2 {
				cm.CertInfo.DNSEnv[kv[0]] = kv[1]
			}
		}
	}
	if cm.CertInfo.CertMode == "remote" {
		cm.CertInfo.TlsCert = cm.TlsSettings.TlsCert
		cm.CertInfo.TlsKey = cm.TlsSettings.TlsKey
	}
	node.Common = cm
	return node, nil
}

func (c *Client) rejectNodeConfig(stage string, status int) error {
	log.WithFields(log.Fields{
		"event": "node_config_rejected", "node_id": c.NodeId,
		"stage": stage, "http_status": status,
	}).Warn("node configuration response rejected")
	return fmt.Errorf("node config rejected: stage=%s http_status=%d", stage, status)
}

func intervalToTime(i interface{}) (time.Duration, error) {
	var seconds int64
	switch v := i.(type) {
	case int:
		seconds = int64(v)
	case string:
		var err error
		seconds, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid interval")
		}
	case float64:
		seconds = int64(v)
		if float64(seconds) != v {
			return 0, fmt.Errorf("invalid interval")
		}
	default:
		return 0, fmt.Errorf("invalid interval")
	}
	if seconds <= 0 || seconds > int64((time.Duration(1<<63-1))/time.Second) {
		return 0, fmt.Errorf("invalid interval")
	}
	return time.Duration(seconds) * time.Second, nil
}

func (t TlsSettings) EffectiveServerNames() []string {
	if len(t.ServerNames) > 0 {
		return t.ServerNames
	}
	if t.ServerName == "" {
		return nil
	}
	return []string{t.ServerName}
}

func (t TlsSettings) EffectiveShortIds() []string {
	if len(t.ShortIds) > 0 {
		return t.ShortIds
	}
	if t.ShortId == "" {
		return nil
	}
	return []string{t.ShortId}
}

func (t TlsSettings) PrimaryServerName() string {
	serverNames := t.EffectiveServerNames()
	if len(serverNames) == 0 {
		return ""
	}
	return serverNames[0]
}
