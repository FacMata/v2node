package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	xcore "github.com/xtls/xray-core/core"
	serial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		panic("server port and trusted certificate file required")
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	certificate, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(certificate)
	if block == nil {
		panic("invalid certificate")
	}
	hash := sha256.Sum256(block.Bytes)
	pin := hex.EncodeToString(hash[:])
	negative := len(os.Args) > 3 && os.Args[3] == "wrong"
	if negative {
		pin = strings.Repeat("0", 64)
	}
	expected := bytes.Repeat([]byte("managed-host-forwarding-check\n"), 4096)
	listener, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		panic(err)
	}
	origin := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(expected) })}
	defer origin.Close()
	go origin.Serve(listener)
	config := fmt.Sprintf(`{"log":{"loglevel":"error"},"inbounds":[{"listen":"127.0.0.1","port":18081,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],"outbounds":[{"protocol":"anytls","settings":{"address":"127.0.0.1","port":%d,"password":"11111111-1111-4111-8111-111111111111"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"localhost","pinnedPeerCertSha256":"%s"}}}]}`, port, pin)
	parsed, err := serial.LoadJSONConfig(bytes.NewBufferString(config))
	if err != nil {
		panic(err)
	}
	instance, err := xcore.New(parsed)
	if err != nil {
		panic(err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		panic(err)
	}
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:18081", nil, proxy.Direct)
	if err != nil {
		panic(err)
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
	}}}
	response, err := client.Get("http://127.0.0.1:18080/check")
	if negative {
		if err == nil {
			response.Body.Close()
			panic("wrong pin accepted")
		}
		fmt.Println("PASS: actual AnyTLS client rejects wrong certificate pin")
		return
	}
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	if response.StatusCode != 200 || !bytes.Equal(body, expected) {
		panic("forwarded payload mismatch")
	}
	fmt.Printf("PASS: authenticated AnyTLS forwarding on %d, %d payload bytes verified\n", port, len(body))
}
