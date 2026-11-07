package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
)

func main() {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile("/tmp/codex-v2node-check-work/test.key", []byte(base64.StdEncoding.EncodeToString(key)), 0600); e != nil {
		panic(e)
	}
	if e = os.WriteFile("/tmp/codex-v2node-check-work/test.pub", []byte(base64.StdEncoding.EncodeToString(pub)), 0644); e != nil {
		panic(e)
	}
}
