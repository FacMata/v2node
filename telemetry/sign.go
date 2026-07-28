package telemetry

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Signer struct {
	nodeID uint64
	keyID  string
	secret []byte
}

type SignedHeaders struct {
	NodeID     string
	KeyID      string
	Timestamp  string
	Nonce      string
	Signature  string
	BodySHA256 string
}

func NewSigner(nodeID uint64, keyID string, secret []byte) (*Signer, error) {
	if nodeID == 0 {
		return nil, fmt.Errorf("node ID is required")
	}
	if keyID == "" {
		return nil, fmt.Errorf("telemetry key ID is required")
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("telemetry HMAC secret must be at least 32 bytes")
	}
	return &Signer{
		nodeID: nodeID,
		keyID:  keyID,
		secret: append([]byte(nil), secret...),
	}, nil
}

func (s *Signer) Sign(body []byte, timestamp time.Time, nonce []byte) (SignedHeaders, error) {
	if len(nonce) != 24 {
		return SignedHeaders{}, fmt.Errorf("telemetry nonce must be 24 bytes")
	}

	bodyHash := sha256.Sum256(body)
	bodyHashHex := hex.EncodeToString(bodyHash[:])
	timestampText := strconv.FormatInt(timestamp.Unix(), 10)
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	canonical := strings.Join([]string{
		"v1",
		strconv.FormatUint(s.nodeID, 10),
		timestampText,
		nonceText,
		bodyHashHex,
	}, "\n")

	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(canonical))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return SignedHeaders{
		NodeID:     strconv.FormatUint(s.nodeID, 10),
		KeyID:      s.keyID,
		Timestamp:  timestampText,
		Nonce:      nonceText,
		Signature:  signature,
		BodySHA256: bodyHashHex,
	}, nil
}
