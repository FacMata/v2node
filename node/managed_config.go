package node

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/management"
	"github.com/wyx2685/v2node/core"
)

func cloneInfo(info *panel.NodeInfo) (*panel.NodeInfo, error) {
	raw, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	var copy panel.NodeInfo
	err = json.Unmarshal(raw, &copy)
	return &copy, err
}

func (c *Controller) materialize(info *panel.NodeInfo, name string) (*panel.NodeInfo, error) {
	copy, err := cloneInfo(info)
	if err != nil {
		return nil, err
	}
	if copy.Type != "anytls" || copy.Security != panel.Tls || copy.Common == nil || copy.Common.CertInfo == nil {
		return nil, errors.New("managed config currently requires AnyTLS TLS")
	}
	certInfo := copy.Common.CertInfo
	cert, key := []byte(certInfo.TlsCert), []byte(certInfo.TlsKey)
	if len(cert) == 0 || len(key) == 0 {
		source := certInfo
		if state := c.apiClient.ManagedState(); state != nil && state.Baseline != nil {
			source = state.Baseline.Common.CertInfo
		}
		cert, err = os.ReadFile(source.CertFile)
		if err != nil {
			return nil, err
		}
		key, err = os.ReadFile(source.KeyFile)
		if err != nil {
			return nil, err
		}
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
		return nil, errors.New("candidate certificate is not currently valid")
	}
	directory := filepath.Join(c.apiClient.ConfigDirectory, "materials", name)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	for filename, data := range map[string][]byte{"cert.pem": cert, "key.pem": key} {
		path := filepath.Join(directory, filename)
		if old, err := os.ReadFile(path); err == nil {
			if !reflect.DeepEqual(old, data) {
				return nil, errors.New("immutable certificate material changed")
			}
		} else if os.IsNotExist(err) {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return nil, err
			}
			if _, err = f.Write(data); err != nil {
				f.Close()
				return nil, err
			}
			err = f.Sync()
			f.Close()
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	d, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return nil, err
	}
	certInfo.CertFile = filepath.Join(directory, "cert.pem")
	certInfo.KeyFile = filepath.Join(directory, "key.pem")
	certInfo.CertMode = "file"
	certInfo.TlsCert = ""
	certInfo.TlsKey = ""
	copy.Common.TlsSettings.TlsCert = ""
	copy.Common.TlsSettings.TlsKey = ""
	return copy, nil
}

func observeLeaf(info *panel.NodeInfo) (string, error) {
	host := info.Common.ListenIP
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(info.Common.ServerPort)), &tls.Config{ServerName: info.Common.CertInfo.CertDomain, InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return "", errors.New("listener returned no certificate")
	}
	cert, err := os.ReadFile(info.Common.CertInfo.CertFile)
	if err != nil {
		return "", err
	}
	key, err := os.ReadFile(info.Common.CertInfo.KeyFile)
	if err != nil {
		return "", err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return "", err
	}
	want := sha256.Sum256(pair.Certificate[0])
	got := sha256.Sum256(peers[0].Raw)
	if got != want {
		return "", errors.New("listener leaf does not match candidate material")
	}
	return hex.EncodeToString(got[:]), nil
}

func (c *Controller) finishManagedStartup(info *panel.NodeInfo) error {
	leaf, err := observeLeaf(info)
	if err != nil {
		return err
	}
	state := c.apiClient.ManagedState()
	if state == nil {
		state = &panel.ManagedConfigState{Current: info, Baseline: info, Generation: c.apiClient.ConfigGeneration(), Result: "bootstrap_ready"}
	}
	copy := *state
	copy.Current = info
	copy.Leaf = &leaf
	copy.Inflight = false
	return c.apiClient.StoreManaged(&copy)
}

func (c *Controller) syncManagedConfig(ctx context.Context) error {
	var ready management.Ready
	if err := management.Read(filepath.Join(management.Directory, "ready.json"), &ready); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if ready.PID != os.Getpid() {
		return nil
	}
	envelope, candidate, fetchErr := c.apiClient.FetchManaged(ctx)
	if fetchErr != nil && envelope == nil {
		return fetchErr
	}
	if err := c.applyManagedConfig(envelope, candidate, fetchErr); err != nil {
		return err
	}
	return c.apiClient.AckManaged(ctx)
}

func (c *Controller) applyManagedConfig(envelope *panel.ManagedEnvelope, candidate *panel.NodeInfo, fetchErr error) error {
	if management.Directory == "" {
		return errors.New("managed config requires server --managed-dir")
	}
	gate, err := management.Gate(management.Directory)
	if err != nil {
		return nil
	}
	defer gate.Unlock()
	frozen, err := management.Frozen(management.Directory)
	if err != nil {
		return err
	}
	if frozen {
		return nil
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	if c.closed {
		return nil
	}
	state := c.apiClient.ManagedState()
	if state == nil {
		return errors.New("managed baseline missing")
	}
	if envelope.Generation != state.Generation {
		return errors.New("managed credential generation changed")
	}
	if envelope.Mode == "bootstrap" || (state.Revision == envelope.Revision && state.Attempt == envelope.Attempt) {
		return nil
	}
	fail := func(cause error) error {
		failed := *state
		failed.Revision = envelope.Revision
		failed.Attempt = envelope.Attempt
		failed.Digest = envelope.Digest
		failed.Result = "failed"
		failed.Inflight = false
		return c.apiClient.StoreManaged(&failed)
	}
	if fetchErr != nil {
		return fail(fetchErr)
	}
	if !state.Inflight && state.CurrentDigest != "" && state.CurrentDigest == envelope.Digest {
		next := *state
		next.Revision = envelope.Revision
		next.Attempt = envelope.Attempt
		next.Digest = envelope.Digest
		next.CurrentRevision = envelope.Revision
		next.Result = "applied"
		return c.apiClient.StoreManaged(&next)
	}
	old := c.info
	before, err := cloneInfo(old)
	if err != nil {
		return err
	}
	after, err := cloneInfo(candidate)
	if err != nil {
		return err
	}
	before.Common.CertInfo = nil
	after.Common.CertInfo = nil
	before.Common.TlsSettings = panel.TlsSettings{}
	after.Common.TlsSettings = panel.TlsSettings{}
	before.Common.PaddingScheme = nil
	after.Common.PaddingScheme = nil
	before.Common.ServerPort = 0
	after.Common.ServerPort = 0
	before.Common.ListenIP = ""
	after.Common.ListenIP = ""
	if !reflect.DeepEqual(before, after) {
		return fail(errors.New("SCOPE_NOT_SUPPORTED: candidate changes core-wide fields"))
	}
	candidate, err = c.materialize(candidate, fmt.Sprintf("%d-%d", envelope.Revision, envelope.Attempt))
	if err != nil {
		return fail(err)
	}
	if err := c.server.ValidateNode(c.tag, candidate); err != nil {
		return fail(err)
	}
	next := *state
	next.Revision = envelope.Revision
	next.Attempt = envelope.Attempt
	next.Digest = envelope.Digest
	next.Previous = old
	next.PreviousRevision = state.CurrentRevision
	next.Inflight = true
	next.Result = "applying"
	if err := c.apiClient.StoreManaged(&next); err != nil {
		return err
	}
	// Local journal, not HTTP acknowledgement, is the recovery boundary.
	if err := c.server.DelNode(c.tag); err == nil {
		err = c.server.AddNode(c.tag, candidate)
		if err == nil {
			_, err = c.server.AddUsers(&core.AddUsersParams{Tag: c.tag, NodeInfo: candidate, Users: c.userList})
		}
		if err == nil {
			var leaf string
			leaf, err = observeLeaf(candidate)
			if err == nil {
				next.Leaf = &leaf
			}
		}
		if err == nil && c.onConfigApplied != nil {
			err = c.onConfigApplied(candidate)
		}
		if err == nil {
			c.info = candidate
			next.Current = candidate
			next.CurrentRevision = envelope.Revision
			next.CurrentDigest = envelope.Digest
			next.Inflight = false
			next.Result = "applied"
			if err := c.apiClient.StoreManaged(&next); err != nil {
				return err
			}
			return nil
		}
	}
	_ = c.server.DelNode(c.tag)
	restoreErr := c.server.AddNode(c.tag, old)
	if restoreErr == nil {
		_, restoreErr = c.server.AddUsers(&core.AddUsersParams{Tag: c.tag, NodeInfo: old, Users: c.userList})
	}
	if restoreErr == nil {
		var leaf string
		leaf, restoreErr = observeLeaf(old)
		if restoreErr == nil {
			next.Leaf = &leaf
		}
	}
	if restoreErr == nil && c.onConfigApplied != nil {
		restoreErr = c.onConfigApplied(old)
	}
	next.Current = old
	next.CurrentRevision = state.CurrentRevision
	next.Inflight = false
	next.Result = "rolled_back"
	if restoreErr != nil {
		next.Result = "rollback_failed"
		_ = os.Remove(filepath.Join(management.Directory, "ready.json"))
	}
	if err := c.apiClient.StoreManaged(&next); err != nil {
		return err
	}
	return nil
}
