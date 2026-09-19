package budget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"github.com/google/uuid"
)

type Grant struct {
	ID        string `json:"id"`
	MaxBytes  int64  `json:"max_bytes"`
	RateMilli int64  `json:"rate_milli"`
	ExpiresAt int64  `json:"expires_at"`
	Source    string `json:"source"`
	Closed    bool   `json:"closed"`
}

type API interface {
	RequestBudget(context.Context, int, string, int64) (Grant, error)
	SettleBudget(context.Context, string, int64, int64, bool) error
}

type State struct {
	RequestID      string `json:"request_id"`
	RequestMinimum int64  `json:"request_minimum,omitempty"`
	Grant          *Grant `json:"grant"`
	Upload         int64  `json:"upload"`
	Download       int64  `json:"download"`
	Closing        bool   `json:"closing"`
}

type Account struct {
	mu     sync.Mutex
	state  State
	id     int
	store  *Store
	failed error
}

type Store struct {
	mu       sync.Mutex
	accounts map[int]*Account
	dir      string
	api      API
	lock     *flock.Flock
}

func Open(dir string, api API) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	l := flock.New(filepath.Join(dir, ".lock"))
	ok, err := l.TryLock()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("traffic budget directory is already in use")
	}
	s := &Store{dir: dir, api: api, lock: l, accounts: make(map[int]*Account)}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		l.Unlock()
		return nil, err
	}
	for _, path := range files {
		id, err := strconv.Atoi(filepath.Base(path[:len(path)-5]))
		if err != nil {
			l.Unlock()
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			l.Unlock()
			return nil, err
		}
		a := &Account{id: id, store: s}
		if err := json.Unmarshal(data, &a.state); err != nil {
			l.Unlock()
			return nil, err
		}
		if a.state.Upload < 0 || a.state.Download < 0 || (a.state.Grant != nil && a.state.Upload+a.state.Download > a.state.Grant.MaxBytes) {
			l.Unlock()
			return nil, errors.New("invalid persisted traffic budget")
		}
		s.accounts[id] = a
	}
	return s, nil
}

func (s *Store) Account(id int) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.accounts[id]; ok {
		return a
	}
	a := &Account{id: id, store: s}
	s.accounts[id] = a
	return a
}

func (a *Account) save() error {
	data, err := json.Marshal(a.state)
	if err != nil {
		return err
	}
	path := filepath.Join(a.store.dir, strconv.Itoa(a.id)+".json")
	f, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		a.failed = err
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(path+".tmp", path)
	}
	if err == nil {
		var d *os.File
		d, err = os.Open(a.store.dir)
		if err == nil {
			err = d.Sync()
			d.Close()
		}
	}
	if err != nil {
		a.failed = err
	}
	return err
}

func (a *Account) closeGrant(ctx context.Context) error {
	if a.state.Grant == nil {
		return nil
	}
	if !a.state.Closing {
		a.state.Closing = true
		if err := a.save(); err != nil {
			return err
		}
	}
	if err := a.store.api.SettleBudget(ctx, a.state.Grant.ID, a.state.Upload, a.state.Download, true); err != nil {
		return err
	}
	a.state = State{}
	return a.save()
}

var ErrRevoked = errors.New("traffic authorization revoked")

// Transfer persists each debit then delivers that exact prefix before seeking more budget.
func (a *Account) Transfer(bytes int64, upload, datagram bool, deliver func(int64) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed != nil {
		return a.failed
	}
	if bytes <= 0 {
		return nil
	}
	if datagram && bytes > 65536 {
		return errors.New("datagram exceeds traffic authorization limit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for bytes > 0 {
		if a.state.Grant != nil && (a.state.Closing || time.Now().Unix() >= a.state.Grant.ExpiresAt || a.state.Upload+a.state.Download == a.state.Grant.MaxBytes || (datagram && bytes > a.state.Grant.MaxBytes-a.state.Upload-a.state.Download)) {
			if err := a.closeGrant(ctx); err != nil {
				return err
			}
		}
		if a.state.Grant == nil {
			if a.state.RequestID == "" {
				a.state.RequestID = uuid.NewString()
				a.state.RequestMinimum = 1
				if datagram {
					a.state.RequestMinimum = bytes
				}
				if err := a.save(); err != nil {
					return err
				}
			}
			if a.state.RequestMinimum == 0 {
				a.state.RequestMinimum = 1
			} // Old persisted requests always requested one byte.
			g, err := a.store.api.RequestBudget(ctx, a.id, a.state.RequestID, a.state.RequestMinimum)
			if err != nil {
				return err
			}
			if g.ID == "" || g.MaxBytes < a.state.RequestMinimum || g.MaxBytes > 8388608 || g.RateMilli < 1 || g.RateMilli > 1000000 {
				return errors.New("invalid traffic authorization")
			}
			if g.Closed {
				a.state = State{}
				if err := a.save(); err != nil {
					return err
				}
				return errors.New("traffic authorization already closed")
			}
			a.state.Grant = &g
			if err := a.save(); err != nil {
				return err
			}
		}
		if time.Now().Unix() >= a.state.Grant.ExpiresAt {
			if err := a.closeGrant(ctx); err != nil {
				return err
			}
			return errors.New("traffic authorization exhausted")
		}
		if datagram && bytes > a.state.Grant.MaxBytes-a.state.Upload-a.state.Download {
			continue
		}
		part := min(bytes, a.state.Grant.MaxBytes-a.state.Upload-a.state.Download)
		if upload {
			a.state.Upload += part
		} else {
			a.state.Download += part
		}
		if err := a.save(); err != nil {
			return err
		}
		if err := deliver(part); err != nil {
			return err
		}
		bytes -= part
	}
	return nil
}

func (s *Store) Report(ctx context.Context) error {
	s.mu.Lock()
	accounts := make([]*Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		accounts = append(accounts, a)
	}
	s.mu.Unlock()
	for _, a := range accounts {
		a.mu.Lock()
		var err error
		if a.failed != nil {
			err = a.failed
		} else if a.state.Grant != nil {
			if a.state.Closing || time.Now().Unix() >= a.state.Grant.ExpiresAt {
				err = a.closeGrant(ctx)
			} else {
				err = s.api.SettleBudget(ctx, a.state.Grant.ID, a.state.Upload, a.state.Download, false)
				if errors.Is(err, ErrRevoked) {
					err = a.closeGrant(ctx)
				}
			}
		}
		a.mu.Unlock()
		if err != nil {
			return fmt.Errorf("traffic account %d: %w", a.id, err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		a.mu.Lock()
		a.failed = errors.New("traffic budget store closed")
		a.mu.Unlock()
	}
	return s.lock.Unlock()
}
