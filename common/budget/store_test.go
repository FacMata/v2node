package budget

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeAPI struct {
	requests     map[string]Grant
	fail         bool
	reported     int64
	count        int
	requestLimit int
	revoked      bool
}

func (a *Account) Consume(bytes int64, upload bool) error {
	return a.Transfer(bytes, upload, false, func(int64) error { return nil })
}

func (f *fakeAPI) RequestBudget(_ context.Context, _ int, key string, minimum int64) (Grant, error) {
	if g, ok := f.requests[key]; ok {
		return g, nil
	}
	if f.requestLimit > 0 && f.count >= f.requestLimit {
		return Grant{}, errors.New("budget insufficient")
	}
	f.count++
	g := Grant{ID: key, MaxBytes: max(1024, minimum), RateMilli: 1000, ExpiresAt: time.Now().Unix() + 120}
	f.requests[key] = g
	return g, nil
}
func (f *fakeAPI) SettleBudget(_ context.Context, _ string, up, down int64, close bool) error {
	if f.fail {
		return errors.New("lost response")
	}
	f.reported = up + down
	if f.revoked && !close {
		return ErrRevoked
	}
	return nil
}

func TestPersistentConsumptionAndFailedAcknowledgment(t *testing.T) {
	dir := t.TempDir()
	api := &fakeAPI{requests: map[string]Grant{}}
	s, err := Open(dir, api)
	if err != nil {
		t.Fatal(err)
	}
	a := s.Account(1)
	if err = a.Consume(500, true); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, api)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a = s.Account(1)
	if err = a.Consume(400, false); err != nil {
		t.Fatal(err)
	}
	if api.count != 1 {
		t.Fatalf("reissued grant after restart: %d", api.count)
	}
	api.fail = true
	if err = s.Report(context.Background()); err == nil {
		t.Fatal("expected failed report")
	}
	if a.state.Upload+a.state.Download != 900 {
		t.Fatal("lost unacknowledged counters")
	}
	api.fail = false
	if err = s.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.reported != 900 {
		t.Fatal(api.reported)
	}
}

func TestPrefixDeliveredBeforeNextGrantFails(t *testing.T) {
	api := &fakeAPI{requests: map[string]Grant{}, requestLimit: 1}
	s, err := Open(t.TempDir(), api)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var delivered int64
	err = s.Account(1).Transfer(1400, true, false, func(n int64) error { delivered += n; return nil })
	if err == nil || delivered != 1024 || api.reported != 1024 {
		t.Fatalf("prefix=%d reported=%d err=%v", delivered, api.reported, err)
	}
}

func TestDatagramNotPartiallyConsumedAtGrantBoundary(t *testing.T) {
	api := &fakeAPI{requests: map[string]Grant{}, requestLimit: 1}
	s, err := Open(t.TempDir(), api)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := s.Account(1)
	if err := a.Consume(900, true); err != nil {
		t.Fatal(err)
	}
	var delivered int64
	err = a.Transfer(200, true, true, func(n int64) error { delivered += n; return nil })
	if err == nil || delivered != 0 || api.reported != 900 {
		t.Fatalf("packet=%d reported=%d err=%v", delivered, api.reported, err)
	}
}

func TestRevocationClosesButStillReportsConsumedBytes(t *testing.T) {
	api := &fakeAPI{requests: map[string]Grant{}}
	s, err := Open(t.TempDir(), api)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := s.Account(1)
	if err := a.Consume(300, true); err != nil {
		t.Fatal(err)
	}
	api.revoked = true
	if err := s.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.state.Grant != nil || api.reported != 300 {
		t.Fatalf("revocation lost settlement: %+v", a.state)
	}
}

func TestConcurrentDirectionsAndCrossGrantBuffer(t *testing.T) {
	api := &fakeAPI{requests: map[string]Grant{}}
	s, err := Open(t.TempDir(), api)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := s.Account(1)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(up bool) {
			defer wg.Done()
			if err := a.Consume(100, up); err != nil {
				t.Error(err)
			}
		}(i%2 == 0)
	}
	wg.Wait()
	if a.state.Upload+a.state.Download != 800 {
		t.Fatal("concurrent debit lost")
	}
	if err = a.Consume(600, true); err != nil {
		t.Fatal(err)
	}
	if api.count != 2 || a.state.Upload+a.state.Download != 376 {
		t.Fatalf("invalid rollover: %d %+v", api.count, a.state)
	}
}
