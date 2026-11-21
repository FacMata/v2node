package limiter

import (
	"sync"
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
)

func testLimiter() (*Limiter, string, panel.UserInfo) {
	Init()
	u := panel.UserInfo{Id: 1, Uuid: "test-user", DeviceLimit: 1}
	return AddLimiter("anytls", "test", []panel.UserInfo{u}, map[int]int{}), format.UserTag("test", u.Uuid), u
}

func TestActiveIPSurvivesReportingWindows(t *testing.T) {
	l, key, _ := testLimiter()
	_, release1, reason := l.CheckLimit(key, "192.0.2.1", true)
	if reason != "" {
		t.Fatal(reason)
	}
	_, release2, reason := l.CheckLimit(key, "192.0.2.1", true)
	if reason != "" {
		t.Fatal(reason)
	}
	l.SetAliveList(map[int]int{1: 1})
	for i := 0; i < 3; i++ {
		online, _ := l.GetOnlineDevice()
		if len(*online) != 1 {
			t.Fatalf("window %d: %v", i, online)
		}
	}
	_, release3, reason := l.CheckLimit(key, "192.0.2.1", true)
	if reason != "" {
		t.Fatal("same active IP rejected:", reason)
	}
	release3()
	if _, _, reason = l.CheckLimit(key, "192.0.2.2", true); reason != "device_limit" {
		t.Fatal("new IP should be rejected", reason)
	}
	release1()
	release1()
	online, _ := l.GetOnlineDevice()
	if len(*online) != 1 {
		t.Fatal("closing one of two links removed IP")
	}
	release2()
	l.GetOnlineDevice()
	online, _ = l.GetOnlineDevice()
	if len(*online) != 0 {
		t.Fatal("closed links remained active", online)
	}
}

func TestConcurrentOnlineStateAndModifiedUsers(t *testing.T) {
	l, key, u := testLimiter()
	var wg sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				switch n {
				case 0:
					_, release, reason := l.CheckLimit(key, "192.0.2.1", true)
					if reason != "" {
						t.Error(reason)
					} else {
						release()
					}
				case 1:
					l.GetOnlineDevice()
					l.SetAliveList(map[int]int{})
				case 2:
					l.UpdateUser("test", nil, nil, []panel.UserInfo{u})
				}
			}
		}(worker)
	}
	wg.Wait()
	l.UpdateUser("test", nil, []panel.UserInfo{u}, nil)
	if _, _, reason := l.CheckLimit(key, "192.0.2.1", true); reason != "user_missing" {
		t.Fatal(reason)
	}
}

func TestAnyTLSAdmissionCannotSurvivePolicyChangeOrReadd(t *testing.T) {
	l, key, u := testLimiter()
	_, finishOriginal, reason, original := l.Admit(key, "192.0.2.1", true)
	if reason != "" {
		t.Fatal(reason)
	}
	defer finishOriginal()
	u.SpeedLimit = 10
	l.UpdateUser("test", nil, nil, []panel.UserInfo{u})
	if reason := l.AdmissionStatus(key, original); reason != "user_policy_changed" {
		t.Fatalf("stale admission after policy change: %q", reason)
	}
	bucket, release, reason, updated := l.Admit(key, "192.0.2.1", true)
	if reason != "" || bucket == nil || l.AdmissionStatus(key, updated) != "" {
		t.Fatalf("current speed policy not applied: bucket=%v reason=%q", bucket, reason)
	}
	defer release()
	l.UpdateUser("test", nil, []panel.UserInfo{u}, nil)
	if reason := l.AdmissionStatus(key, updated); reason != UserMissing {
		t.Fatalf("revoked admission: %q", reason)
	}
	l.UpdateUser("test", []panel.UserInfo{u}, nil, nil)
	if reason := l.AdmissionStatus(key, updated); reason != "user_policy_changed" {
		t.Fatalf("stale admission after same-user readd: %q", reason)
	}
}
