package dispatcher

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestManagedLinkReleasesExactlyOnce(t *testing.T) {
	r, w := pipe.New()
	m := &LinkManager{links: make(map[*ManagedWriter]buf.Reader)}
	var released atomic.Int32
	mw := &ManagedWriter{writer: w, manager: m, release: func() { released.Add(1) }}
	m.AddLink(mw, r)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			switch n {
			case 0:
				mw.Close()
			case 1:
				mw.Interrupt()
			case 2:
				m.CloseAll()
			}
		}(i)
	}
	wg.Wait()
	if released.Load() != 1 {
		t.Fatal("release count", released.Load())
	}
}

func TestClosedManagerRejectsNewLink(t *testing.T) {
	r, w := pipe.New()
	m := &LinkManager{links: make(map[*ManagedWriter]buf.Reader)}
	m.CloseAll()
	var released atomic.Int32
	mw := &ManagedWriter{writer: w, manager: m, release: func() { released.Add(1) }}
	m.AddLink(mw, r)
	if released.Load() != 1 {
		t.Fatal("late link leaked")
	}
}
