//go:build windows

package etw

import (
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// kernelProcessGUID is Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}; keyword 0x10 = WINEVENT_KEYWORD_PROCESS.
var kernelProcessGUID = windows.GUID{Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B, Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}

// TestLiveKernelProcess is an end-to-end smoke test of the packaged consumer against a real ETW session. It requires administrator
// rights (a real-time session) so it is skipped when StartSession fails with access-denied; on the CI-less Windows dev VM it runs as
// SYSTEM. It spawns child processes and asserts the consumer receives ProcessStart events and can extract their payload fields.
func TestLiveKernelProcess(t *testing.T) {
	sess, err := StartSession("edr-etw-smoke")
	if err != nil {
		t.Skipf("cannot start ETW session (needs admin?): %v", err)
	}
	defer sess.Stop()
	if err := sess.EnableProvider(kernelProcessGUID, 0x10); err != nil {
		t.Fatalf("EnableProvider: %v", err)
	}

	var (
		total    int64
		mu       sync.Mutex
		gotPID   bool
		gotImage bool
	)
	consumer, err := OpenConsumer(sess.Name(), func(r Record) {
		atomic.AddInt64(&total, 1)
		if r.EventID() != 1 { // ProcessStart
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if pid, ok := r.Uint32("ProcessID"); ok && pid != 0 {
			gotPID = true
		}
		if r.UTF16String("ImageName") != "" {
			gotImage = true
		}
	})
	if err != nil {
		t.Fatalf("OpenConsumer: %v", err)
	}

	done := make(chan struct{})
	go func() { _ = consumer.Process(); close(done) }()

	for range 10 {
		_ = exec.Command("cmd.exe", "/c", "ver").Run()
		time.Sleep(150 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)

	_ = sess.Stop()
	_ = consumer.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ProcessTrace did not return after session stop")
	}

	if atomic.LoadInt64(&total) == 0 {
		t.Fatal("no events received")
	}
	mu.Lock()
	defer mu.Unlock()
	if !gotPID {
		t.Error("no ProcessStart event yielded a ProcessID")
	}
	if !gotImage {
		t.Error("no ProcessStart event yielded an ImageName")
	}
	t.Logf("received %d events; extracted pid=%v image=%v", atomic.LoadInt64(&total), gotPID, gotImage)
}
