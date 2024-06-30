// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package gp

import (
	"testing"
	"time"

	"tailscale.com/util/cibuild"
)

func TestWatchForPolicyChange(t *testing.T) {
	if cibuild.On() {
		// Unlike tests that also use the GP API in net\dns\manager_windows_test.go,
		// this one does not require elevation. However, a Group Policy change notification
		// never arrives when this tests runs on a GitHub-hosted runner.
		t.Skipf("test requires running on a real Windows environment")
	}

	done, close := setupMachinePolicyChangeNotifier(t)
	defer close()

	// RefreshMachinePolicy is a non-blocking call.
	if err := RefreshMachinePolicy(true); err != nil {
		t.Fatalf("RefreshMachinePolicy failed: %v\n", err)
	}

	// We should receive a policy change notification when
	// the Group Policy service completes policy processing.
	// Otherwise, the test will eventually time out.
	<-done
}

func TestGroupPolicyReadLock(t *testing.T) {
	if cibuild.On() {
		// Unlike tests that also use the GP API in net\dns\manager_windows_test.go,
		// this one does not require elevation. However, a Group Policy change notification
		// never arrives when this tests runs on a GitHub-hosted runner.
		t.Skipf("test requires running on a real Windows environment")
	}

	done, close := setupMachinePolicyChangeNotifier(t)
	defer close()

	doWithMachinePolicyLocked(t, func() {
		// RefreshMachinePolicy is a non-blocking call.
		if err := RefreshMachinePolicy(true); err != nil {
			t.Fatalf("RefreshMachinePolicy failed: %v\n", err)
		}

		// Give the Group Policy service a few seconds to attempt to refresh the policy.
		// It shouldn't be able to do so while the lock is held, and the below should time out.
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		select {
		case <-timeout.C:
		case <-done:
			t.Fatal("Policy refresh occurred while the policy lock was held\n")
		}
	})

	// We should receive a policy change notification once the lock is released
	// and GP can refresh the policy.
	// Otherwise, the test will eventually time out.
	<-done
}

func setupMachinePolicyChangeNotifier(t *testing.T) (chan struct{}, func()) {
	done := make(chan struct{})
	var watcher *ChangeWatcher
	watcher, err := NewChangeWatcher(MachinePolicy, func() {
		close(done)
	})
	if err != nil {
		t.Fatalf("NewChangeWatcher failed: %v\n", err)
	}
	return done, func() {
		if err := watcher.Close(); err != nil {
			t.Errorf("(*ChangeWatcher).Close failed: %v\n", err)
		}
	}
}

func doWithMachinePolicyLocked(t *testing.T, f func()) {
	gpLock := NewMachinePolicyLock()
	if err := gpLock.Lock(); err != nil {
		t.Fatalf("(*PolicyLock).Lock failed: %v\n", err)
	}
	defer gpLock.Unlock()
	f()
}
