// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package gp

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"tailscale.com/types/lazy"
)

// PolicyLock allows pausing the application of policy to safely read Group Policy
// settings. A PolicyLock is an R-lock that can be held by multiple readers simultaneously,
// preventing the Group Policy Client service (which maintains its W-counterpart) from
// modifying policies while they are being read.
//
// It is not possible to pause group policy processing for longer than 10 minutes.
// If the system needs to apply policies and the lock is being held for more than that,
// the Group Policy Client service will release the lock and continue policy processing.
//
// To avoid deadlocks when acquiring both machine and user locks, acquire the
// user lock before the machine lock.
type PolicyLock struct {
	scope Scope
	token windows.Token

	closing chan struct{} // closing is closed when the Close method is called.

	mu      sync.Mutex
	handle  atomic.Uintptr
	lockCnt atomic.Int32 // A non-zero LSB indicates that the lock can be acquired.
}

// policyLockHandle is the underlying lock handle returned by enterCriticalPolicySection.
type policyLockHandle uintptr

type policyLockResult struct {
	handle policyLockHandle
	err    error
}

var (
	// ErrInvalidLockState is returned by (*PolicyLock).Lock if the lock has a zero value or has already been closed.
	ErrInvalidLockState = errors.New("the lock has not been created or has already been closed")
	machinePolicyLock   lazy.SyncValue[*PolicyLock]
)

// NewMachinePolicyLock creates a PolicyLock that allows to pause application of the
// computer policy. To avoid deadlocks when acquiring both machine and user
// locks, acquire the user lock before the machine lock.
func NewMachinePolicyLock() *PolicyLock {
	return machinePolicyLock.Get(func() *PolicyLock {
		lock := &PolicyLock{scope: MachinePolicy, closing: make(chan struct{})}
		lock.lockCnt.Store(1) // mark as initialized
		return lock
	})
}

// NewUserPolicyLock creates a PolicyLock that allows to pause application of the
// user policy for the specified user. To avoid deadlocks when acquiring both
// machine and user locks, acquire the user lock before the machine lock.
//
// The token indicates which user's policy should be locked for reading.
// If specified, the token must have TOKEN_DUPLICATE access,
// the specified user must be logged in interactively.
// and the caller retains ownership of the token.
//
// Otherwise, a zero token value indicates the current user. It should not
// be used by services or other applications running under system identities.
func NewUserPolicyLock(token windows.Token) (*PolicyLock, error) {
	cs := &PolicyLock{scope: UserPolicy, closing: make(chan struct{})}
	if token != 0 {
		err := windows.DuplicateHandle(
			windows.CurrentProcess(),
			windows.Handle(token),
			windows.CurrentProcess(),
			(*windows.Handle)(&cs.token),
			windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE,
			false,
			0)
		if err != nil {
			return nil, err
		}
	}
	cs.lockCnt.Store(1) // mark as initialized
	return cs, nil
}

// Lock locks l.
// It returns ErrNotInitialized if l has a zero value or has already been closed,
// or an Errno if the underlying Group Policy lock cannot be acquired.
//
// As a special case, it fails with windows.ERROR_ACCESS_DENIED
// if l is a user policy lock, and the corresponding user is not logged in
// interactively at the time of the call.
func (l *PolicyLock) Lock() error {
	if l == nil || l.lockCnt.Add(2)&1 == 0 {
		// The lock cannot be acquired because it has either never been properly
		// created or its Close method has already been called. However, we need
		// to call Unlock to both decrement lockCnt and leave the underlying
		// CriticalPolicySection if we won the race with another goroutine and
		// now own the lock.
		l.Unlock()
		return ErrInvalidLockState
	}

	if l.handle.Load() != 0 {
		// The underlying CriticalPolicySection is already acquired.
		// It is an R-Lock (with the W-counterpart owned by the Group Policy service),
		// meaning that it can be acquired by multiple readers simultaneously.
		// So we can just return.
		return nil
	}

	return l.lockSlow()
}

func (l *PolicyLock) lockSlow() (err error) {
	// Use the mutex to guarantee that the critical policy section
	// is acquired if lockSlow returns successfully.
	// We don't need this level of synchronization in other methods.
	l.mu.Lock()
	defer l.mu.Unlock()
	defer func() {
		if err != nil {
			// Decrement the counter if the lock cannot be acquired,
			// and complete the pending close request if we're the last owner.
			if l.lockCnt.Add(-2) == 0 {
				l.closeInternal()
			}
		}
	}()

	if l.handle.Load() != 0 {
		// The underlying CriticalPolicySection is already acquired.
		// It is an R-Lock (with the W-counterpart owned by the Group Policy service),
		// meaning that it can be acquired by multiple readers simultaneously.
		// So we can just return.
		return nil
	}

	if l.lockCnt.Load()&1 == 0 {
		// The Close method was called while we waited on l.mu.
		return ErrInvalidLockState
	}

	// In some cases in production environments, the Group Policy service may
	// hold the corresponding W-Lock for extended periods of time (minutes
	// rather than seconds or milliseconds). We need to make our wait operation
	// cancellable. So, if one goroutine invokes (*PolicyLock).Close while another
	// initiates (*PolicyLock).Lock and waits for the underlying R-lock to be
	// acquired by enterCriticalPolicySection, the Close method should cancel
	// the wait.

	initCh := make(chan error)
	resultCh := make(chan policyLockResult)

	go func() {
		if l.scope == UserPolicy && l.token != 0 {
			// Impersonate the user whose critical policy section we want to acquire.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := impersonateLoggedOnUser(l.token); err != nil {
				initCh <- err
				return
			}
			defer func() {
				if err := windows.RevertToSelf(); err != nil {
					// RevertToSelf errors are non-recoverable.
					panic(fmt.Errorf("could not revert impersonation: %w", err))
				}
			}()
		}
		close(initCh)

		var machine bool
		if l.scope == MachinePolicy {
			machine = true
		}
		handle, err := enterCriticalPolicySection(machine)

		select {
		case resultCh <- policyLockResult{handle, err}:
			// lockSlow has received the result.
		default:
			// The lock is being closed, and we lost the race to l.closing.
			if err == nil {
				leaveCriticalPolicySection(handle)
			}
		}
	}()

	// lockSlow should not return until the goroutine above has been fully initialized,
	// even if the lock is being closed.
	if err = <-initCh; err != nil {
		return err
	}

	select {
	case result := <-resultCh:
		if result.err == nil {
			l.handle.Store(uintptr(result.handle))
		}
		return result.err
	case <-l.closing:
		return ErrInvalidLockState
	}
}

// Unlock unlocks l.
// It panics if l is not locked on entry to Unlock.
func (l *PolicyLock) Unlock() {
	lockCnt := l.lockCnt.Add(-2)
	if lockCnt < 0 {
		panic("negative lockCnt")
	}
	if lockCnt > 1 {
		// The lock is still being used by other readers.
		// We compare against 1 rather than 0 because the least significant bit
		// of lockCnt indicates that l has been initialized and a close
		// has not been requested yet.
		return
	}

	if handle := policyLockHandle(l.handle.Swap(0)); handle != 0 {
		// Impersonation is not required to unlock a critical policy section.
		// The handle we pass determines which mutex will be unlocked.
		leaveCriticalPolicySection(handle)
	}

	if lockCnt == 0 {
		// Complete the pending close request if there's no more readers.
		l.closeInternal()
	}
}

// Close releases resources associated with l.
// It is a no-op for the machine policy lock.
func (l *PolicyLock) Close() error {
	lockCnt := l.lockCnt.Load()
	if lockCnt&1 == 0 {
		// The lock has never been initialized, or close has already been called.
		return nil
	}

	close(l.closing)

	// Unset the LSB to indicate a pending close request.
	for !l.lockCnt.CompareAndSwap(lockCnt, lockCnt&^int32(1)) {
		lockCnt = l.lockCnt.Load()
	}

	if lockCnt != 0 {
		// The lock is still being used and will be closed upon the final Unlock call.
		return nil
	}

	return l.closeInternal()
}

func (l *PolicyLock) closeInternal() error {
	if l.token != 0 {
		if err := l.token.Close(); err != nil {
			return err
		}
		l.token = 0
	}
	l.closing = nil
	return nil
}
