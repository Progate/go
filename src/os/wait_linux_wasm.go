// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os

import (
	"internal/syscall/unix"
	"runtime"
	"syscall"
	"time"
)

// blockUntilWaitable attempts to block until a call to p.Wait will
// succeed immediately, and reports whether it has done so.
// It does not actually call p.Wait.
//
// The linux/wasm runtime runs every goroutine on one thread, so a waitid(2)
// that blocks until the child exits would stop the goroutines the child may
// be waiting on (one feeding its standard input, say). Instead this polls
// with WNOHANG and sleeps in between, which lets the other goroutines and the
// network poller run.
func (p *Process) blockUntilWaitable() (bool, error) {
	delay := 100 * time.Microsecond
	for {
		var info unix.SiginfoChild
		err := ignoringEINTR(func() error {
			return unix.Waitid(unix.P_PID, p.Pid, &info, syscall.WEXITED|syscall.WNOWAIT|syscall.WNOHANG, nil)
		})
		runtime.KeepAlive(p)
		if err != nil {
			if err == syscall.ENOSYS {
				return false, nil
			}
			return false, NewSyscallError("waitid", err)
		}
		if info.Pid != 0 {
			return true, nil
		}
		time.Sleep(delay)
		if delay < 20*time.Millisecond {
			delay *= 2
		}
	}
}
