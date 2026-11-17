// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall

import "unsafe"

// fcntl64Syscall is usually SYS_FCNTL, but is overridden on 32-bit Linux
// systems by flock_linux_32bit.go to be SYS_FCNTL64. linux/wasm has only
// SYS_FCNTL64 (see _SYS_fcntl).
var fcntl64Syscall uintptr = _SYS_fcntl

// FcntlFlock performs a fcntl syscall for the [F_GETLK], [F_SETLK] or [F_SETLKW] command.
func FcntlFlock(fd uintptr, cmd int, lk *Flock_t) error {
	_, _, errno := Syscall(fcntl64Syscall, fd, uintptr(cmd), uintptr(unsafe.Pointer(lk)))
	if errno == 0 {
		return nil
	}
	return errno
}
