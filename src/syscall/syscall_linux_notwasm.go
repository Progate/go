// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !wasm

package syscall

import "unsafe"

const _SYS_fcntl = SYS_FCNTL

func rawSyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr)
func rawVforkSyscall(trap, a1, a2, a3 uintptr) (r1 uintptr, err Errno)

// The kernel structures below hold pointers. On linux/wasm a pointer member
// is a 32-bit address (see syscall_linux_wasm.go), so the code that fills
// them in goes through these methods.

func (iov *Iovec) setBase(p *byte) { iov.Base = p }

func (msg *Msghdr) setName(p unsafe.Pointer) { msg.Name = (*byte)(p) }

func (msg *Msghdr) setIov(iov *Iovec) { msg.Iov = iov }

func (msg *Msghdr) setControl(p *byte) { msg.Control = p }

func (p *SockFprog) setFilter(f *SockFilter) { p.Filter = f }
