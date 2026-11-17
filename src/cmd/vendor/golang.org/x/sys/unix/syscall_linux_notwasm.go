// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !wasm

package unix

import "unsafe"

// sysFcntl is the fcntl system call that fcntl64Syscall starts from (see
// fcntl.go). linux/wasm has only SYS_FCNTL64.
const sysFcntl = SYS_FCNTL

// The kernel structures below hold pointers. On linux/wasm a pointer member
// is a 32-bit address (see syscall_linux_wasm.go), so the code that fills
// them in goes through these methods.

func (msg *Msghdr) setName(p unsafe.Pointer) { msg.Name = (*byte)(p) }

func (msg *Msghdr) setIov(iov *Iovec) { msg.Iov = iov }

func (msg *Msghdr) setControl(p *byte) { msg.Control = p }
