// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris) && !(linux && wasm)

package unix

import "unsafe"

// The kernel structures below hold pointers. On linux/wasm a pointer member
// is a 32-bit address (see syscall_linux_wasm.go), so the code that fills
// them in goes through these methods.

func (iov *Iovec) setBase(p *byte) { iov.Base = p }

func (iov *Iovec) base() unsafe.Pointer { return unsafe.Pointer(iov.Base) }
