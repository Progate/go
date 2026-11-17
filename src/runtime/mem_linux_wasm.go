// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "unsafe"

// On linux/wasm the kernel owns the linear memory past the program image: it
// hands it out through brk(2) and mmap(2) (file mappings, thread stacks), and
// grows the memory as needed. So the runtime grows its heap through the
// kernel too, as Plan 9 does with its brk: the break first, and when a
// mapping sits right after the break, a new region from mmap, as Linux's
// malloc does.

const (
	_SYS_brk   = 214
	_SYS_mmap2 = 222

	_PROT_READ     = 0x1
	_PROT_WRITE    = 0x2
	_MAP_PRIVATE   = 0x2
	_MAP_ANONYMOUS = 0x20
)

func sbrk(n uintptr) unsafe.Pointer {
	bl := bloc
	n = memRound(n)
	if bl+n > blocMax {
		if brk(bl+n) < bl+n {
			p := mmapAnon(n)
			if p == 0 {
				return nil
			}
			bloc = p + n
			blocMax = bloc
			return unsafe.Pointer(p)
		}
		blocMax = bl + n
	}
	bloc += n
	return unsafe.Pointer(bl)
}

// brk sets the program break to end and returns the new break, which is
// the old one when it cannot move.
func brk(end uintptr) uintptr {
	r, e := syscall6(_SYS_brk, end, 0, 0, 0, 0, 0)
	if e != 0 {
		return 0
	}
	return uintptr(uint32(r))
}

// mmapAnon maps n bytes of fresh memory, aligned to physPageSize.
func mmapAnon(n uintptr) uintptr {
	r, e := syscall6(_SYS_mmap2, 0, n+physPageSize, _PROT_READ|_PROT_WRITE, _MAP_PRIVATE|_MAP_ANONYMOUS, ^uintptr(0), 0)
	if e != 0 {
		return 0
	}
	return memRound(uintptr(uint32(r)))
}
