// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package linux

// On linux/wasm the kernel is the WebAssembly host. It takes Linux system
// calls through a single import, browser_os_linux.syscall, with the numbers,
// argument layout, structures and errno values of riscv32 Linux (ILP32,
// 64-bit time_t). Every argument is a 32-bit long widened to i64; a 64-bit
// value is passed as two arguments, low word first, without padding.
// The result is the value of the riscv32 a0 register, a 32-bit long, in the
// low word: -errno on failure. Like any 32-bit Linux port, a result is
// sign-extended to a Go word; callers that get an address back (mmap)
// zero-extend it.

//go:wasmimport browser_os_linux syscall
//go:noescape
func syscall6(num int32, a1, a2, a3, a4, a5, a6 int64) int64

// Syscall6 calls system call number 'num' with arguments a1-6.
//
//go:nosplit
func Syscall6(num, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, errno uintptr) {
	r := int32(syscall6(int32(num), arg(a1), arg(a2), arg(a3), arg(a4), arg(a5), arg(a6)))
	if r < 0 && r > -4096 {
		return ^uintptr(0), 0, uintptr(-r)
	}
	return uintptr(r), 0, 0
}

// arg narrows a Go word to the 32-bit long the kernel reads. Pointers fit,
// since wasm32 addresses are below 4GiB; sign-extension keeps negative ints
// (AT_FDCWD) negative.
//
//go:nosplit
func arg(a uintptr) int64 {
	return int64(int32(uint32(a)))
}
