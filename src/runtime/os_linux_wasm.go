// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// linux/wasm runs a Go program as a Linux process whose kernel is the
// WebAssembly host. The runtime is the single-threaded one of GOARCH=wasm
// (no threads, no signals, the heap grows with memory.grow) and talks to the
// kernel only through Linux system calls (see internal/runtime/syscall/linux).
// The ABI of the kernel is riscv32 Linux: 32-bit longs and pointers, 64-bit
// time_t.

package runtime

import (
	"internal/runtime/syscall/linux"
	"unsafe"
)

// System call numbers used here (riscv32, asm-generic/unistd.h).
const (
	_SYS_write                  = 64
	_SYS_exit_group             = 94
	_SYS_getrandom              = 278
	_SYS_clock_gettime64        = 403
	_SYS_clock_nanosleep_time64 = 407
	_SYS_sched_yield            = 124
	_SYS_getpid                 = 172
	_SYS_kill                   = 129
	_SYS_fcntl64                = 25

	_CLOCK_REALTIME  = 0
	_CLOCK_MONOTONIC = 1

	_AT_NULL   = 0
	_AT_PAGESZ = 6
	_AT_SECURE = 23
	_AT_RANDOM = 25

	_EINTR  = 4
	_EAGAIN = 11
)

// Flags of open(2) and pipe2(2) (asm-generic/fcntl.h).
const (
	_O_WRONLY   = 0x1
	_O_CREAT    = 0x40
	_O_TRUNC    = 0x200
	_O_NONBLOCK = 0x800
	_O_CLOEXEC  = 0x80000

	_SYS_pipe2 = 59
)

func sched_yield() uint32 {
	_, e := syscall6(_SYS_sched_yield, 0, 0, 0, 0, 0, 0)
	return uint32(e)
}

func pipe2(flags int32) (r, w int32, errno int32) {
	var p [2]int32
	_, e := syscall6(_SYS_pipe2, uintptr(unsafe.Pointer(&p)), uintptr(flags), 0, 0, 0, 0)
	return p[0], p[1], int32(e)
}

// timespec64 is struct __kernel_timespec.
type timespec64 struct {
	sec  int64
	nsec int64
}

// startStack is the initial stack of the process. The linker points the
// exported __stack_pointer at its top, and the kernel lays argc, argv, envp
// and auxv out below that (see rt0_linux_wasm.s).
var startStack [256 << 10]byte

// startBlock is the stack pointer the kernel left: the address of argc.
var startBlock uintptr

// secureMode is set from AT_SECURE, as on other Linux ports.
var secureMode bool

func syscall6(nr uintptr, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr) {
	r, _, e := linux.Syscall6(nr, a1, a2, a3, a4, a5, a6)
	return r, e
}

func exit(code int32) {
	for {
		syscall6(_SYS_exit_group, uintptr(code), 0, 0, 0, 0, 0)
	}
}

// write1 calls the write system call.
// It returns a non-negative number of bytes written or a negative errno value.
//
//go:nosplit
func write1(fd uintptr, p unsafe.Pointer, n int32) int32 {
	r, e := syscall6(_SYS_write, fd, uintptr(p), uintptr(n), 0, 0, 0)
	if e != 0 {
		return -int32(e)
	}
	return int32(r)
}

// read calls the read system call.
// It returns a non-negative number of bytes read or a negative errno value.
func read(fd int32, p unsafe.Pointer, n int32) int32 {
	r, e := linux.Read(int(fd), unsafe.Slice((*byte)(p), n))
	if e != 0 {
		return -int32(e)
	}
	return int32(r)
}

func open(name *byte, mode, perm int32) int32 {
	fd, e := linux.Open(name, int(mode), uint32(perm))
	if e != 0 {
		return -1
	}
	return int32(fd)
}

func closefd(fd int32) int32 {
	if linux.Close(int(fd)) != 0 {
		return -1
	}
	return 0
}

//go:nosplit
func fcntl(fd, cmd, arg int32) (ret int32, errno int32) {
	r, e := syscall6(_SYS_fcntl64, uintptr(fd), uintptr(cmd), uintptr(arg), 0, 0, 0)
	return int32(r), int32(e)
}

func usleep(usec uint32) {
	ts := timespec64{sec: int64(usec / 1e6), nsec: int64(usec%1e6) * 1e3}
	for {
		_, e := syscall6(_SYS_clock_nanosleep_time64, _CLOCK_MONOTONIC, 0, uintptr(unsafe.Pointer(&ts)), uintptr(unsafe.Pointer(&ts)), 0, 0)
		if e != _EINTR {
			return
		}
	}
}

func readRandom(r []byte) int {
	n := 0
	for n < len(r) {
		got, e := syscall6(_SYS_getrandom, uintptr(unsafe.Pointer(&r[n])), uintptr(len(r)-n), 0, 0, 0, 0)
		if e == _EINTR {
			continue
		}
		if e != 0 {
			break
		}
		n += int(got)
	}
	return n
}

func clockGettime(clock uintptr) timespec64 {
	var ts timespec64
	if _, e := syscall6(_SYS_clock_gettime64, clock, uintptr(unsafe.Pointer(&ts)), 0, 0, 0, 0); e != 0 {
		throw("clock_gettime failed")
	}
	return ts
}

func walltime() (sec int64, nsec int32) {
	ts := clockGettime(_CLOCK_REALTIME)
	return ts.sec, int32(ts.nsec)
}

func nanotime1() int64 {
	ts := clockGettime(_CLOCK_MONOTONIC)
	return ts.sec*1e9 + ts.nsec
}

// startWord reads the i'th 32-bit word of the start block.
func startWord(i uintptr) uint32 {
	return *(*uint32)(unsafe.Pointer(startBlock + i*4))
}

// startString copies the NUL-terminated string at the 32-bit address p.
func startString(p uint32) string {
	if p == 0 {
		return ""
	}
	return gostring((*byte)(unsafe.Pointer(uintptr(p))))
}

// sysargs is called from schedinit through args on other ports. Here the
// arguments come from the start block in goenvs.
func sysargs(argc int32, argv **byte) {}

// goenvs reads argc, argv, envp and auxv from the start block that execve(2)
// left at the top of the initial stack:
//
//	argc
//	argv[0] .. argv[argc-1], 0
//	envp[0] .. , 0
//	auxv pairs, ending with {AT_NULL, 0}
func goenvs() {
	top := uintptr(unsafe.Pointer(&startStack[0])) + uintptr(len(startStack))
	if startBlock == 0 || startBlock >= top {
		// Started without a start block (nothing was laid out).
		return
	}
	i := uintptr(0)
	argc := uintptr(startWord(i))
	i++
	argslice = make([]string, argc)
	for j := range argslice {
		argslice[j] = startString(startWord(i))
		i++
	}
	i++ // NULL
	n := uintptr(0)
	for startWord(i+n) != 0 {
		n++
	}
	envs = make([]string, n)
	for j := range envs {
		envs[j] = startString(startWord(i))
		i++
	}
	i++ // NULL
	for {
		key, val := startWord(i), startWord(i+1)
		i += 2
		switch key {
		case _AT_NULL:
			return
		case _AT_SECURE:
			secureMode = val == 1
		case _AT_RANDOM:
			startupRand = unsafe.Slice((*byte)(unsafe.Pointer(uintptr(val))), 16)
		}
	}
}

// sbrk0 returns the current process brk, or 0 if not implemented.
// The Go heap grows with memory.grow (see mem_wasm.go), not brk(2).

//go:nowritebarrierrec
//go:nosplit
func libpreinit() {}

//go:nowritebarrierrec
//go:nosplit
func newosproc0(stacksize uintptr, fn unsafe.Pointer) {
	throw("bad newosproc0")
}

// signalM sends a signal to the thread of mp. There is a single thread.
func signalM(mp *m, sig int) {}

// raiseproc sends sig to the process itself, as Linux's raise(3) does on a
// single-threaded process.
func raiseproc(sig uint32) {
	pid, _ := syscall6(_SYS_getpid, 0, 0, 0, 0, 0, 0)
	syscall6(_SYS_kill, pid, uintptr(sig), 0, 0, 0, 0)
}
