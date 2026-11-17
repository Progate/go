// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The system calls of syscall_linux.go that riscv32 (linux/wasm) has only as a
// _time64 variant, or not at all. syscall_linux_wasm.go has those.

//go:build linux && !wasm

package unix

//sys	ppoll(fds *PollFd, nfds int, timeout *Timespec, sigmask *Sigset_t) (n int, err error)
//sys	utimensat(dirfd int, path string, times *[2]Timespec, flags int) (err error)
//sys	Adjtimex(buf *Timex) (state int, err error)
//sys	ClockAdjtime(clockid int32, buf *Timex) (state int, err error)
//sys	ClockGetres(clockid int32, res *Timespec) (err error)
//sys	ClockGettime(clockid int32, time *Timespec) (err error)
//sys	ClockSettime(clockid int32, time *Timespec) (err error)
//sys	ClockNanosleep(clockid int32, flags int, request *Timespec, remain *Timespec) (err error)
//sys	Nanosleep(time *Timespec, leftover *Timespec) (err error)
//sys	pselect6(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timespec, sigmask *sigset_argpack) (n int, err error)
//sysnb	Settimeofday(tv *Timeval) (err error)
//sysnb	TimerfdGettime(fd int, currValue *ItimerSpec) (err error)
//sysnb	TimerfdSettime(fd int, flags int, newValue *ItimerSpec, oldValue *ItimerSpec) (err error)

// Pselect is a wrapper around the Linux pselect6 system call.
// This version does not modify the timeout argument.
func Pselect(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timespec, sigmask *Sigset_t) (n int, err error) {
	// Per https://man7.org/linux/man-pages/man2/select.2.html#NOTES,
	// The Linux pselect6() system call modifies its timeout argument.
	// [Not modifying the argument] is the behavior required by POSIX.1-2001.
	var mutableTimeout *Timespec
	if timeout != nil {
		mutableTimeout = new(Timespec)
		*mutableTimeout = *timeout
	}

	// The final argument of the pselect6() system call is not a
	// sigset_t * pointer, but is instead a structure
	var kernelMask *sigset_argpack
	if sigmask != nil {
		wordBits := 32 << (^uintptr(0) >> 63) // see math.intSize

		// A sigset stores one bit per signal,
		// offset by 1 (because signal 0 does not exist).
		// So the number of words needed is ⌈__C_NSIG - 1 / wordBits⌉.
		sigsetWords := (_C__NSIG - 1 + wordBits - 1) / (wordBits)

		sigsetBytes := uintptr(sigsetWords * (wordBits / 8))
		kernelMask = &sigset_argpack{
			ss:    sigmask,
			ssLen: sigsetBytes,
		}
	}

	return pselect6(nfd, r, w, e, mutableTimeout, kernelMask)
}
