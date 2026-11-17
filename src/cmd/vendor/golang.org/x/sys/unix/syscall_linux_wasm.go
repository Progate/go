// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build wasm && linux

// linux/wasm talks to its kernel with the system calls of riscv32 Linux.
// riscv32 is a 32-bit ABI with a 64-bit time_t and off_t, so it has none of
// the old calls: no stat family (statx), no lseek (_llseek), no getrlimit
// (prlimit64) and only the _time64 variants of the calls that take a time.

package unix

import (
	"runtime"
	"syscall"
	"unsafe"
)

// The system call entry points. The kernel is reached through the syscall
// package, which calls the single import browser_os_linux.syscall.

func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.Syscall(trap, a1, a2, a3)
}

func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.Syscall6(trap, a1, a2, a3, a4, a5, a6)
}

func RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.RawSyscall(trap, a1, a2, a3)
}

func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.RawSyscall6(trap, a1, a2, a3, a4, a5, a6)
}

// SyscallNoError may be used instead of Syscall for syscalls that don't fail.
func SyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr) {
	r1, r2, _ = syscall.Syscall(trap, a1, a2, a3)
	return
}

// RawSyscallNoError may be used instead of RawSyscall for syscalls that don't
// fail.
func RawSyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr) {
	r1, r2, _ = syscall.RawSyscall(trap, a1, a2, a3)
	return
}

// sysFcntl is the fcntl system call that fcntl64Syscall starts from (see
// fcntl.go).
const sysFcntl = SYS_FCNTL64

//sys	EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error) = SYS_EPOLL_PWAIT
//sys	Fadvise(fd int, offset int64, length int64, advice int) (err error) = SYS_FADVISE64_64
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	fstatfs64(fd int, size uintptr, buf *Statfs_t) (err error) = SYS_FSTATFS64
//sys	statfs64(path string, size uintptr, buf *Statfs_t) (err error) = SYS_STATFS64
//sys	Ftruncate(fd int, length int64) (err error) = SYS_FTRUNCATE64
//sysnb	Getegid() (egid int)
//sysnb	Geteuid() (euid int)
//sysnb	Getgid() (gid int)
//sysnb	Getuid() (uid int)
//sys	Listen(s int, n int) (err error)
//sys	MemfdSecret(flags int) (fd int, err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error) = SYS_PREAD64
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error) = SYS_PWRITE64
//sys	llseek(fd int, offhi uintptr, offlo uintptr, result *int64, whence int) (err error) = SYS__LLSEEK
//sys	sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) = SYS_SENDFILE64
//sys	setfsgid(gid int) (prev int, err error)
//sys	setfsuid(uid int) (prev int, err error)
//sys	Shutdown(fd int, how int) (err error)
//sys	Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int64, err error)
//sys	SyncFileRange(fd int, off int64, n int64, flags int) (err error)
//sys	Truncate(path string, length int64) (err error) = SYS_TRUNCATE64
//sys	accept4(s int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (fd int, err error)
//sys	bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sys	connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sysnb	getgroups(n int, list *_Gid_t) (nn int, err error)
//sysnb	setgroups(n int, list *_Gid_t) (err error)
//sys	getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error)
//sys	setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)
//sysnb	socket(domain int, typ int, proto int) (fd int, err error)
//sysnb	socketpair(domain int, typ int, proto int, fd *[2]int32) (err error)
//sysnb	getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
//sysnb	getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
//sys	recvfrom(fd int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error)
//sys	sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error)
//sys	recvmsg(s int, msg *Msghdr, flags int) (n int, err error)
//sys	sendmsg(s int, msg *Msghdr, flags int) (n int, err error)
//sys	mmap2(addr uintptr, length uintptr, prot int, flags int, fd int, pageOffset uintptr) (xaddr uintptr, err error)

// The calls of syscall_linux_time32.go, which riscv32 has only as a _time64
// variant.

//sys	ppoll(fds *PollFd, nfds int, timeout *Timespec, sigmask *Sigset_t) (n int, err error) = SYS_PPOLL_TIME64
//sys	utimensat(dirfd int, path string, times *[2]Timespec, flags int) (err error) = SYS_UTIMENSAT_TIME64
//sys	ClockAdjtime(clockid int32, buf *Timex) (state int, err error) = SYS_CLOCK_ADJTIME64
//sys	ClockGetres(clockid int32, res *Timespec) (err error) = SYS_CLOCK_GETRES_TIME64
//sys	ClockGettime(clockid int32, time *Timespec) (err error) = SYS_CLOCK_GETTIME64
//sys	ClockSettime(clockid int32, time *Timespec) (err error) = SYS_CLOCK_SETTIME64
//sys	ClockNanosleep(clockid int32, flags int, request *Timespec, remain *Timespec) (err error) = SYS_CLOCK_NANOSLEEP_TIME64
//sys	pselect6(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timespec, sigmask *sigsetArgpack32) (n int, err error) = SYS_PSELECT6_TIME64
//sysnb	TimerfdGettime(fd int, currValue *ItimerSpec) (err error) = SYS_TIMERFD_GETTIME64
//sysnb	TimerfdSettime(fd int, flags int, newValue *ItimerSpec, oldValue *ItimerSpec) (err error) = SYS_TIMERFD_SETTIME64

// Adjtimex is clock_adjtime(CLOCK_REALTIME) (riscv32 has no adjtimex).
func Adjtimex(buf *Timex) (state int, err error) {
	return ClockAdjtime(CLOCK_REALTIME, buf)
}

// Nanosleep is clock_nanosleep(CLOCK_REALTIME) (riscv32 has no nanosleep).
func Nanosleep(time *Timespec, leftover *Timespec) (err error) {
	return ClockNanosleep(CLOCK_REALTIME, 0, time, leftover)
}

// Settimeofday is clock_settime(CLOCK_REALTIME) (riscv32 has no
// settimeofday).
func Settimeofday(tv *Timeval) (err error) {
	ts := Timespec{Sec: int64(tv.Sec), Nsec: int64(tv.Usec) * 1000}
	return ClockSettime(CLOCK_REALTIME, &ts)
}

func Gettimeofday(tv *Timeval) (err error) {
	var ts Timespec
	if err := ClockGettime(CLOCK_REALTIME, &ts); err != nil {
		return err
	}
	*tv = Timeval{Sec: int32(ts.Sec), Usec: int32(ts.Nsec / 1000)}
	return nil
}

func Time(t *Time_t) (Time_t, error) {
	var ts Timespec
	if err := ClockGettime(CLOCK_REALTIME, &ts); err != nil {
		return 0, err
	}
	if t != nil {
		*t = Time_t(ts.Sec)
	}
	return Time_t(ts.Sec), nil
}

// sigsetArgpack32 is the last argument of pselect6: a pointer to the signal
// set and its size, as 32-bit words.
type sigsetArgpack32 struct {
	ss    uint32 // sigset_t *
	ssLen uint32
}

// Pselect is a wrapper around the Linux pselect6 system call.
// This version does not modify the timeout argument.
func Pselect(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timespec, sigmask *Sigset_t) (n int, err error) {
	var mutableTimeout *Timespec
	if timeout != nil {
		mutableTimeout = new(Timespec)
		*mutableTimeout = *timeout
	}
	var kernelMask *sigsetArgpack32
	if sigmask != nil {
		// _C__NSIG - 1 signals, one bit each, in 32-bit words.
		kernelMask = &sigsetArgpack32{
			ss:    uint32(uintptr(unsafe.Pointer(sigmask))),
			ssLen: uint32((_C__NSIG - 1 + 31) / 32 * 4),
		}
	}
	n, err = pselect6(nfd, r, w, e, mutableTimeout, kernelMask)
	runtime.KeepAlive(sigmask)
	return n, err
}

func Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error) {
	var ts *Timespec
	if timeout != nil {
		ts = &Timespec{Sec: int64(timeout.Sec), Nsec: int64(timeout.Usec) * 1000}
	}
	return pselect6(nfd, r, w, e, ts, nil)
}

func fillStat(st *Stat_t, sx *Statx_t) {
	*st = Stat_t{
		Dev:     Mkdev(sx.Dev_major, sx.Dev_minor),
		Ino:     sx.Ino,
		Mode:    uint32(sx.Mode),
		Nlink:   sx.Nlink,
		Uid:     sx.Uid,
		Gid:     sx.Gid,
		Rdev:    Mkdev(sx.Rdev_major, sx.Rdev_minor),
		Size:    int64(sx.Size),
		Blksize: int32(sx.Blksize),
		Blocks:  int64(sx.Blocks),
		Atim:    Timespec{Sec: sx.Atime.Sec, Nsec: int64(sx.Atime.Nsec)},
		Mtim:    Timespec{Sec: sx.Mtime.Sec, Nsec: int64(sx.Mtime.Nsec)},
		Ctim:    Timespec{Sec: sx.Ctime.Sec, Nsec: int64(sx.Ctime.Nsec)},
	}
}

// Fstatat is statx(2) with the basic stats (riscv32 has no stat family).
func Fstatat(dirfd int, path string, stat *Stat_t, flags int) error {
	var sx Statx_t
	if err := Statx(dirfd, path, flags|AT_NO_AUTOMOUNT, STATX_BASIC_STATS, &sx); err != nil {
		return err
	}
	fillStat(stat, &sx)
	return nil
}

func Fstat(fd int, stat *Stat_t) error {
	return Fstatat(fd, "", stat, AT_EMPTY_PATH)
}

func Stat(path string, stat *Stat_t) (err error) {
	return Fstatat(AT_FDCWD, path, stat, 0)
}

func Lstat(path string, stat *Stat_t) (err error) {
	return Fstatat(AT_FDCWD, path, stat, AT_SYMLINK_NOFOLLOW)
}

func Lchown(path string, uid int, gid int) (err error) {
	return Fchownat(AT_FDCWD, path, uid, gid, AT_SYMLINK_NOFOLLOW)
}

func Fstatfs(fd int, buf *Statfs_t) (err error) {
	return fstatfs64(fd, unsafe.Sizeof(*buf), buf)
}

func Statfs(path string, buf *Statfs_t) (err error) {
	return statfs64(path, unsafe.Sizeof(*buf), buf)
}

func Ustat(dev int, ubuf *Ustat_t) (err error) {
	return ENOSYS
}

// Getrlimit is prlimit64 on the calling process (riscv32 has no getrlimit).
func Getrlimit(resource int, rlim *Rlimit) (err error) {
	return Prlimit(0, resource, nil, rlim)
}

func Seek(fd int, offset int64, whence int) (newoffset int64, err error) {
	err = llseek(fd, uintptr(uint64(offset)>>32), uintptr(uint32(offset)), &newoffset, whence)
	return newoffset, err
}

func mmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset int64) (xaddr uintptr, err error) {
	page := uintptr(offset / 4096)
	if offset != int64(page)*4096 {
		return 0, EINVAL
	}
	xaddr, err = mmap2(addr, length, prot, flags, fd, page)
	// An address is an unsigned 32-bit value.
	return uintptr(uint32(xaddr)), err
}

func setTimespec(sec, nsec int64) Timespec {
	return Timespec{Sec: sec, Nsec: nsec}
}

func setTimeval(sec, usec int64) Timeval {
	return Timeval{Sec: int32(sec), Usec: int32(usec)}
}

func futimesat(dirfd int, path string, tv *[2]Timeval) (err error) {
	if tv == nil {
		return utimensat(dirfd, path, nil, 0)
	}

	ts := []Timespec{
		NsecToTimespec(TimevalToNsec(tv[0])),
		NsecToTimespec(TimevalToNsec(tv[1])),
	}
	return utimensat(dirfd, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
}

func Utime(path string, buf *Utimbuf) error {
	if buf == nil {
		return Utimes(path, nil)
	}
	tv := []Timeval{
		{Sec: buf.Actime},
		{Sec: buf.Modtime},
	}
	return Utimes(path, tv)
}

func utimes(path string, tv *[2]Timeval) (err error) {
	if tv == nil {
		return utimensat(AT_FDCWD, path, nil, 0)
	}

	ts := []Timespec{
		NsecToTimespec(TimevalToNsec(tv[0])),
		NsecToTimespec(TimevalToNsec(tv[1])),
	}
	return utimensat(AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
}

func (r *PtraceRegs) PC() uint64 { return uint64(r.Pc) }

func (r *PtraceRegs) SetPC(pc uint64) { r.Pc = uint32(pc) }

// SetBase points iov at p. Iovec.Base is a 32-bit address on linux/wasm.
func (iov *Iovec) SetBase(p *byte) {
	iov.Base = uint32(uintptr(unsafe.Pointer(p)))
}

func (iov *Iovec) setBase(p *byte) { iov.SetBase(p) }

func (iov *Iovec) base() unsafe.Pointer { return unsafe.Pointer(uintptr(iov.Base)) }

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint32(length)
}

func (msg *Msghdr) setName(p unsafe.Pointer) { msg.Name = uint32(uintptr(p)) }

func (msg *Msghdr) setIov(iov *Iovec) { msg.Iov = uint32(uintptr(unsafe.Pointer(iov))) }

func (msg *Msghdr) setControl(p *byte) { msg.Control = uint32(uintptr(unsafe.Pointer(p))) }

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = uint32(length)
}

func (msghdr *Msghdr) SetIovlen(length int) {
	msghdr.Iovlen = uint32(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = uint32(length)
}

func (rsa *RawSockaddrNFCLLCP) SetServiceNameLen(length int) {
	rsa.Service_name_len = uint32(length)
}

// ifreqData is an Ifreq which carries pointer data, as a 32-bit address.
// To produce an ifreqData, use the Ifreq.withData method.
type ifreqData struct {
	name [IFNAMSIZ]byte
	data uint32 // void *
	// Pad to the same size as ifreq.
	_ [len(ifreq{}.Ifru) - 4]byte
}

// withData produces an ifreqData with the pointer p set for ioctls which require
// arbitrary pointer data.
func (ifr Ifreq) withData(p unsafe.Pointer) ifreqData {
	return ifreqData{
		name: ifr.raw.Ifrn,
		data: uint32(uintptr(p)),
	}
}

func Pause() error {
	_, err := ppoll(nil, 0, nil, nil)
	return err
}

func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error) {
	return Renameat2(olddirfd, oldpath, newdirfd, newpath, 0)
}

//sys	kexecFileLoad(kernelFd int, initrdFd int, cmdlineLen int, cmdline string, flags int) (err error)

func KexecFileLoad(kernelFd int, initrdFd int, cmdline string, flags int) error {
	cmdlineLen := len(cmdline)
	if cmdlineLen > 0 {
		// Account for the additional NULL byte added by
		// BytePtrFromString in kexecFileLoad. The kexec_file_load
		// syscall expects a NULL-terminated string.
		cmdlineLen++
	}
	return kexecFileLoad(kernelFd, initrdFd, cmdlineLen, cmdline, flags)
}
