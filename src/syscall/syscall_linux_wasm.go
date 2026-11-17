// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// linux/wasm talks to its kernel with the system calls of riscv32 Linux
// (see internal/runtime/syscall/linux). riscv32 is a 32-bit ABI with a 64-bit
// time_t and off_t, so it has none of the old calls: no stat family (statx),
// no lseek (_llseek), no getrlimit (prlimit64) and only the _time64 variants
// of the calls that take a time.

package syscall

import (
	"internal/runtime/syscall/linux"
	"unsafe"
)

const (
	_SYS_setgroups  = SYS_SETGROUPS
	_SYS_clone3     = SYS_CLONE3
	_SYS_faccessat2 = SYS_FACCESSAT2
	_SYS_fchmodat2  = SYS_FCHMODAT2
	_SYS_fcntl      = SYS_FCNTL64
)

//go:nosplit
func rawSyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr) {
	r1, r2, _ = linux.Syscall6(trap, a1, a2, a3, 0, 0, 0)
	return
}

//sys	EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error) = SYS_EPOLL_PWAIT
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	fstatfs64(fd int, size uintptr, buf *Statfs_t) (err error) = SYS_FSTATFS64
//sys	statfs64(path string, size uintptr, buf *Statfs_t) (err error) = SYS_STATFS64
//sys	Ftruncate(fd int, length int64) (err error) = SYS_FTRUNCATE64
//sys	Truncate(path string, length int64) (err error) = SYS_TRUNCATE64
//sysnb	Getegid() (egid int)
//sysnb	Geteuid() (euid int)
//sysnb	Getgid() (gid int)
//sysnb	Getuid() (uid int)
//sys	Listen(s int, n int) (err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error) = SYS_PREAD64
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error) = SYS_PWRITE64
//sys	renameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) (err error)
//sys	llseek(fd int, offhi uintptr, offlo uintptr, result *int64, whence int) (err error) = SYS__LLSEEK
//sys	sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) = SYS_SENDFILE64
//sys	Setfsgid(gid int) (err error)
//sys	Setfsuid(uid int) (err error)
//sys	Shutdown(fd int, how int) (err error)
//sys	Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int64, err error)
//sys	SyncFileRange(fd int, off int64, n int64, flags int) (err error)
//sys	accept4(s int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (fd int, err error)
//sys	bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sys	connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sysnb	getgroups(n int, list *_Gid_t) (nn int, err error)
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
//sys	statx(dirfd int, path string, flags int, mask int, stat *statx_t) (err error)

// The calls of syscall_linux.go that have a _time64 or 64-bit variant on
// riscv32. mkall.sh leaves their //sys lines in syscall_linux.go out.

//sys	utimensat(dirfd int, path string, times *[2]Timespec, flags int) (err error) = SYS_UTIMENSAT_TIME64
//sys	fcntl(fd int, cmd int, arg int) (val int, err error) = SYS_FCNTL64
//sys	clockNanosleep(clockid int, flags int, request *Timespec, remain *Timespec) (err error) = SYS_CLOCK_NANOSLEEP_TIME64
//sysnb	clockGettime(clockid int, ts *Timespec) (err error) = SYS_CLOCK_GETTIME64
//sysnb	clockSettime(clockid int, ts *Timespec) (err error) = SYS_CLOCK_SETTIME64
//sysnb	clockAdjtime(clockid int, buf *Timex) (state int, err error) = SYS_CLOCK_ADJTIME64

const _CLOCK_REALTIME = 0

func Nanosleep(time *Timespec, leftover *Timespec) (err error) {
	return clockNanosleep(_CLOCK_REALTIME, 0, time, leftover)
}

func Settimeofday(tv *Timeval) (err error) {
	ts := Timespec{Sec: int64(tv.Sec), Nsec: int64(tv.Usec) * 1000}
	return clockSettime(_CLOCK_REALTIME, &ts)
}

func Adjtimex(buf *Timex) (state int, err error) {
	return clockAdjtime(_CLOCK_REALTIME, buf)
}

func Gettimeofday(tv *Timeval) (err error) {
	var ts Timespec
	if err := clockGettime(_CLOCK_REALTIME, &ts); err != nil {
		return err
	}
	*tv = Timeval{Sec: int32(ts.Sec), Usec: int32(ts.Nsec / 1000)}
	return nil
}

func Time(t *Time_t) (Time_t, error) {
	var ts Timespec
	if err := clockGettime(_CLOCK_REALTIME, &ts); err != nil {
		return 0, err
	}
	if t != nil {
		*t = Time_t(ts.Sec)
	}
	return Time_t(ts.Sec), nil
}

// statx_t is struct statx.
type statx_t struct {
	Mask            uint32
	Blksize         uint32
	Attributes      uint64
	Nlink           uint32
	Uid             uint32
	Gid             uint32
	Mode            uint16
	_               [1]uint16
	Ino             uint64
	Size            uint64
	Blocks          uint64
	Attributes_mask uint64
	Atime           statxTimestamp
	Btime           statxTimestamp
	Ctime           statxTimestamp
	Mtime           statxTimestamp
	Rdev_major      uint32
	Rdev_minor      uint32
	Dev_major       uint32
	Dev_minor       uint32
	_               [14]uint64
}

type statxTimestamp struct {
	Sec  int64
	Nsec uint32
	_    int32
}

const (
	_AT_NO_AUTOMOUNT     = 0x800
	_STATX_BASIC_STATS   = 0x7ff
	_AT_STATX_SYNC_AS_ST = 0x0
)

func mkdev(major, minor uint32) uint64 {
	return uint64(major&0xfff)<<8 | uint64(minor&0xff) | uint64(minor&^0xff)<<12 | uint64(major&^0xfff)<<32
}

func fillStat(st *Stat_t, sx *statx_t) {
	*st = Stat_t{
		Dev:     mkdev(sx.Dev_major, sx.Dev_minor),
		Ino:     sx.Ino,
		Mode:    uint32(sx.Mode),
		Nlink:   sx.Nlink,
		Uid:     sx.Uid,
		Gid:     sx.Gid,
		Rdev:    mkdev(sx.Rdev_major, sx.Rdev_minor),
		Size:    int64(sx.Size),
		Blksize: int32(sx.Blksize),
		Blocks:  int64(sx.Blocks),
		Atim:    Timespec{Sec: sx.Atime.Sec, Nsec: int64(sx.Atime.Nsec)},
		Mtim:    Timespec{Sec: sx.Mtime.Sec, Nsec: int64(sx.Mtime.Nsec)},
		Ctim:    Timespec{Sec: sx.Ctime.Sec, Nsec: int64(sx.Ctime.Nsec)},
	}
}

func fstatat(dirfd int, path string, stat *Stat_t, flags int) error {
	var sx statx_t
	if err := statx(dirfd, path, flags|_AT_NO_AUTOMOUNT, _STATX_BASIC_STATS, &sx); err != nil {
		return err
	}
	fillStat(stat, &sx)
	return nil
}

func Fstatat(fd int, path string, stat *Stat_t, flags int) error {
	return fstatat(fd, path, stat, flags)
}

func Fstat(fd int, stat *Stat_t) error {
	return fstatat(fd, "", stat, _AT_EMPTY_PATH)
}

func Stat(path string, stat *Stat_t) (err error) {
	return fstatat(_AT_FDCWD, path, stat, 0)
}

func Lstat(path string, stat *Stat_t) (err error) {
	return fstatat(_AT_FDCWD, path, stat, _AT_SYMLINK_NOFOLLOW)
}

func Lchown(path string, uid int, gid int) (err error) {
	return Fchownat(_AT_FDCWD, path, uid, gid, _AT_SYMLINK_NOFOLLOW)
}

func Fstatfs(fd int, buf *Statfs_t) (err error) {
	return fstatfs64(fd, unsafe.Sizeof(*buf), buf)
}

func Statfs(path string, buf *Statfs_t) (err error) {
	return statfs64(path, unsafe.Sizeof(*buf), buf)
}

func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error) {
	return renameat2(olddirfd, oldpath, newdirfd, newpath, 0)
}

func Seek(fd int, offset int64, whence int) (newoffset int64, err error) {
	err = llseek(fd, uintptr(uint64(offset)>>32), uintptr(uint32(offset)), &newoffset, whence)
	return newoffset, err
}

const pageSize = 4096

func mmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset int64) (xaddr uintptr, err error) {
	page := uintptr(offset / pageSize)
	if offset != int64(page)*pageSize {
		return 0, EINVAL
	}
	xaddr, err = mmap2(addr, length, prot, flags, fd, page)
	// An address is an unsigned 32-bit value.
	return uintptr(uint32(xaddr)), err
}

type sigset_t struct {
	X__val [2]uint32
}

//sys	pselect(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timespec, sigmask *sigset_t) (n int, err error) = SYS_PSELECT6_TIME64

func Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error) {
	var ts *Timespec
	if timeout != nil {
		ts = &Timespec{Sec: int64(timeout.Sec), Nsec: int64(timeout.Usec) * 1000}
	}
	return pselect(nfd, r, w, e, ts, nil)
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
		return utimensat(_AT_FDCWD, path, nil, 0)
	}

	ts := []Timespec{
		NsecToTimespec(TimevalToNsec(tv[0])),
		NsecToTimespec(TimevalToNsec(tv[1])),
	}
	return utimensat(_AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
}

func (r *PtraceRegs) PC() uint64 { return uint64(r.Pc) }

func (r *PtraceRegs) SetPC(pc uint64) { r.Pc = uint32(pc) }

// SetBase points iov at p. Iovec.Base is a 32-bit address on linux/wasm.
func (iov *Iovec) SetBase(p *byte) {
	iov.Base = uint32(uintptr(unsafe.Pointer(p)))
}

func (iov *Iovec) setBase(p *byte) { iov.SetBase(p) }

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint32(length)
}

func (msg *Msghdr) setName(p unsafe.Pointer) { msg.Name = uint32(uintptr(p)) }

func (msg *Msghdr) setIov(iov *Iovec) { msg.Iov = uint32(uintptr(unsafe.Pointer(iov))) }

func (msg *Msghdr) setControl(p *byte) { msg.Control = uint32(uintptr(unsafe.Pointer(p))) }

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = uint32(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = uint32(length)
}

func (p *SockFprog) setFilter(f *SockFilter) { p.Filter = uint32(uintptr(unsafe.Pointer(f))) }

func InotifyInit() (fd int, err error) {
	return InotifyInit1(0)
}

//sys	ppoll(fds *pollFd, nfds int, timeout *Timespec, sigmask *sigset_t) (n int, err error) = SYS_PPOLL_TIME64

func Pause() error {
	_, err := ppoll(nil, 0, nil, nil)
	return err
}
