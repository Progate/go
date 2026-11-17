// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall

import (
	"internal/runtime/syscall/linux"
	"unsafe"
)

// On linux/wasm a vfork child cannot resume the parent's frames: wasm has no
// way to return twice. The kernel instead runs the child by calling back into
// the program. clone(CLONE_VM|CLONE_VFORK) does not return to the caller
// until the child is done; meanwhile the kernel calls the exported function
// __browseros_clone_child_return on the same thread, with the child's state
// (fd table, credentials, working directory) in place. Once the child's
// execve succeeds or it calls exit, the kernel ends the child and those calls
// return 0 to the program, so the child function returns. clone then returns
// the child's pid to the parent.
//
// So the code a vfork child runs is a function here, vforkChild, which the
// parent sets right before calling clone.

var vforkChild func()

//go:wasmexport __browseros_clone_child_return
func cloneChildReturn() {
	if f := vforkChild; f != nil {
		f()
	}
}

// rawVforkSyscall calls clone with CLONE_VFORK. The child runs vforkChild.
//
//go:nosplit
func rawVforkSyscall(trap, a1, a2, a3 uintptr) (r1 uintptr, err Errno) {
	r1, _, e := linux.Syscall6(trap, a1, a2, a3, 0, 0, 0)
	return r1, Errno(e)
}

// childExit ends a vfork child. The kernel returns from exit to the child
// function, which returns in turn.
//
//go:nosplit
func childExit(code uintptr) {
	RawSyscall(SYS_EXIT, code, 0, 0)
}

// cPointers lays out ptrs as a NULL-terminated array of 32-bit addresses
// (char *[] on riscv32).
func cPointers(ptrs []*byte) []uint32 {
	out := make([]uint32, len(ptrs))
	for i, p := range ptrs {
		out[i] = uint32(uintptr(unsafe.Pointer(p)))
	}
	if len(out) == 0 || out[len(out)-1] != 0 {
		out = append(out, 0)
	}
	return out
}

// forkChild is what the parent hands to the vfork child.
type forkChild struct {
	argv0       *byte
	argv, envv  []uint32
	chroot, dir *byte
	sys         *SysProcAttr
	pipe        int
	fd          []int
	nextfd      int
	ppid        uintptr
	rlim        *Rlimit
}

var forkState forkChild

// forkAndExecInChild1 implements the body of forkAndExecInChild up to
// the parent's post-fork path.
//
//go:noinline
//go:norace
//go:nocheckptr
func forkAndExecInChild1(argv0 *byte, argv, envv []*byte, chroot, dir *byte, attr *ProcAttr, sys *SysProcAttr, pipe int) (pid uintptr, pidfd int32, err1 Errno, mapPipe [2]int, locked bool) {
	var flags uintptr
	pidfd = -1

	// A child in a new user namespace is not a vfork child, and wasm cannot
	// copy the running program into a new process.
	if sys.Cloneflags&CLONE_NEWUSER != 0 || sys.Unshareflags&CLONE_NEWUSER != 0 ||
		sys.UidMappings != nil || sys.GidMappings != nil || sys.UseCgroupFD || sys.Cloneflags&CLONE_NEWTIME != 0 {
		err1 = ENOSYS
		return
	}

	c := &forkState
	*c = forkChild{
		argv0:  argv0,
		argv:   cPointers(argv),
		envv:   cPointers(envv),
		chroot: chroot,
		dir:    dir,
		sys:    sys,
		pipe:   pipe,
		rlim:   origRlimitNofile.Load(),
	}

	// Record parent PID so child can test if it has died.
	if sys.Pdeathsig != 0 {
		c.ppid, _ = rawSyscallNoError(SYS_GETPID, 0, 0, 0)
	}

	// Guard against side effects of shuffling fds below.
	// Make sure that nextfd is beyond any currently open files so
	// that we can't run the risk of overwriting any of them.
	c.fd = make([]int, len(attr.Files))
	c.nextfd = len(attr.Files)
	for i, ufd := range attr.Files {
		if c.nextfd < int(ufd) {
			c.nextfd = int(ufd)
		}
		c.fd[i] = int(ufd)
	}
	c.nextfd++

	flags = sys.Cloneflags | CLONE_VFORK | CLONE_VM | uintptr(SIGCHLD)
	if sys.PidFD != nil {
		flags |= CLONE_PIDFD
	}

	// About to call fork.
	// No more allocation or calls of non-assembly functions.
	runtime_BeforeFork()
	locked = true
	vforkChild = runForkChild
	pid, err1 = rawVforkSyscall(SYS_CLONE, flags, 0, uintptr(unsafe.Pointer(&pidfd)))
	vforkChild = nil
	*c = forkChild{}
	return
}

// runForkChild is the vfork child of forkAndExecInChild1: the child part of
// forkAndExecInChild1 on the other ports.
//
//go:norace
//go:nocheckptr
func runForkChild() {
	// Defined in linux/prctl.h starting with Linux 4.3.
	const (
		PR_CAP_AMBIENT       = 0x2f
		PR_CAP_AMBIENT_RAISE = 0x2
	)
	var (
		err1   Errno
		i      int
		caps   caps
		pgrp   int32
		cred   *Credential
		groups uintptr
		pid    uintptr
		lim    Rlimit
	)
	c := &forkState
	sys := c.sys
	fd := c.fd
	nextfd := c.nextfd
	pipe := c.pipe

	// Enable the "keep capabilities" flag to set ambient capabilities later.
	if len(sys.AmbientCaps) > 0 {
		_, _, err1 = RawSyscall6(SYS_PRCTL, PR_SET_KEEPCAPS, 1, 0, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Session ID
	if sys.Setsid {
		_, _, err1 = RawSyscall(SYS_SETSID, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Set process group
	if sys.Setpgid || sys.Foreground {
		// Place child in process group.
		_, _, err1 = RawSyscall(SYS_SETPGID, 0, uintptr(sys.Pgid), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	if sys.Foreground {
		pgrp = int32(sys.Pgid)
		if pgrp == 0 {
			pid, _ = rawSyscallNoError(SYS_GETPID, 0, 0, 0)
			pgrp = int32(pid)
		}

		// Place process group in foreground.
		_, _, err1 = RawSyscall(SYS_IOCTL, uintptr(sys.Ctty), uintptr(TIOCSPGRP), uintptr(unsafe.Pointer(&pgrp)))
		if err1 != 0 {
			goto childerror
		}
	}

	// Restore the signal mask. We do this after TIOCSPGRP to avoid
	// having the kernel send a SIGTTOU signal to the process group.
	runtime_AfterForkInChild()

	// Unshare
	if sys.Unshareflags != 0 {
		_, _, err1 = RawSyscall(SYS_UNSHARE, sys.Unshareflags, 0, 0)
		if err1 != 0 {
			goto childerror
		}
		if sys.Unshareflags&CLONE_NEWNS == CLONE_NEWNS {
			_, _, err1 = RawSyscall6(SYS_MOUNT, uintptr(unsafe.Pointer(&none[0])), uintptr(unsafe.Pointer(&slash[0])), 0, MS_REC|MS_PRIVATE, 0, 0)
			if err1 != 0 {
				goto childerror
			}
		}
	}

	// Chroot
	if c.chroot != nil {
		_, _, err1 = RawSyscall(SYS_CHROOT, uintptr(unsafe.Pointer(c.chroot)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// User and groups
	if cred = sys.Credential; cred != nil {
		groups = uintptr(0)
		if len(cred.Groups) > 0 {
			groups = uintptr(unsafe.Pointer(&cred.Groups[0]))
		}
		if !cred.NoSetGroups {
			_, _, err1 = RawSyscall(_SYS_setgroups, uintptr(len(cred.Groups)), groups, 0)
			if err1 != 0 {
				goto childerror
			}
		}
		_, _, err1 = RawSyscall(sys_SETGID, uintptr(cred.Gid), 0, 0)
		if err1 != 0 {
			goto childerror
		}
		_, _, err1 = RawSyscall(sys_SETUID, uintptr(cred.Uid), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	if len(sys.AmbientCaps) != 0 {
		// Ambient capabilities were added in the 4.3 kernel,
		// so it is safe to always use _LINUX_CAPABILITY_VERSION_3.
		caps.hdr.version = _LINUX_CAPABILITY_VERSION_3

		if _, _, err1 = RawSyscall(SYS_CAPGET, uintptr(unsafe.Pointer(&caps.hdr)), uintptr(unsafe.Pointer(&caps.data[0])), 0); err1 != 0 {
			goto childerror
		}

		for _, cp := range sys.AmbientCaps {
			// Add the c capability to the permitted and inheritable capability mask,
			// otherwise we will not be able to add it to the ambient capability mask.
			idx := int(capToIndex(cp))
			if idx >= len(caps.data) {
				err1 = EINVAL
				goto childerror
			}
			caps.data[idx].permitted |= capToMask(cp)
			caps.data[idx].inheritable |= capToMask(cp)
		}

		if _, _, err1 = RawSyscall(SYS_CAPSET, uintptr(unsafe.Pointer(&caps.hdr)), uintptr(unsafe.Pointer(&caps.data[0])), 0); err1 != 0 {
			goto childerror
		}

		for _, cp := range sys.AmbientCaps {
			_, _, err1 = RawSyscall6(SYS_PRCTL, PR_CAP_AMBIENT, uintptr(PR_CAP_AMBIENT_RAISE), cp, 0, 0, 0)
			if err1 != 0 {
				goto childerror
			}
		}
	}

	// Chdir
	if c.dir != nil {
		_, _, err1 = RawSyscall(SYS_CHDIR, uintptr(unsafe.Pointer(c.dir)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Parent death signal
	if sys.Pdeathsig != 0 {
		_, _, err1 = RawSyscall6(SYS_PRCTL, PR_SET_PDEATHSIG, uintptr(sys.Pdeathsig), 0, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}

		// Signal self if parent is already dead. This might cause a
		// duplicate signal in rare cases, but it won't matter when
		// using SIGKILL.
		pid, _ = rawSyscallNoError(SYS_GETPPID, 0, 0, 0)
		if pid != c.ppid {
			pid, _ = rawSyscallNoError(SYS_GETPID, 0, 0, 0)
			_, _, err1 = RawSyscall(SYS_KILL, pid, uintptr(sys.Pdeathsig), 0)
			if err1 != 0 {
				goto childerror
			}
		}
	}

	// Pass 1: look for fd[i] < i and move those up above len(fd)
	// so that pass 2 won't stomp on an fd it needs later.
	if pipe < nextfd {
		_, _, err1 = RawSyscall(SYS_DUP3, uintptr(pipe), uintptr(nextfd), O_CLOEXEC)
		if err1 != 0 {
			goto childerror
		}
		pipe = nextfd
		nextfd++
	}
	for i = 0; i < len(fd); i++ {
		if fd[i] >= 0 && fd[i] < i {
			if nextfd == pipe { // don't stomp on pipe
				nextfd++
			}
			_, _, err1 = RawSyscall(SYS_DUP3, uintptr(fd[i]), uintptr(nextfd), O_CLOEXEC)
			if err1 != 0 {
				goto childerror
			}
			fd[i] = nextfd
			nextfd++
		}
	}

	// Pass 2: dup fd[i] down onto i.
	for i = 0; i < len(fd); i++ {
		if fd[i] == -1 {
			RawSyscall(SYS_CLOSE, uintptr(i), 0, 0)
			continue
		}
		if fd[i] == i {
			// dup2(i, i) won't clear close-on-exec flag on Linux,
			// probably not elsewhere either.
			_, _, err1 = RawSyscall(fcntl64Syscall, uintptr(fd[i]), F_SETFD, 0)
			if err1 != 0 {
				goto childerror
			}
			continue
		}
		// The new fd is created NOT close-on-exec,
		// which is exactly what we want.
		_, _, err1 = RawSyscall(SYS_DUP3, uintptr(fd[i]), uintptr(i), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// By convention, we don't close-on-exec the fds we are
	// started with, so if len(fd) < 3, close 0, 1, 2 as needed.
	// Programs that know they inherit fds >= 3 will need
	// to set them close-on-exec.
	for i = len(fd); i < 3; i++ {
		RawSyscall(SYS_CLOSE, uintptr(i), 0, 0)
	}

	// Detach fd 0 from tty
	if sys.Noctty {
		_, _, err1 = RawSyscall(SYS_IOCTL, 0, uintptr(TIOCNOTTY), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Set the controlling TTY to Ctty
	if sys.Setctty {
		_, _, err1 = RawSyscall(SYS_IOCTL, uintptr(sys.Ctty), uintptr(TIOCSCTTY), 1)
		if err1 != 0 {
			goto childerror
		}
	}

	// Restore original rlimit.
	if c.rlim != nil {
		_, _, err1 = RawSyscall6(SYS_PRLIMIT64, 0, RLIMIT_NOFILE, 0, uintptr(unsafe.Pointer(&lim)), 0, 0)
		if err1 != 0 || (lim.Cur == c.rlim.Max-1 && lim.Max == c.rlim.Max) {
			RawSyscall6(SYS_PRLIMIT64, 0, RLIMIT_NOFILE, uintptr(unsafe.Pointer(c.rlim)), 0, 0, 0)
		}
	}

	// Enable tracing if requested.
	if sys.Ptrace {
		_, _, err1 = RawSyscall(SYS_PTRACE, uintptr(PTRACE_TRACEME), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Time to exec. A successful execve ends the child and returns 0.
	_, _, err1 = RawSyscall(SYS_EXECVE,
		uintptr(unsafe.Pointer(c.argv0)),
		uintptr(unsafe.Pointer(&c.argv[0])),
		uintptr(unsafe.Pointer(&c.envv[0])))
	if err1 == 0 {
		return
	}

childerror:
	// send error code on pipe
	RawSyscall(SYS_WRITE, uintptr(pipe), uintptr(unsafe.Pointer(&err1)), unsafe.Sizeof(err1))
	childExit(253)
}

// doCheckClonePidfd implements the actual clone call of os_checkClonePidfd.
// Its vfork child exits at once.
//
//go:noinline
func doCheckClonePidfd(pidfd *int32) (pid uintptr, errno Errno) {
	flags := uintptr(CLONE_VFORK | CLONE_VM | CLONE_PIDFD)
	vforkChild = exitCheckChild
	pid, errno = rawVforkSyscall(SYS_CLONE, flags, 0, uintptr(unsafe.Pointer(pidfd)))
	vforkChild = nil
	return
}

func exitCheckChild() {
	RawSyscall(SYS_EXIT_GROUP, 0, 0, 0)
}
