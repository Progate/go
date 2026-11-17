// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !wasm

package syscall

import (
	"runtime"
	"unsafe"
)

// forkAndExecInChild1 implements the body of forkAndExecInChild up to
// the parent's post-fork path. This is a separate function so we can
// separate the child's and parent's stack frames if we're using
// vfork.
//
// This is go:noinline because the point is to keep the stack frames
// of this and forkAndExecInChild separate.
//
//go:noinline
//go:norace
//go:nocheckptr
func forkAndExecInChild1(argv0 *byte, argv, envv []*byte, chroot, dir *byte, attr *ProcAttr, sys *SysProcAttr, pipe int) (pid uintptr, pidfd int32, err1 Errno, mapPipe [2]int, locked bool) {
	// Defined in linux/prctl.h starting with Linux 4.3.
	const (
		PR_CAP_AMBIENT       = 0x2f
		PR_CAP_AMBIENT_RAISE = 0x2
	)

	// vfork requires that the child not touch any of the parent's
	// active stack frames. Hence, the child does all post-fork
	// processing in this stack frame and never returns, while the
	// parent returns immediately from this frame and does all
	// post-fork processing in the outer frame.
	//
	// Declare all variables at top in case any
	// declarations require heap allocation (e.g., err2).
	// ":=" should not be used to declare any variable after
	// the call to runtime_BeforeFork.
	//
	// NOTE(bcmills): The allocation behavior described in the above comment
	// seems to lack a corresponding test, and it may be rendered invalid
	// by an otherwise-correct change in the compiler.
	var (
		err2                      Errno
		nextfd                    int
		i                         int
		caps                      caps
		fd1, flags, ppid          uintptr
		puid, psetgroups, pgid    []byte
		uidmap, setgroups, gidmap []byte
		clone3                    *cloneArgs
		pgrp                      int32
		dirfd                     int
		cred                      *Credential
		ngroups, groups           uintptr
		c                         uintptr
		rlim                      *Rlimit
		lim                       Rlimit
	)
	pidfd = -1

	rlim = origRlimitNofile.Load()

	if sys.UidMappings != nil {
		puid = []byte("/proc/self/uid_map\000")
		uidmap = formatIDMappings(sys.UidMappings)
	}

	if sys.GidMappings != nil {
		psetgroups = []byte("/proc/self/setgroups\000")
		pgid = []byte("/proc/self/gid_map\000")

		if sys.GidMappingsEnableSetgroups {
			setgroups = []byte("allow\000")
		} else {
			setgroups = []byte("deny\000")
		}
		gidmap = formatIDMappings(sys.GidMappings)
	}

	// Record parent PID so child can test if it has died.
	if sys.Pdeathsig != 0 {
		ppid, _ = rawSyscallNoError(SYS_GETPID, 0, 0, 0)
	}

	// Guard against side effects of shuffling fds below.
	// Make sure that nextfd is beyond any currently open files so
	// that we can't run the risk of overwriting any of them.
	fd := make([]int, len(attr.Files))
	nextfd = len(attr.Files)
	for i, ufd := range attr.Files {
		if nextfd < int(ufd) {
			nextfd = int(ufd)
		}
		fd[i] = int(ufd)
	}
	nextfd++

	// Allocate another pipe for parent to child communication for
	// synchronizing writing of User ID/Group ID mappings.
	if sys.UidMappings != nil || sys.GidMappings != nil {
		if err := forkExecPipe(mapPipe[:]); err != nil {
			err1 = err.(Errno)
			return
		}
	}

	flags = sys.Cloneflags
	if sys.Cloneflags&CLONE_NEWUSER == 0 && sys.Unshareflags&CLONE_NEWUSER == 0 {
		flags |= CLONE_VFORK | CLONE_VM
	}
	if sys.PidFD != nil {
		flags |= CLONE_PIDFD
	}
	// Whether to use clone3.
	if sys.UseCgroupFD || flags&CLONE_NEWTIME != 0 || forceClone3 {
		clone3 = &cloneArgs{
			flags:      uint64(flags),
			exitSignal: uint64(SIGCHLD),
		}
		if sys.UseCgroupFD {
			clone3.flags |= CLONE_INTO_CGROUP
			clone3.cgroup = uint64(sys.CgroupFD)
		}
		if sys.PidFD != nil {
			clone3.pidFD = uint64(uintptr(unsafe.Pointer(&pidfd)))
		}
	}

	// About to call fork.
	// No more allocation or calls of non-assembly functions.
	runtime_BeforeFork()
	locked = true
	if clone3 != nil {
		pid, err1 = rawVforkSyscall(_SYS_clone3, uintptr(unsafe.Pointer(clone3)), unsafe.Sizeof(*clone3), 0)
	} else {
		// N.B. Keep in sync with doCheckClonePidfd.
		flags |= uintptr(SIGCHLD)
		if runtime.GOARCH == "s390x" {
			// On Linux/s390, the first two arguments of clone(2) are swapped.
			pid, err1 = rawVforkSyscall(SYS_CLONE, 0, flags, uintptr(unsafe.Pointer(&pidfd)))
		} else {
			pid, err1 = rawVforkSyscall(SYS_CLONE, flags, 0, uintptr(unsafe.Pointer(&pidfd)))
		}
	}
	if err1 != 0 || pid != 0 {
		// If we're in the parent, we must return immediately
		// so we're not in the same stack frame as the child.
		// This can at most use the return PC, which the child
		// will not modify, and the results of
		// rawVforkSyscall, which must have been written after
		// the child was replaced.
		return
	}

	// Fork succeeded, now in child.

	// Enable the "keep capabilities" flag to set ambient capabilities later.
	if len(sys.AmbientCaps) > 0 {
		_, _, err1 = RawSyscall6(SYS_PRCTL, PR_SET_KEEPCAPS, 1, 0, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Wait for User ID/Group ID mappings to be written.
	if sys.UidMappings != nil || sys.GidMappings != nil {
		if _, _, err1 = RawSyscall(SYS_CLOSE, uintptr(mapPipe[1]), 0, 0); err1 != 0 {
			goto childerror
		}
		c, _, err1 = RawSyscall(SYS_READ, uintptr(mapPipe[0]), uintptr(unsafe.Pointer(&err2)), unsafe.Sizeof(err2))
		if err1 != 0 {
			goto childerror
		}
		if c != unsafe.Sizeof(err2) {
			err1 = EINVAL
			goto childerror
		}
		if err2 != 0 {
			err1 = err2
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

		if sys.Unshareflags&CLONE_NEWUSER != 0 && sys.GidMappings != nil {
			dirfd = int(_AT_FDCWD)
			if fd1, _, err1 = RawSyscall6(SYS_OPENAT, uintptr(dirfd), uintptr(unsafe.Pointer(&psetgroups[0])), uintptr(O_WRONLY), 0, 0, 0); err1 != 0 {
				goto childerror
			}
			_, _, err1 = RawSyscall(SYS_WRITE, fd1, uintptr(unsafe.Pointer(&setgroups[0])), uintptr(len(setgroups)))
			if err1 != 0 {
				goto childerror
			}
			if _, _, err1 = RawSyscall(SYS_CLOSE, fd1, 0, 0); err1 != 0 {
				goto childerror
			}

			if fd1, _, err1 = RawSyscall6(SYS_OPENAT, uintptr(dirfd), uintptr(unsafe.Pointer(&pgid[0])), uintptr(O_WRONLY), 0, 0, 0); err1 != 0 {
				goto childerror
			}
			_, _, err1 = RawSyscall(SYS_WRITE, fd1, uintptr(unsafe.Pointer(&gidmap[0])), uintptr(len(gidmap)))
			if err1 != 0 {
				goto childerror
			}
			if _, _, err1 = RawSyscall(SYS_CLOSE, fd1, 0, 0); err1 != 0 {
				goto childerror
			}
		}

		if sys.Unshareflags&CLONE_NEWUSER != 0 && sys.UidMappings != nil {
			dirfd = int(_AT_FDCWD)
			if fd1, _, err1 = RawSyscall6(SYS_OPENAT, uintptr(dirfd), uintptr(unsafe.Pointer(&puid[0])), uintptr(O_WRONLY), 0, 0, 0); err1 != 0 {
				goto childerror
			}
			_, _, err1 = RawSyscall(SYS_WRITE, fd1, uintptr(unsafe.Pointer(&uidmap[0])), uintptr(len(uidmap)))
			if err1 != 0 {
				goto childerror
			}
			if _, _, err1 = RawSyscall(SYS_CLOSE, fd1, 0, 0); err1 != 0 {
				goto childerror
			}
		}

		// The unshare system call in Linux doesn't unshare mount points
		// mounted with --shared. Systemd mounts / with --shared. For a
		// long discussion of the pros and cons of this see debian bug 739593.
		// The Go model of unsharing is more like Plan 9, where you ask
		// to unshare and the namespaces are unconditionally unshared.
		// To make this model work we must further mark / as MS_PRIVATE.
		// This is what the standard unshare command does.
		if sys.Unshareflags&CLONE_NEWNS == CLONE_NEWNS {
			_, _, err1 = RawSyscall6(SYS_MOUNT, uintptr(unsafe.Pointer(&none[0])), uintptr(unsafe.Pointer(&slash[0])), 0, MS_REC|MS_PRIVATE, 0, 0)
			if err1 != 0 {
				goto childerror
			}
		}
	}

	// Chroot
	if chroot != nil {
		_, _, err1 = RawSyscall(SYS_CHROOT, uintptr(unsafe.Pointer(chroot)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// User and groups
	if cred = sys.Credential; cred != nil {
		ngroups = uintptr(len(cred.Groups))
		groups = uintptr(0)
		if ngroups > 0 {
			groups = uintptr(unsafe.Pointer(&cred.Groups[0]))
		}
		if !(sys.GidMappings != nil && !sys.GidMappingsEnableSetgroups && ngroups == 0) && !cred.NoSetGroups {
			_, _, err1 = RawSyscall(_SYS_setgroups, ngroups, groups, 0)
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

		for _, c = range sys.AmbientCaps {
			// Add the c capability to the permitted and inheritable capability mask,
			// otherwise we will not be able to add it to the ambient capability mask.
			idx := int(capToIndex(c))
			if idx >= len(caps.data) {
				err1 = EINVAL
				goto childerror
			}
			caps.data[idx].permitted |= capToMask(c)
			caps.data[idx].inheritable |= capToMask(c)
		}

		if _, _, err1 = RawSyscall(SYS_CAPSET, uintptr(unsafe.Pointer(&caps.hdr)), uintptr(unsafe.Pointer(&caps.data[0])), 0); err1 != 0 {
			goto childerror
		}

		for _, c = range sys.AmbientCaps {
			_, _, err1 = RawSyscall6(SYS_PRCTL, PR_CAP_AMBIENT, uintptr(PR_CAP_AMBIENT_RAISE), c, 0, 0, 0)
			if err1 != 0 {
				goto childerror
			}
		}
	}

	// Chdir
	if dir != nil {
		_, _, err1 = RawSyscall(SYS_CHDIR, uintptr(unsafe.Pointer(dir)), 0, 0)
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
		if pid != ppid {
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
	if rlim != nil {
		// Some other process may have changed our rlimit by
		// calling prlimit. We can check for that case because
		// our current rlimit will not be the value we set when
		// caching the rlimit in the init function in rlimit.go.
		//
		// Note that this test is imperfect, since it won't catch
		// the case in which some other process used prlimit to
		// set our rlimits to max-1/max. In that case we will fall
		// back to the original cur/max when starting the child.
		// We hope that setting to max-1/max is unlikely.
		_, _, err1 = RawSyscall6(SYS_PRLIMIT64, 0, RLIMIT_NOFILE, 0, uintptr(unsafe.Pointer(&lim)), 0, 0)
		if err1 != 0 || (lim.Cur == rlim.Max-1 && lim.Max == rlim.Max) {
			RawSyscall6(SYS_PRLIMIT64, 0, RLIMIT_NOFILE, uintptr(unsafe.Pointer(rlim)), 0, 0, 0)
		}
	}

	// Enable tracing if requested.
	// Do this right before exec so that we don't unnecessarily trace the runtime
	// setting up after the fork. See issue #21428.
	if sys.Ptrace {
		_, _, err1 = RawSyscall(SYS_PTRACE, uintptr(PTRACE_TRACEME), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Time to exec.
	_, _, err1 = RawSyscall(SYS_EXECVE,
		uintptr(unsafe.Pointer(argv0)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envv[0])))

childerror:
	// send error code on pipe
	RawSyscall(SYS_WRITE, uintptr(pipe), uintptr(unsafe.Pointer(&err1)), unsafe.Sizeof(err1))
	for {
		RawSyscall(SYS_EXIT, 253, 0, 0)
	}
}

// doCheckClonePidfd implements the actual clone call of os_checkClonePidfd and
// child execution. This is a separate function so we can separate the child's
// and parent's stack frames if we're using vfork.
//
// This is go:noinline because the point is to keep the stack frames of this
// and os_checkClonePidfd separate.
//
//go:noinline
func doCheckClonePidfd(pidfd *int32) (pid uintptr, errno Errno) {
	flags := uintptr(CLONE_VFORK | CLONE_VM | CLONE_PIDFD)
	if runtime.GOARCH == "s390x" {
		// On Linux/s390, the first two arguments of clone(2) are swapped.
		pid, errno = rawVforkSyscall(SYS_CLONE, 0, flags, uintptr(unsafe.Pointer(pidfd)))
	} else {
		pid, errno = rawVforkSyscall(SYS_CLONE, flags, 0, uintptr(unsafe.Pointer(pidfd)))
	}
	if errno != 0 || pid != 0 {
		// If we're in the parent, we must return immediately
		// so we're not in the same stack frame as the child.
		// This can at most use the return PC, which the child
		// will not modify, and the results of
		// rawVforkSyscall, which must have been written after
		// the child was replaced.
		return
	}

	for {
		RawSyscall(SYS_EXIT_GROUP, 0, 0, 0)
	}
}
