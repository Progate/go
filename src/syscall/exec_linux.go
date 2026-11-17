// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package syscall

import (
	errpkg "errors"
	"internal/strconv"
	"unsafe"
)

// Linux unshare/clone/clone2/clone3 flags, architecture-independent,
// copied from linux/sched.h.
const (
	CLONE_VM             = 0x00000100 // set if VM shared between processes
	CLONE_FS             = 0x00000200 // set if fs info shared between processes
	CLONE_FILES          = 0x00000400 // set if open files shared between processes
	CLONE_SIGHAND        = 0x00000800 // set if signal handlers and blocked signals shared
	CLONE_PIDFD          = 0x00001000 // set if a pidfd should be placed in parent
	CLONE_PTRACE         = 0x00002000 // set if we want to let tracing continue on the child too
	CLONE_VFORK          = 0x00004000 // set if the parent wants the child to wake it up on mm_release
	CLONE_PARENT         = 0x00008000 // set if we want to have the same parent as the cloner
	CLONE_THREAD         = 0x00010000 // Same thread group?
	CLONE_NEWNS          = 0x00020000 // New mount namespace group
	CLONE_SYSVSEM        = 0x00040000 // share system V SEM_UNDO semantics
	CLONE_SETTLS         = 0x00080000 // create a new TLS for the child
	CLONE_PARENT_SETTID  = 0x00100000 // set the TID in the parent
	CLONE_CHILD_CLEARTID = 0x00200000 // clear the TID in the child
	CLONE_DETACHED       = 0x00400000 // Unused, ignored
	CLONE_UNTRACED       = 0x00800000 // set if the tracing process can't force CLONE_PTRACE on this clone
	CLONE_CHILD_SETTID   = 0x01000000 // set the TID in the child
	CLONE_NEWCGROUP      = 0x02000000 // New cgroup namespace
	CLONE_NEWUTS         = 0x04000000 // New utsname namespace
	CLONE_NEWIPC         = 0x08000000 // New ipc namespace
	CLONE_NEWUSER        = 0x10000000 // New user namespace
	CLONE_NEWPID         = 0x20000000 // New pid namespace
	CLONE_NEWNET         = 0x40000000 // New network namespace
	CLONE_IO             = 0x80000000 // Clone io context

	// Flags for the clone3() syscall.

	CLONE_CLEAR_SIGHAND = 0x100000000 // Clear any signal handler and reset to SIG_DFL.
	CLONE_INTO_CGROUP   = 0x200000000 // Clone into a specific cgroup given the right permissions.

	// Cloning flags intersect with CSIGNAL so can be used with unshare and clone3
	// syscalls only:

	CLONE_NEWTIME = 0x00000080 // New time namespace
)

// SysProcIDMap holds Container ID to Host ID mappings used for User Namespaces in Linux.
// See user_namespaces(7).
//
// Note that User Namespaces are not available on a number of popular Linux
// versions (due to security issues), or are available but subject to AppArmor
// restrictions like in Ubuntu 24.04.
type SysProcIDMap struct {
	ContainerID int // Container ID.
	HostID      int // Host ID.
	Size        int // Size.
}

type SysProcAttr struct {
	Chroot     string      // Chroot.
	Credential *Credential // Credential.
	// Ptrace tells the child to call ptrace(PTRACE_TRACEME).
	// Call runtime.LockOSThread before starting a process with this set,
	// and don't call UnlockOSThread until done with PtraceSyscall calls.
	Ptrace bool
	Setsid bool // Create session.
	// Setpgid sets the process group ID of the child to Pgid,
	// or, if Pgid == 0, to the new child's process ID.
	Setpgid bool
	// Setctty sets the controlling terminal of the child to
	// file descriptor Ctty. Ctty must be a descriptor number
	// in the child process: an index into ProcAttr.Files.
	// This is only meaningful if Setsid is true.
	Setctty bool
	Noctty  bool // Detach fd 0 from controlling terminal.
	Ctty    int  // Controlling TTY fd.
	// Foreground places the child process group in the foreground.
	// This implies Setpgid. The Ctty field must be set to
	// the descriptor of the controlling TTY.
	// Unlike Setctty, in this case Ctty must be a descriptor
	// number in the parent process.
	Foreground bool
	Pgid       int // Child's process group ID if Setpgid.
	// Pdeathsig, if non-zero, is a signal that the kernel will send to
	// the child process when the creating thread dies. Note that the signal
	// is sent on thread termination, which may happen before process termination.
	// There are more details at https://go.dev/issue/27505.
	Pdeathsig    Signal
	Cloneflags   uintptr        // Flags for clone calls.
	Unshareflags uintptr        // Flags for unshare calls.
	UidMappings  []SysProcIDMap // User ID mappings for user namespaces.
	GidMappings  []SysProcIDMap // Group ID mappings for user namespaces.
	// GidMappingsEnableSetgroups enabling setgroups syscall.
	// If false, then setgroups syscall will be disabled for the child process.
	// This parameter is no-op if GidMappings == nil. Otherwise for unprivileged
	// users this should be set to false for mappings work.
	GidMappingsEnableSetgroups bool
	AmbientCaps                []uintptr // Ambient capabilities.
	UseCgroupFD                bool      // Whether to make use of the CgroupFD field.
	CgroupFD                   int       // File descriptor of a cgroup to put the new process into.
	// PidFD, if not nil, is used to store the pidfd of a child, if the
	// functionality is supported by the kernel, or -1. Note *PidFD is
	// changed only if the process starts successfully.
	PidFD *int
}

var (
	none  = [...]byte{'n', 'o', 'n', 'e', 0}
	slash = [...]byte{'/', 0}

	forceClone3 = false // Used by unit tests only.
)

// Implemented in runtime package.
func runtime_BeforeFork()
func runtime_AfterFork()
func runtime_AfterForkInChild()

// Fork, dup fd onto 0..len(fd), and exec(argv0, argvv, envv) in child.
// If a dup or exec fails, write the errno error to pipe.
// (Pipe is close-on-exec so if exec succeeds, it will be closed.)
// In the child, this function must not acquire any locks, because
// they might have been locked at the time of the fork. This means
// no rescheduling, no malloc calls, and no new stack segments.
// For the same reason compiler does not race instrument it.
// The calls to RawSyscall are okay because they are assembly
// functions that do not grow the stack.
//
//go:norace
func forkAndExecInChild(argv0 *byte, argv, envv []*byte, chroot, dir *byte, attr *ProcAttr, sys *SysProcAttr, pipe int) (pid int, err Errno) {
	// Set up and fork. This returns immediately in the parent or
	// if there's an error.
	upid, pidfd, err, mapPipe, locked := forkAndExecInChild1(argv0, argv, envv, chroot, dir, attr, sys, pipe)
	if locked {
		runtime_AfterFork()
	}
	if err != 0 {
		return 0, err
	}

	// parent; return PID
	pid = int(upid)
	if sys.PidFD != nil {
		*sys.PidFD = int(pidfd)
	}

	if sys.UidMappings != nil || sys.GidMappings != nil {
		Close(mapPipe[0])
		var err2 Errno
		// uid/gid mappings will be written after fork and unshare(2) for user
		// namespaces.
		if sys.Unshareflags&CLONE_NEWUSER == 0 {
			if err := writeUidGidMappings(pid, sys); err != nil {
				err2 = err.(Errno)
			}
		}
		RawSyscall(SYS_WRITE, uintptr(mapPipe[1]), uintptr(unsafe.Pointer(&err2)), unsafe.Sizeof(err2))
		Close(mapPipe[1])
	}

	return pid, 0
}

const _LINUX_CAPABILITY_VERSION_3 = 0x20080522

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}
type caps struct {
	hdr  capHeader
	data [2]capData
}

// See CAP_TO_INDEX in linux/capability.h:
func capToIndex(cap uintptr) uintptr { return cap >> 5 }

// See CAP_TO_MASK in linux/capability.h:
func capToMask(cap uintptr) uint32 { return 1 << uint(cap&31) }

// cloneArgs holds arguments for clone3 Linux syscall.
type cloneArgs struct {
	flags      uint64 // Flags bit mask
	pidFD      uint64 // Where to store PID file descriptor (int *)
	childTID   uint64 // Where to store child TID, in child's memory (pid_t *)
	parentTID  uint64 // Where to store child TID, in parent's memory (pid_t *)
	exitSignal uint64 // Signal to deliver to parent on child termination
	stack      uint64 // Pointer to lowest byte of stack
	stackSize  uint64 // Size of stack
	tls        uint64 // Location of new TLS
	setTID     uint64 // Pointer to a pid_t array (since Linux 5.5)
	setTIDSize uint64 // Number of elements in set_tid (since Linux 5.5)
	cgroup     uint64 // File descriptor for target cgroup of child (since Linux 5.7)
}

func formatIDMappings(idMap []SysProcIDMap) []byte {
	var data []byte
	for _, im := range idMap {
		data = append(data, strconv.Itoa(im.ContainerID)+" "+strconv.Itoa(im.HostID)+" "+strconv.Itoa(im.Size)+"\n"...)
	}
	return data
}

// writeIDMappings writes the user namespace User ID or Group ID mappings to the specified path.
func writeIDMappings(path string, idMap []SysProcIDMap) error {
	fd, err := Open(path, O_RDWR, 0)
	if err != nil {
		return err
	}

	if _, err := Write(fd, formatIDMappings(idMap)); err != nil {
		Close(fd)
		return err
	}

	if err := Close(fd); err != nil {
		return err
	}

	return nil
}

// writeSetgroups writes to /proc/PID/setgroups "deny" if enable is false
// and "allow" if enable is true.
// This is needed since kernel 3.19, because you can't write gid_map without
// disabling setgroups() system call.
func writeSetgroups(pid int, enable bool) error {
	sgf := "/proc/" + strconv.Itoa(pid) + "/setgroups"
	fd, err := Open(sgf, O_RDWR, 0)
	if err != nil {
		return err
	}

	var data []byte
	if enable {
		data = []byte("allow")
	} else {
		data = []byte("deny")
	}

	if _, err := Write(fd, data); err != nil {
		Close(fd)
		return err
	}

	return Close(fd)
}

// writeUidGidMappings writes User ID and Group ID mappings for user namespaces
// for a process and it is called from the parent process.
func writeUidGidMappings(pid int, sys *SysProcAttr) error {
	if sys.UidMappings != nil {
		uidf := "/proc/" + strconv.Itoa(pid) + "/uid_map"
		if err := writeIDMappings(uidf, sys.UidMappings); err != nil {
			return err
		}
	}

	if sys.GidMappings != nil {
		// If the kernel is too old to support /proc/PID/setgroups, writeSetGroups will return ENOENT; this is OK.
		if err := writeSetgroups(pid, sys.GidMappingsEnableSetgroups); err != nil && err != ENOENT {
			return err
		}
		gidf := "/proc/" + strconv.Itoa(pid) + "/gid_map"
		if err := writeIDMappings(gidf, sys.GidMappings); err != nil {
			return err
		}
	}

	return nil
}

// forkAndExecFailureCleanup cleans up after an exec failure.
func forkAndExecFailureCleanup(attr *ProcAttr, sys *SysProcAttr) {
	if sys.PidFD != nil && *sys.PidFD != -1 {
		Close(*sys.PidFD)
		*sys.PidFD = -1
	}
}

// checkClonePidfd verifies that clone(CLONE_PIDFD) works by actually doing a
// clone.
//
//go:linkname os_checkClonePidfd os.checkClonePidfd
func os_checkClonePidfd() error {
	pidfd := int32(-1)
	pid, errno := doCheckClonePidfd(&pidfd)
	if errno != 0 {
		return errno
	}

	if pidfd == -1 {
		// Bad: CLONE_PIDFD failed to provide a pidfd. Reap the process
		// before returning.

		var err error
		for {
			var status WaitStatus
			// WCLONE is an untyped constant that sets bit 31, so
			// it cannot convert directly to int on 32-bit
			// GOARCHes. We must convert through another type
			// first.
			flags := uint(WCLONE)
			_, err = Wait4(int(pid), &status, int(flags), nil)
			if err != EINTR {
				break
			}
		}
		if err != nil {
			return err
		}

		return errpkg.New("clone(CLONE_PIDFD) failed to return pidfd")
	}

	// Good: CLONE_PIDFD provided a pidfd. Reap the process and close the
	// pidfd.
	defer Close(int(pidfd))

	// TODO(roland): this is necessary to prevent valgrind from complaining
	// about passing 0x0 to waitid, which is doesn't like. This is clearly not
	// ideal. The structures are copied (mostly) verbatim from syscall/unix,
	// which we obviously cannot import because of an import loop.

	const is64bit = ^uint(0) >> 63 // 0 for 32-bit hosts, 1 for 64-bit ones.
	type sigInfo struct {
		Signo int32
		_     struct {
			Errno int32
			Code  int32
		} // Two int32 fields, swapped on MIPS.
		_ [is64bit]int32 // Extra padding for 64-bit hosts only.

		// End of common part. Beginning of signal-specific part.

		Pid    int32
		Uid    uint32
		Status int32

		// Pad to 128 bytes.
		_ [128 - (6+is64bit)*4]byte
	}

	for {
		const _P_PIDFD = 3
		var info sigInfo
		_, _, errno = Syscall6(SYS_WAITID, _P_PIDFD, uintptr(pidfd), uintptr(unsafe.Pointer(&info)), WEXITED|WCLONE, 0, 0)
		if errno != EINTR {
			break
		}
	}
	if errno != 0 {
		return errno
	}

	return nil
}
