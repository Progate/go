// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build dragonfly || freebsd || netbsd

package unix

// sysFcntl is the fcntl system call that fcntl64Syscall starts from (see
// fcntl.go).
const sysFcntl = SYS_FCNTL
