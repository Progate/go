// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package poll

import "syscall"

func newIovecWithBase(base *byte) syscall.Iovec {
	var iov syscall.Iovec
	iov.SetBase(base)
	return iov
}
