// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !wasm

package unix

import "unsafe"

// An ifreqData is an Ifreq which carries pointer data. To produce an ifreqData,
// use the Ifreq.withData method.
type ifreqData struct {
	name [IFNAMSIZ]byte
	// A type separate from ifreq is required in order to comply with the
	// unsafe.Pointer rules since the "pointer-ness" of data would not be
	// preserved if it were cast into the byte array of a raw ifreq.
	data unsafe.Pointer
	// Pad to the same size as ifreq.
	_ [len(ifreq{}.Ifru) - SizeofPtr]byte
}

// withData produces an ifreqData with the pointer p set for ioctls which require
// arbitrary pointer data.
func (ifr Ifreq) withData(p unsafe.Pointer) ifreqData {
	return ifreqData{
		name: ifr.raw.Ifrn,
		data: p,
	}
}
