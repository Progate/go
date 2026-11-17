// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

// Implemented in src/runtime/sys_wasm.s
func growMemory(pages int32) int32
func currentMemory() int32
