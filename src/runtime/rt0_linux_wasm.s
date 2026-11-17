// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "go_asm.h"
#include "textflag.h"

// _rt0_wasm_linux is the program entry point, exported as _start.
//
// As on any Linux, execve(2) leaves argc, argv, envp and the auxiliary vector
// at the top of the initial stack and points the stack pointer at argc. On
// wasm the stack pointer is the SP global, which the linker exports as
// __stack_pointer and initializes to the top of runtime·startStack. The
// layout is riscv32's: 32-bit words and pointers.
//
// The Go runtime then runs on its own m0 stack, leaving the block in place for
// goenvs and sysauxv to read.
TEXT _rt0_wasm_linux(SB),NOSPLIT,$0
	MOVD SP, runtime·startBlock(SB)
	MOVD $runtime·wasmStack+(m0Stack__size-16)(SB), SP

	I32Const $0 // entry PC_B
	Call runtime·rt0_go(SB)
	Drop
	Call wasm_pc_f_loop(SB)

	Return
