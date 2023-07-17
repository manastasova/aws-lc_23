// This file is generated from a similarly-named Perl script in the BoringSSL
// source tree. Do not edit by hand.

#if !defined(__has_feature)
#define __has_feature(x) 0
#endif
#if __has_feature(memory_sanitizer) && !defined(OPENSSL_NO_ASM)
#define OPENSSL_NO_ASM
#endif

#if !defined(OPENSSL_NO_ASM) && defined(__AARCH64EL__) && defined(__ELF__)
#if defined(BORINGSSL_PREFIX)
#include <boringssl_prefix_symbols_asm.h>
#endif

#define SEP ;
#include <openssl/arm_arch.h>
.type	round_constants, %object
round_constants:
.quad	0x0000000000000001
.quad	0x0000000000000001
.quad	0x0000000000008082
.quad	0x0000000000008082
.quad	0x800000000000808a
.quad	0x800000000000808a
.quad	0x8000000080008000
.quad	0x8000000080008000
.quad	0x000000000000808b
.quad	0x000000000000808b
.quad	0x0000000080000001
.quad	0x0000000080000001
.quad	0x8000000080008081
.quad	0x8000000080008081
.quad	0x8000000000008009
.quad	0x8000000000008009
.quad	0x000000000000008a
.quad	0x000000000000008a
.quad	0x0000000000000088
.quad	0x0000000000000088
.quad	0x0000000080008009
.quad	0x0000000080008009
.quad	0x000000008000000a
.quad	0x000000008000000a
.quad	0x000000008000808b
.quad	0x000000008000808b
.quad	0x800000000000008b
.quad	0x800000000000008b
.quad	0x8000000000008089
.quad	0x8000000000008089
.quad	0x8000000000008003
.quad	0x8000000000008003
.quad	0x8000000000008002
.quad	0x8000000000008002
.quad	0x8000000000000080
.quad	0x8000000000000080
.quad	0x000000000000800a
.quad	0x000000000000800a
.quad	0x800000008000000a
.quad	0x800000008000000a
.quad	0x8000000080008081
.quad	0x8000000080008081
.quad	0x8000000000008080
.quad	0x8000000000008080
.quad	0x0000000080000001
.quad	0x0000000080000001
.quad	0x8000000080008008
.quad	0x8000000080008008
.size	round_constants, .-round_constants




	/*	Mapping of Kecck-f1600 state to vector registers
	*	at the beginning and end of each round. */

.macro	load_constant_ptr
	adr	x1, round_constants
.endm



.macro	load_input
	ldp	q0, q1, [x0, #(2*8*0)]
	ldp	q2, q3, [x0, #(2*8*2)]
	ldp	q4, q5, [x0, #(2*8*4)]
	ldp	q6, q7, [x0, #(2*8*6)]
	ldp	q8, q9, [x0, #(2*8*8)]
	ldp	q10, q11, [x0, #(2*8*10)]
	ldp	q12, q13, [x0, #(2*8*12)]
	ldp	q14, q15, [x0, #(2*8*14)]
	ldp	q16, q17, [x0, #(2*8*16)]
	ldp	q18, q19, [x0, #(2*8*18)]
	ldp	q20, q21, [x0, #(2*8*20)]
	ldp	q22, q23, [x0, #(2*8*22)]
	ldr	q24, [x0, #(2*8*24)]
.endm

.macro	store_input
	str	q0, [x0, #(2*8*0)]
	str	q1, [x0, #(2*8*1)]
	str	q2, [x0, #(2*8*2)]
	str	q3, [x0, #(2*8*3)]
	str	q4, [x0, #(2*8*4)]
	str	q5, [x0, #(2*8*5)]
	str	q6, [x0, #(2*8*6)]
	str	q7, [x0, #(2*8*7)]
	str	q8, [x0, #(2*8*8)]
	str	q9, [x0, #(2*8*9)]
	str	q10, [x0, #(2*8*10)]
	str	q11, [x0, #(2*8*11)]
	str	q12, [x0, #(2*8*12)]
	str	q13, [x0, #(2*8*13)]
	str	q14, [x0, #(2*8*14)]
	str	q15, [x0, #(2*8*15)]
	str	q16, [x0, #(2*8*16)]
	str	q17, [x0, #(2*8*17)]
	str	q18, [x0, #(2*8*18)]
	str	q19, [x0, #(2*8*19)]
	str	q20, [x0, #(2*8*20)]
	str	q21, [x0, #(2*8*21)]
	str	q22, [x0, #(2*8*22)]
	str	q23, [x0, #(2*8*23)]
	str	q24, [x0, #(2*8*24)]
.endm

#define STACK_SIZE (16*4 + 16*34)
#define STACK_BASE_VREGS 0
#define STACK_BASE_TMP   16*4

#define Aga_offset 0
#define E0_offset  1
#define E1_offset  2
#define E2_offset  3
#define E3_offset  4
#define E4_offset  5
#define Ame_offset  7
#define Agi_offset  8
#define Aka_offset  9
#define Abo_offset  10
#define Amo_offset  11
#define Ami_offset  12
#define Ake_offset  13
#define Agu_offset  14
#define Asi_offset  15
#define Aku_offset  16
#define Asa_offset  17
#define Abu_offset  18
#define Asu_offset  19
#define Ase_offset  20
//#define Aga_offset  21
#define Age_offset  22
#define vBgo_offset 23
#define vBke_offset 24
#define vBgi_offset 25
#define vBga_offset 26
#define vBbo_offset 27
#define vBmo_offset 28
#define vBmi_offset 29
#define vBge_offset 30

.macro	alloc_stack
	sub	sp, sp, #(STACK_SIZE)
.endm

.macro	free_stack
	add	sp, sp, #(STACK_SIZE)
.endm

.macro	save_vregs
	stp	d8,  d9, [sp, #(STACK_BASE_VREGS + 16*0)]
	stp	d10, d11, [sp, #(STACK_BASE_VREGS + 16*1)]
	stp	d12, d13, [sp, #(STACK_BASE_VREGS + 16*2)]
	stp	d14, d15, [sp, #(STACK_BASE_VREGS + 16*3)]
.endm

.macro	restore_vregs
	ldp	d8,  d9, [sp, #(STACK_BASE_VREGS + 16*0)]
	ldp	d10, d11, [sp, #(STACK_BASE_VREGS + 16*1)]
	ldp	d12, d13, [sp, #(STACK_BASE_VREGS + 16*2)]
	ldp	d14, d15, [sp, #(STACK_BASE_VREGS + 16*3)]
.endm



.macro	eor3_m1_0 d s0 s1 s2
	eor	\d\().16b, \s0\().16b, \s1\().16b
.endm

.macro	eor2 d s0 s1
	eor	\d\().16b, \s0\().16b, \s1\().16b
.endm

.macro	eor3_m1_1 d s0 s1 s2
	eor	\d\().16b, \d\().16b,  \s2\().16b
.endm

.macro	eor3_m1 d s0 s1 s2
	eor3_m1_0	\d, \s0, \s1, \s2
	eor3_m1_1	\d, \s0, \s1, \s2
.endm

.macro	rax1_m1 d s0 s1
   // Use add instead of SHL #1
	add	tmp.2d, \s1\().2d, \s1\().2d
	sri	tmp.2d, \s1\().2d, #63
	eor	\d\().16b, tmp.16b, \s0\().16b
.endm

.macro	xar_m1 d s0 s1 imm
   // Special cases where we can replace SHLs by ADDs
.if	\imm == 63
	eor	\s0\().16b, \s0\().16b, \s1\().16b
	add	\d\().2d, \s0\().2d, \s0\().2d
	sri	\d\().2d, \s0\().2d, #(63)
.elseif	\imm == 62
	eor	\s0\().16b, \s0\().16b, \s1\().16b
	add	\d\().2d, \s0\().2d, \s0\().2d
	add	\d\().2d, \d\().2d,  \d\().2d
	sri	\d\().2d, \s0\().2d, #(62)
   // .elseif \imm == 61
   //   eor \s0\().16b, \s0\().16b, \s1\().16b
   //   add \d\().2d, \s0\().2d, \s0\().2d
   //   add \d\().2d, \d\().2d,  \d\().2d
   //   add \d\().2d, \d\().2d,  \d\().2d
   //   sri \d\().2d, \s0\().2d, #(61)
.else
	eor	\s0\().16b, \s0\().16b, \s1\().16b
	shl	\d\().2d, \s0\().2d, #(64-\imm)
	sri	\d\().2d, \s0\().2d, #(\imm)
.endif
.endm

.macro	xar_m1_0 d s0 s1 imm
   // Special cases where we can replace SHLs by ADDs
.if	\imm == 63
	eor	\s0\().16b, \s0\().16b, \s1\().16b
.elseif	\imm == 62
	eor	\s0\().16b, \s0\().16b, \s1\().16b
.else
	eor	\s0\().16b, \s0\().16b, \s1\().16b
.endif
.endm

.macro	xar_m1_1 d s0 s1 imm
   // Special cases where we can replace SHLs by ADDs
.if	\imm == 63
	add	\d\().2d, \s0\().2d, \s0\().2d
	sri	\d\().2d, \s0\().2d, #(63)
.elseif	\imm == 62
	add	\d\().2d, \s0\().2d, \s0\().2d
	add	\d\().2d, \d\().2d,  \d\().2d
	sri	\d\().2d, \s0\().2d, #(62)
.else
	shl	\d\().2d, \s0\().2d, #(64-\imm)
	sri	\d\().2d, \s0\().2d, #(\imm)
.endif
.endm

.macro	bcax_m1 d s0 s1 s2
	bic	tmp.16b, \s1\().16b, \s2\().16b
	eor	\d\().16b, tmp.16b, \s0\().16b
.endm


.macro	keccak_f1600_round_pre

	eor3_m1_0	v28, v1, v6, v11
	eor3_m1_0	v30, v3, v8, v13
	eor3_m1_0	v27, v0, v5, v10
	eor3_m1_0	v29, v2, v7, v12
	eor3_m1_0	v31, v4, v9, v14
	eor3_m1_1	v28, v1, v6, v11
	eor3_m1_1	v30, v3, v8, v13
	eor3_m1_1	v27, v0, v5, v10
	eor3_m1_1	v29, v2, v7, v12
	eor3_m1_1	v31, v4, v9, v14
	eor3_m1_0	v28, v28, v16,  v21
	eor3_m1_0	v30, v30, v18,  v23
	eor3_m1_0	v27, v27, v15,  v20
	eor3_m1_0	v29, v29, v17,  v22
	eor3_m1_0	v31, v31, v19,  v24
	eor3_m1_1	v28, v28, v16,  v21
	eor3_m1_1	v30, v30, v18,  v23
	eor3_m1_1	v27, v27, v15,  v20
	eor3_m1_1	v29, v29, v17,  v22
	eor3_m1_1	v31, v31, v19,  v24

.endm

.macro	keccak_f1600_round

	eor3_m1_0	v27, v0, v5, v10
	eor3_m1_0	v28, v1, v6, v11
	eor3_m1_0	v29, v2, v7, v12
	eor3_m1_0	v30, v3, v8, v13
	eor3_m1_0	v31, v4, v9, v14
	eor3_m1_1	v27, v0, v5, v10
	eor3_m1_1	v28, v1, v6, v11
	eor3_m1_1	v29, v2, v7, v12
	eor3_m1_1	v30, v3, v8, v13
	eor3_m1_1	v31, v4, v9, v14
	eor3_m1_0	v27, v27, v15,  v20
	eor3_m1_0	v28, v28, v16,  v21
	eor3_m1_0	v29, v29, v17,  v22
	eor3_m1_0	v30, v30, v18,  v23
	eor3_m1_0	v31, v31, v19,  v24
	eor3_m1_1	v27, v27, v15,  v20
	eor3_m1_1	v28, v28, v16,  v21
	eor3_m1_1	v29, v29, v17,  v22
	eor3_m1_1	v30, v30, v18,  v23
	eor3_m1_1	v31, v31, v19,  v24

	tmp	.req v25
	rax1_m1	v26, v28, v30
	rax1_m1	v30, v30, v27
	rax1_m1	v27, v27, v29
	rax1_m1	v29, v29, v31
	rax1_m1	v31, v31, v28
.unreq	tmp

	tmp	.req v28
	tmpq	.req q28

	eor	v25.16b, v0.16b, v31.16b
	xar_m1	v0, v2, v26, 2
	xar_m1	v2, v12, v26, 21
	xar_m1	v12, v13, v29, 39
	xar_m1	v13, v19, v30, 56
	xar_m1	v19, v23, v29, 8
	xar_m1	v23, v15, v31, 23
	xar_m1	v15, v1, v27, 63
	xar_m1	v1, v8, v29, 9
	xar_m1	v8, v16, v27, 19
	xar_m1	v16, v7, v26, 58
	xar_m1	v7, v10, v31, 61
	xar_m1	v10, v3, v29, 36
	xar_m1	v3, v18, v29, 43
	xar_m1	v18, v17, v26, 49
	xar_m1	v17, v11, v27, 54
	xar_m1	v11, v9, v30, 44
	xar_m1	v9, v22, v26, 3
	xar_m1	v22, v14, v30, 25
	xar_m1	v14, v20, v31, 46
	xar_m1	v20, v4, v30, 37
	xar_m1	v4, v24, v30, 50
	xar_m1	v24, v21, v27, 62
	xar_m1	v21, v5, v31, 28
	xar_m1	v26, v6, v27, 20

	bcax_m1	v5, v10, v7, v11
	bcax_m1	v6, v11, v8, v7
	bcax_m1	v7, v7, v9, v8
	bcax_m1	v8, v8, v10, v9
	bcax_m1	v9, v9, v11, v10
	bcax_m1	v10, v15, v12, v16
	bcax_m1	v11, v16, v13, v12
	bcax_m1	v12, v12, v14, v13
	bcax_m1	v13, v13, v15, v14
	bcax_m1	v14, v14, v16, v15
	bcax_m1	v15, v20, v17, v21
	bcax_m1	v16, v21, v18, v17
	bcax_m1	v17, v17, v19, v18
	bcax_m1	v18, v18, v20, v19
	bcax_m1	v19, v19, v21, v20
	bcax_m1	v20, v0, v22, v1
	bcax_m1	v21, v1, v23, v22
	bcax_m1	v22, v22, v24, v23
	bcax_m1	v23, v23, v0, v24
	bcax_m1	v24, v24, v1, v0
	bcax_m1	v0, v25, v2, v26
	bcax_m1	v1, v26, v3, v2
	bcax_m1	v2, v2, v4, v3
	bcax_m1	v3, v3, v25, v4
	bcax_m1	v4, v4, v26, v25

    // iota step
    //ld1r {tmp.2d}, [x1], #8
	ldr	tmpq, [x1], #16
	eor	v0.16b, v0.16b, tmp.16b

.unreq	tmp
.unreq	tmpq

.endm

.macro	keccak_f1600_round_core

	tmp	.req v25
	rax1_m1	v26, v28, v30
	str	q5, [sp, #(STACK_BASE_TMP + 16 * 30)]
	rax1_m1	v30, v30, v27
	rax1_m1	v27, v27, v29
	rax1_m1	v29, v29, v31
	rax1_m1	v31, v31, v28


.unreq	tmp
	tmp	.req v28
	tmpq	.req q28

	eor	v25.16b, v0.16b, v31.16b
	xar_m1	v0, v2, v26, 2
	xar_m1	v2, v12, v26, 21
	xar_m1	v12, v13, v29, 39
	xar_m1	v13, v19, v30, 56
	xar_m1	v19, v23, v29, 8
	xar_m1	v23, v15, v31, 23
	xar_m1	v15, v1, v27, 63
	xar_m1	v1, v8, v29, 9
	xar_m1	v8, v16, v27, 19
	xar_m1	v16, v7, v26, 58
	xar_m1	v7, v10, v31, 61
	xar_m1	v10, v3, v29, 36
	xar_m1	v3, v18, v29, 43
	xar_m1	v18, v17, v26, 49
	xar_m1	v17, v11, v27, 54
	xar_m1	v11, v9, v30, 44
	bcax_m1	v5, v10, v7, v11
	xar_m1	v9, v22, v26, 3
	xar_m1	v22, v14, v30, 25
	xar_m1	v14, v20, v31, 46
	xar_m1	v20, v4, v30, 37
	xar_m1	v4, v24, v30, 50
	xar_m1	v24, v21, v27, 62
	ldr	tmpq, [sp, #(STACK_BASE_TMP + 16*30)]
	xar_m1	v21, tmp, v31, 28
	xar_m1	v26, v6, v27, 20

	bcax_m1	v6, v11, v8, v7
	bcax_m1	v7, v7, v9, v8
	bcax_m1	v8, v8, v10, v9
	bcax_m1	v9, v9, v11, v10
	bcax_m1	v10, v15, v12, v16
	bcax_m1	v11, v16, v13, v12

.unreq	tmp
.unreq	tmpq

	eor2	v27,  v10, v5
	str	q5, [sp, #(STACK_BASE_TMP + 16 * Aga_offset)]

	tmp	.req v5
	tmpq	.req q5
	bcax_m1	v12, v12, v14, v13
	bcax_m1	v13, v13, v15, v14
	eor2	v28,  v11, v6
	bcax_m1	v14, v14, v16, v15
	eor2	v29,  v12, v7
	bcax_m1	v15, v20, v17, v21
	eor2	v30,  v13, v8
	bcax_m1	v16, v21, v18, v17
	eor2	v31,  v14, v9
	bcax_m1	v17, v17, v19, v18
	eor2	v27,  v27,  v15
	bcax_m1	v18, v18, v20, v19
	eor2	v28,  v28,  v16
	bcax_m1	v19, v19, v21, v20
	eor2	v29,  v29,  v17
	bcax_m1	v20, v0, v22, v1
	eor2	v30,  v30,  v18
	bcax_m1	v21, v1, v23, v22
	eor2	v31,  v31,  v19
	bcax_m1	v22, v22, v24, v23
	eor2	v27,  v27,  v20
	bcax_m1	v23, v23, v0, v24
	eor2	v28,  v28,  v21
	bcax_m1	v24, v24, v1, v0
	eor2	v29,  v29,  v22
	eor2	v30,  v30,  v23
	bcax_m1	v0, v25, v2, v26
	bcax_m1	v1, v26, v3, v2
	eor2	v28,  v28,  v1

    // iota step
    //ld1r {tmp.2d}, [x1], #8
	ldr	tmpq, [x1], #16
	eor	v0.16b, v0.16b, tmp.16b
	eor2	v31,  v31,  v24
	bcax_m1	v2, v2, v4, v3
	bcax_m1	v3, v3, v25, v4
	eor2	v30,  v30,  v3
	eor2	v29,  v29,  v2
	eor2	v27,  v27,  v0
	bcax_m1	v4, v4, v26, v25
	eor2	v31,  v31,  v4

	ldr	q5, [sp, #(STACK_BASE_TMP + 16 * Aga_offset)]
.unreq	tmp
.unreq	tmpq

.endm

.macro	keccak_f1600_round_post

	tmp	.req v25
	rax1_m1	v26, v28, v30
	str	q5, [sp, #(STACK_BASE_TMP + 16 * 30)]
	rax1_m1	v30, v30, v27
	rax1_m1	v27, v27, v29
	rax1_m1	v29, v29, v31
	rax1_m1	v31, v31, v28


.unreq	tmp
	tmp	.req v28
	tmpq	.req q28

	eor	v25.16b, v0.16b, v31.16b
	xar_m1	v0, v2, v26, 2
	xar_m1	v2, v12, v26, 21
	xar_m1	v12, v13, v29, 39
	xar_m1	v13, v19, v30, 56
	xar_m1	v19, v23, v29, 8
	xar_m1	v23, v15, v31, 23
	xar_m1	v15, v1, v27, 63
	xar_m1	v1, v8, v29, 9
	xar_m1	v8, v16, v27, 19
	xar_m1	v16, v7, v26, 58
	xar_m1	v7, v10, v31, 61
	xar_m1	v10, v3, v29, 36
	xar_m1	v3, v18, v29, 43
	xar_m1	v18, v17, v26, 49
	xar_m1	v17, v11, v27, 54
	xar_m1	v11, v9, v30, 44
	bcax_m1	v5, v10, v7, v11
	xar_m1	v9, v22, v26, 3
	xar_m1	v22, v14, v30, 25
	xar_m1	v14, v20, v31, 46
	xar_m1	v20, v4, v30, 37
	xar_m1	v4, v24, v30, 50
	xar_m1	v24, v21, v27, 62
	ldr	tmpq, [sp, #(STACK_BASE_TMP + 16*30)]
	xar_m1	v21, tmp, v31, 28
	xar_m1	v26, v6, v27, 20

	bcax_m1	v6, v11, v8, v7
	bcax_m1	v7, v7, v9, v8
	bcax_m1	v8, v8, v10, v9
	bcax_m1	v9, v9, v11, v10
	bcax_m1	v10, v15, v12, v16
	bcax_m1	v11, v16, v13, v12
	bcax_m1	v12, v12, v14, v13
	bcax_m1	v13, v13, v15, v14
	bcax_m1	v14, v14, v16, v15
	bcax_m1	v15, v20, v17, v21
	bcax_m1	v16, v21, v18, v17
	bcax_m1	v17, v17, v19, v18
	bcax_m1	v18, v18, v20, v19
	bcax_m1	v19, v19, v21, v20
	bcax_m1	v20, v0, v22, v1
	bcax_m1	v21, v1, v23, v22
	bcax_m1	v22, v22, v24, v23
	bcax_m1	v23, v23, v0, v24
	bcax_m1	v24, v24, v1, v0
	bcax_m1	v0, v25, v2, v26
	bcax_m1	v1, v26, v3, v2
	bcax_m1	v2, v2, v4, v3
	bcax_m1	v3, v3, v25, v4
	bcax_m1	v4, v4, v26, v25

    // iota step
    //ld1r {tmp.2d}, [x1], #8
	ldr	tmpq, [x1], #16
	eor	v0.16b, v0.16b, tmp.16b

.unreq	tmp

.endm


.text
.align	4
.globl	keccak_f1600_x2_v84a_asm_v2pp2
.hidden	keccak_f1600_x2_v84a_asm_v2pp2
.globl	_keccak_f1600_x2_v84a_asm_v2pp2
.hidden	_keccak_f1600_x2_v84a_asm_v2pp2

#define KECCAK_F1600_ROUNDS 24

keccak_f1600_x2_v84a_asm_v2pp2:
_keccak_f1600_x2_v84a_asm_v2pp2:
	alloc_stack
	save_vregs
	load_constant_ptr
	load_input

    //mov x2, #(KECCAK_F1600_ROUNDS-2)
	mov	x2, #11
	keccak_f1600_round_pre
loop:
	keccak_f1600_round_core
	keccak_f1600_round_core
	sub	x2, x2, #1
	cbnz	x2, loop

	keccak_f1600_round_core
	keccak_f1600_round_post
	store_input
	restore_vregs
	free_stack
	ret
.byte	75,101,99,99,97,107,45,49,54,48,48,32,97,98,115,111,114,98,32,97,110,100,32,115,113,117,101,101,122,101,32,102,111,114,32,65,82,77,118,56,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	2
#endif  // !OPENSSL_NO_ASM && defined(__AARCH64EL__) && defined(__ELF__)
#if defined(__ELF__)
// See https://www.airs.com/blog/archives/518.
.section .note.GNU-stack,"",%progbits
#endif
