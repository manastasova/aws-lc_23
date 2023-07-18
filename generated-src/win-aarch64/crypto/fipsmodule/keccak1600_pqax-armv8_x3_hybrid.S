// This file is generated from a similarly-named Perl script in the BoringSSL
// source tree. Do not edit by hand.

#if !defined(__has_feature)
#define __has_feature(x) 0
#endif
#if __has_feature(memory_sanitizer) && !defined(OPENSSL_NO_ASM)
#define OPENSSL_NO_ASM
#endif

#if !defined(OPENSSL_NO_ASM) && defined(__AARCH64EL__) && defined(_WIN32)
#if defined(BORINGSSL_PREFIX)
#include <boringssl_prefix_symbols_asm.h>
#endif
#ifndef	__KERNEL__
# include <openssl/arm_arch.h>
#endif

#define SEP ;
#include <openssl/arm_arch.h>

.align(8)


round_constants:
.quad	0x0000000000000001
.quad	0x0000000000008082
.quad	0x800000000000808a
.quad	0x8000000080008000
.quad	0x000000000000808b
.quad	0x0000000080000001
.quad	0x8000000080008081
.quad	0x8000000000008009
.quad	0x000000000000008a
.quad	0x0000000000000088
.quad	0x0000000080008009
.quad	0x000000008000000a
.quad	0x000000008000808b
.quad	0x800000000000008b
.quad	0x8000000000008089
.quad	0x8000000000008003
.quad	0x8000000000008002
.quad	0x8000000000000080
.quad	0x000000000000800a
.quad	0x800000008000000a
.quad	0x8000000080008081
.quad	0x8000000000008080
.quad	0x0000000080000001
.quad	0x8000000080008008



round_constants_vec:
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




	input_addr	.req x0
	const_addr	.req x29
	count	.req w27
	cur_const	.req x26

    // Mapping of Kecck-f1600 SIMD state to vector registers at the beginning and end of each round. */

    // Mapping of Kecck-f1600 state to vector registers at the beginning and end of each round. */



	/*	Mapping of Kecck-f1600 state to scalar registers
	*	at the beginning and end of each round. */
	s_Aba	.req x1
	sAbe	.req x6
	sAbi	.req x11
	sAbo	.req x16
	sAbu	.req x21
	sAga	.req x2
	sAge	.req x7
	sAgi	.req x12
	sAgo	.req x17
	sAgu	.req x22
	sAka	.req x3
	sAke	.req x8
	sAki	.req x13
	sAko	.req x18
	sAku	.req x23
	sAma	.req x4
	sAme	.req x9
	sAmi	.req x14
	sAmo	.req x19
	sAmu	.req x24
	sAsa	.req x5
	sAse	.req x10
	sAsi	.req x15
	sAso	.req x20
	sAsu	.req x25


	s_Aba_	.req x0
	sAbe_	.req x28
	sAbi_	.req x11
	sAbo_	.req x16
	sAbu_	.req x21
	sAga_	.req x3
	sAge_	.req x8
	sAgi_	.req x12
	sAgo_	.req x17
	sAgu_	.req x22
	sAka_	.req x4
	sAke_	.req x9
	sAki_	.req x13
	sAko_	.req x18
	sAku_	.req x23
	sAma_	.req x5
	sAme_	.req x10
	sAmi_	.req x14
	sAmo_	.req x19
	sAmu_	.req x24
	sAsa_	.req x1
	sAse_	.req x6
	sAsi_	.req x15
	sAso_	.req x20
	sAsu_	.req x25



	sC0	.req x0
	sE0	.req x29
	sC1	.req x26
	sE1	.req x30
	sC2	.req x27
	sE2	.req x26
	sC3	.req x28
	sE3	.req x27
	sC4	.req x29
	sE4	.req x28

	tmp	.req x30





.macro	eor3_m0 d s0 s1 s2
	eor3	\d\().16b, \s0\().16b, \s1\().16b, \s2\().16b
.endm

.macro	rax1_m0 d s0 s1
	rax1	\d\().2d, \s0\().2d, \s1\().2d
.endm

.macro	xar_m0 d s0 s1 imm
	xar	\d\().2d, \s0\().2d, \s1\().2d, #\imm
.endm

.macro	bcax_m0 d s0 s1 s2
	bcax	\d\().16b, \s0\().16b, \s1\().16b, \s2\().16b
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
	add	vvtmp.2d, \s1\().2d, \s1\().2d
	sri	vvtmp.2d, \s1\().2d, #63
	eor	\d\().16b, vvtmp.16b, \s0\().16b
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
	bic	vvtmp.16b, \s1\().16b, \s2\().16b
	eor	\d\().16b, vvtmp.16b, \s0\().16b
.endm

.macro	load_input_vector num idx
	ldr	q0, [ input_addr, #(24*    0        )]
	ldr	q1, [ input_addr, #(24*    1        )]
	ldr	q2, [ input_addr, #(24*    2        )]
	ldr	q3, [ input_addr, #(24*    3        )]
	ldr	q4, [ input_addr, #(24*    4        )]
	ldr	q5, [ input_addr, #(24*    5        )]
	ldr	q6, [ input_addr, #(24*    6        )]
	ldr	q7, [ input_addr, #(24*    7        )]
	ldr	q8, [ input_addr, #(24*    8        )]
	ldr	q9, [ input_addr, #(24*    9        )]

	add	input_addr, input_addr, #24*10
	ldr	q10, [ input_addr, #(24*    0       )]
	ldr	q11, [ input_addr, #(24*    1       )]
	ldr	q12, [ input_addr, #(24*    2       )]
	ldr	q13, [ input_addr, #(24*    3       )]
	ldr	q14, [ input_addr, #(24*    4       )]
	ldr	q15, [ input_addr, #(24*    5       )]
	ldr	q16, [ input_addr, #(24*    6       )]
	ldr	q17, [ input_addr, #(24*    7       )]
	ldr	q18, [ input_addr, #(24*    8       )]
	ldr	q19, [ input_addr, #(24*    9       )]

	add	input_addr, input_addr, #24*10
	ldr	q20, [ input_addr, #(24*    0      )]
	ldr	q21, [ input_addr, #(24*    1       )]
	ldr	q22, [ input_addr, #(24*    2       )]
	ldr	q23, [ input_addr, #(24*    3       )]
	ldr	q24, [ input_addr, #(24*    4       )]
	sub	input_addr, input_addr, #480
.endm

.macro	store_input_vector num idx
	str	q0, [ input_addr, #(24*    0 )]
	str	q1, [ input_addr, #(24*    1 )]
	str	q2, [ input_addr, #(24*    2 )]
	str	q3, [ input_addr, #(24*    3 )]
	str	q4, [ input_addr, #(24*    4 )]
	str	q5, [ input_addr, #(24*    5 )]
	str	q6, [ input_addr, #(24*    6 )]
	str	q7, [ input_addr, #(24*    7 )]
	str	q8, [ input_addr, #(24*    8 )]
	str	q9, [ input_addr, #(24*    9 )]
	add	input_addr, input_addr, #24*10
	str	q10, [ input_addr, #(24*    0       )]
	str	q11, [ input_addr, #(24*    1       )]
	str	q12, [ input_addr, #(24*    2       )]
	str	q13, [ input_addr, #(24*    3       )]
	str	q14, [ input_addr, #(24*    4       )]
	str	q15, [ input_addr, #(24*    5       )]
	str	q16, [ input_addr, #(24*    6       )]
	str	q17, [ input_addr, #(24*    7       )]
	str	q18, [ input_addr, #(24*    8       )]
	str	q19, [ input_addr, #(24*    9       )]
	add	input_addr, input_addr, #24*10
	str	q20, [ input_addr, #(24*    0       )]
	str	q21, [ input_addr, #(24*    1       )]
	str	q22, [ input_addr, #(24*    2       )]
	str	q23, [ input_addr, #(24*    3       )]
	str	q24, [ input_addr, #(24*    4       )]
	sub	input_addr, input_addr, #24*20
.endm

.macro	store_input_scalar num idx
	str	s_Aba,[input_addr, 24*(0)]
	str	sAbe, [input_addr, 24*(1)]
	str	sAbi, [input_addr, 24*(2)]
	str	sAbo, [input_addr, 24*(3)]
	str	sAbu, [input_addr, 24*(4)]
	str	sAga, [input_addr, 24*(5)]
	str	sAge, [input_addr, 24*(6)]
	str	sAgi, [input_addr, 24*(7)]
	str	sAgo, [input_addr, 24*(8)]
	str	sAgu, [input_addr, 24*(9)]
	str	sAka, [input_addr, 24*(10)]
	str	sAke, [input_addr, 24*(11)]
	str	sAki, [input_addr, 24*(12)]
	str	sAko, [input_addr, 24*(13)]
	str	sAku, [input_addr, 24*(14)]
	str	sAma, [input_addr, 24*(15)]
	str	sAme, [input_addr, 24*(16)]
	str	sAmi, [input_addr, 24*(17)]
	str	sAmo, [input_addr, 24*(18)]
	str	sAmu, [input_addr, 24*(19)]
	str	sAsa, [input_addr, 24*(20)]
	str	sAse, [input_addr, 24*(21)]
	str	sAsi, [input_addr, 24*(22)]
	str	sAso, [input_addr, 24*(23)]
	str	sAsu, [input_addr, 24*(24)]
.endm

.macro	load_input_scalar num idx
	ldr	s_Aba, [input_addr,24*(0)]
	ldr	sAbe, [input_addr, 24*(1)]
	ldr	sAbi, [input_addr, 24*(2)]
	ldr	sAbo, [input_addr, 24*(3)]
	ldr	sAbu, [input_addr, 24*(4)]
	ldr	sAga, [input_addr, 24*(5)]
	ldr	sAge, [input_addr, 24*(6)]
	ldr	sAgi, [input_addr, 24*(7)]
	ldr	sAgo, [input_addr, 24*(8)]
	ldr	sAgu, [input_addr, 24*(9)]
	ldr	sAka, [input_addr, 24*(10)]
	ldr	sAke, [input_addr, 24*(11)]
	ldr	sAki, [input_addr, 24*(12)]
	ldr	sAko, [input_addr, 24*(13)]
	ldr	sAku, [input_addr, 24*(14)]
	ldr	sAma, [input_addr, 24*(15)]
	ldr	sAme, [input_addr, 24*(16)]
	ldr	sAmi, [input_addr, 24*(17)]
	ldr	sAmo, [input_addr, 24*(18)]
	ldr	sAmu, [input_addr, 24*(19)]
	ldr	sAsa, [input_addr, 24*(20)]
	ldr	sAse, [input_addr, 24*(21)]
	ldr	sAsi, [input_addr, 24*(22)]
	ldr	sAso, [input_addr, 24*(23)]
	ldr	sAsu, [input_addr, 24*(24)]
.endm
#define STACK_SIZE (8*8 + 16*6 + 3*8 + 8 + 16*34) // VREGS (8*8), GPRs (16*6), count (8), const (8), input (8), padding (8)
#define STACK_BASE_GPRS  (3*8+8)
#define STACK_BASE_VREGS (3*8+8+16*6)
#define STACK_BASE_TMP (8*8 + 16*6 + 3*8 + 8)
#define STACK_OFFSET_INPUT (0*8)
#define STACK_OFFSET_CONST (1*8)
#define STACK_OFFSET_COUNT (2*8)

#define vAga_offset 0
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


.macro	save_gprs
	stp	x19, x20, [sp, #(STACK_BASE_GPRS + 16*0)]
	stp	x21, x22, [sp, #(STACK_BASE_GPRS + 16*1)]
	stp	x23, x24, [sp, #(STACK_BASE_GPRS + 16*2)]
	stp	x25, x26, [sp, #(STACK_BASE_GPRS + 16*3)]
	stp	x27, x28, [sp, #(STACK_BASE_GPRS + 16*4)]
	stp	x29, x30, [sp, #(STACK_BASE_GPRS + 16*5)]
.endm

.macro	restore_gprs
	ldp	x19, x20, [sp, #(STACK_BASE_GPRS + 16*0)]
	ldp	x21, x22, [sp, #(STACK_BASE_GPRS + 16*1)]
	ldp	x23, x24, [sp, #(STACK_BASE_GPRS + 16*2)]
	ldp	x25, x26, [sp, #(STACK_BASE_GPRS + 16*3)]
	ldp	x27, x28, [sp, #(STACK_BASE_GPRS + 16*4)]
	ldp	x29, x30, [sp, #(STACK_BASE_GPRS + 16*5)]
.endm

.macro	save_vregs
	stp	d8,  d9,  [sp,#(STACK_BASE_VREGS+0*16)]
	stp	d10, d11, [sp,#(STACK_BASE_VREGS+1*16)]
	stp	d12, d13, [sp,#(STACK_BASE_VREGS+2*16)]
	stp	d14, d15, [sp,#(STACK_BASE_VREGS+3*16)]
.endm

.macro	restore_vregs
	ldp	d14, d15, [sp,#(STACK_BASE_VREGS+3*16)]
	ldp	d12, d13, [sp,#(STACK_BASE_VREGS+2*16)]
	ldp	d10, d11, [sp,#(STACK_BASE_VREGS+1*16)]
	ldp	d8,  d9,  [sp,#(STACK_BASE_VREGS+0*16)]
.endm

.macro	alloc_stack
	sub	sp, sp, #(STACK_SIZE)
.endm

.macro	free_stack
	add	sp, sp, #(STACK_SIZE)
.endm

.macro	eor5 dst, src0, src1, src2, src3, src4
	eor	\dst, \src0, \src1
	eor	\dst, \dst,  \src2
	eor	\dst, \dst,  \src3
	eor	\dst, \dst,  \src4
.endm

.macro	xor_rol dst, src1, src0, imm
	eor	\dst, \src0, \src1, ROR  #(64-\imm)
.endm

.macro	bic_rol dst, src1, src0, imm
	bic	\dst, \src0, \src1, ROR  #(64-\imm)
.endm

.macro	rotate dst, src, imm
	ror	\dst, \src, #(64-\imm)
.endm

.macro	save reg, offset
	str	\reg, [sp, #\offset]
.endm

.macro	restore reg, offset
	ldr	\reg, [sp, #\offset]
.endm

.macro	load_constant_ptr
	adr	const_addr, round_constants
.endm

.macro	hybrid_round_initial
	eor	sC0, sAma, sAsa                             SEP
	eor	sC1, sAme, sAse                             SEP      .inst	0xce062c3c	//eor3_m0 v28,v1,v6,v11
	eor	sC2, sAmi, sAsi                             SEP      eor3_m1 v30,v3,v8,v13
	eor	sC3, sAmo, sAso                             SEP      .inst	0xce05281b	//eor3_m0 v27,v0,v5,v10
	eor	sC4, sAmu, sAsu                             SEP      eor3_m1 v29,v2,v7,v12
	eor	sC0, sAka, sC0                              SEP      .inst	0xce09389f	//eor3_m0 v31,v4,v9,v14
	eor	sC1, sAke, sC1                              SEP      eor3_m1 v28, v28,v16, v21
	eor	sC2, sAki, sC2                              SEP      .inst	0xce125fde	//eor3_m0 v30, v30,v18, v23
	eor	sC3, sAko, sC3                              SEP      eor3_m1 v27, v27,v15, v20
	eor	sC4, sAku, sC4                              SEP      .inst	0xce115bbd	//eor3_m0 v29, v29,v17, v22
	eor	sC0, sAga, sC0                              SEP      eor3_m1 v31, v31,v19, v24
	eor	sC1, sAge, sC1                              SEP      vvtmp .req v25
	eor	sC2, sAgi, sC2                              SEP
	eor	sC3, sAgo, sC3                              SEP      .inst	0xce7e8f9a	//rax1_m0 v26, v28, v30
	eor	sC4, sAgu, sC4                              SEP      rax1_m1 v30, v30, v27
	eor	sC0, s_Aba, sC0                             SEP      .inst	0xce7d8f7b	//rax1_m0 v27, v27, v29
	eor	sC1, sAbe, sC1                              SEP      rax1_m1 v29, v29, v31
	eor	sC2, sAbi, sC2                              SEP      .inst	0xce7c8fff	//rax1_m0 v31, v31, v28
	eor	sC3, sAbo, sC3                              SEP      .unreq vvtmp
	eor	sC4, sAbu, sC4                              SEP      vvtmp .req v28
	eor	sE1, sC0, sC2, ROR #63                      SEP      vvtmpq .req q28
	eor	sE3, sC2, sC4, ROR #63                      SEP      eor v25.16b, v0.16b, v31.16b
	eor	sE0, sC4, sC1, ROR #63                      SEP      xar_m1 v0, v2, v26, 2
	eor	sE2, sC1, sC3, ROR #63                      SEP
	eor	sE4, sC3, sC0, ROR #63                      SEP      xar_m1 v2, v12, v26, 21
	eor	s_Aba_, s_Aba, sE0                          SEP      xar_m1 v12, v13, v29, 39
	eor	sAsa_, sAbi, sE2                            SEP      xar_m1 v13, v19, v30, 56
	eor	sAbi_, sAki, sE2                            SEP      xar_m1 v19, v23, v29, 8
	eor	sAki_, sAko, sE3                            SEP      xar_m1 v23, v15, v31, 23
	eor	sAko_, sAmu, sE4                            SEP      xar_m1 v15, v1, v27, 63
	eor	sAmu_, sAso, sE3                            SEP      xar_m1 v1, v8, v29, 9
	eor	sAso_, sAma, sE0                            SEP      xar_m1 v8, v16, v27, 19
	eor	sAka_, sAbe, sE1                            SEP      xar_m1 v16, v7, v26, 58
	eor	sAse_, sAgo, sE3                            SEP      xar_m1 v7, v10, v31, 61
	eor	sAgo_, sAme, sE1                            SEP
	eor	sAke_, sAgi, sE2                            SEP      xar_m1 v10, v3, v29, 36
	eor	sAgi_, sAka, sE0                            SEP      xar_m1 v3, v18, v29, 43
	eor	sAga_, sAbo, sE3                            SEP      xar_m1 v18, v17, v26, 49
	eor	sAbo_, sAmo, sE3                            SEP      xar_m1 v17, v11, v27, 54
	eor	sAmo_, sAmi, sE2                            SEP      xar_m1 v11, v9, v30, 44
	eor	sAmi_, sAke, sE1                            SEP      mov v29.16b, v5.16b
	eor	sAge_, sAgu, sE4                            SEP      bcax_m1 v5, v10, v7, v11
	eor	sAgu_, sAsi, sE2                            SEP      xar_m1 v9, v22, v26, 3
	eor	sAsi_, sAku, sE4                            SEP      xar_m1 v22, v14, v30, 25
	eor	sAku_, sAsa, sE0                            SEP      xar_m1 v14, v20, v31, 46
	eor	sAma_, sAbu, sE4                            SEP
	eor	sAbu_, sAsu, sE4                            SEP      xar_m1 v20, v4, v30, 37
	eor	sAsu_, sAse, sE1                            SEP      xar_m1 v4, v24, v30, 50
	eor	sAme_, sAga, sE0                            SEP      xar_m1 v24, v21, v27, 62
	eor	sAbe_, sAge, sE1                            SEP      xar_m1 v21, v29, v31, 28
	load_constant_ptr	SEP      xar_m1 v26, v6, v27, 20
	bic	tmp, sAgi_, sAge_, ROR #47                  SEP      bcax_m1 v6, v11, v8, v7
	eor	sAga, tmp,  sAga_, ROR #39                  SEP      .inst	0xce2920e7	//bcax_m0 v7, v7, v9, v8
	bic	tmp, sAgo_, sAgi_, ROR #42                  SEP      bcax_m1 v8, v8, v10, v9
	eor	sAge, tmp,  sAge_, ROR #25                  SEP      .inst	0xce2b2929	//bcax_m0 v9, v9, v11, v10
	bic	tmp, sAgu_, sAgo_, ROR #16                  SEP      bcax_m1 v10, v15, v12, v16
	eor	sAgi, tmp,  sAgi_, ROR #58                  SEP      .inst	0xce2d320b	//bcax_m0 v11, v16, v13, v12
	bic	tmp, sAga_, sAgu_, ROR #31                  SEP
	eor	sAgo, tmp,  sAgo_, ROR #47                  SEP      .unreq vvtmp
	bic	tmp, sAge_, sAga_, ROR #56                  SEP      .unreq vvtmpq
	eor	sAgu, tmp,  sAgu_, ROR #23                  SEP      eor2    v27,  v10, v5
	bic	tmp, sAki_, sAke_, ROR #19                  SEP      str q5, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
	eor	sAka, tmp,  sAka_, ROR #24                  SEP      vvtmp .req v5
	bic	tmp, sAko_, sAki_, ROR #47                  SEP      vvtmpq .req q5
	eor	sAke, tmp,  sAke_, ROR #2                   SEP      .inst	0xce2e358c	//bcax_m0 v12, v12, v14, v13
	bic	tmp, sAku_, sAko_, ROR #10                  SEP      bcax_m1 v13, v13, v15, v14
	eor	sAki, tmp,  sAki_, ROR #57                  SEP      eor2    v28,  v11, v6
	bic	tmp, sAka_, sAku_, ROR #47                  SEP      .inst	0xce303dce	//bcax_m0 v14, v14, v16, v15
	eor	sAko, tmp,  sAko_, ROR #57                  SEP
	bic	tmp, sAke_, sAka_, ROR #5                   SEP      eor2    v29,  v12, v7
	eor	sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m1 v15, v20, v17, v21
	bic	tmp, sAmi_, sAme_, ROR #38                  SEP      eor2    v30,  v13, v8
	eor	sAma, tmp,  sAma_, ROR #47                  SEP      .inst	0xce3246b0	//bcax_m0 v16, v21, v18, v17
	bic	tmp, sAmo_, sAmi_, ROR #5                   SEP      eor2    v31,  v14, v9
	eor	sAme, tmp,  sAme_, ROR #43                  SEP      bcax_m1 v17, v17, v19, v18
	bic	tmp, sAmu_, sAmo_, ROR #41                  SEP      eor2    v27,  v27,  v15
	eor	sAmi, tmp,  sAmi_, ROR #46                  SEP      .inst	0xce344e52	//bcax_m0 v18, v18, v20, v19
	ldr	cur_const, [const_addr]                     SEP      eor2    v28,  v28,  v16
	mov	count, #1                                   SEP      bcax_m1 v19, v19, v21, v20
	bic	tmp, sAma_, sAmu_, ROR #35                  SEP
	eor	sAmo, tmp,  sAmo_, ROR #12                  SEP      eor2    v29,  v29,  v17
	bic	tmp, sAme_, sAma_, ROR #9                   SEP      .inst	0xce360414	//bcax_m0 v20, v0, v22, v1
	eor	sAmu, tmp,  sAmu_, ROR #44                  SEP      eor2    v30,  v30,  v18
	bic	tmp, sAsi_, sAse_, ROR #48                  SEP      bcax_m1 v21, v1, v23, v22
	eor	sAsa, tmp,  sAsa_, ROR #41                  SEP      eor2    v31,  v31,  v19
	bic	tmp, sAso_, sAsi_, ROR #2                   SEP      .inst	0xce385ed6	//bcax_m0 v22, v22, v24, v23
	eor	sAse, tmp,  sAse_, ROR #50                  SEP      eor2    v27,  v27,  v20
	bic	tmp, sAsu_, sAso_, ROR #25                  SEP      bcax_m1 v23, v23, v0, v24
	eor	sAsi, tmp,  sAsi_, ROR #27                  SEP      eor2    v28,  v28,  v21
	bic	tmp, sAsa_, sAsu_, ROR #60                  SEP      .inst	0xce210318	//bcax_m0 v24, v24, v1, v0
	eor	sAso, tmp,  sAso_, ROR #21                  SEP
	save	count, STACK_OFFSET_COUNT                  SEP
	bic	tmp, sAse_, sAsa_, ROR #57                  SEP      eor2    v29,  v29,  v22
	eor	sAsu, tmp,  sAsu_, ROR #53                  SEP      eor2    v30,  v30,  v23
	bic	tmp, sAbi_, sAbe_, ROR #63                  SEP      bcax_m1 v0, v25, v2, v26
	eor	s_Aba, s_Aba_, tmp,  ROR #21                SEP      .inst	0xce230b41	//bcax_m0 v1, v26, v3, v2
	bic	tmp, sAbo_, sAbi_, ROR #42                  SEP      eor2    v28,  v28,  v1
	eor	sAbe, tmp,  sAbe_, ROR #41                  SEP      restore x27, STACK_OFFSET_CONST
	bic	tmp, sAbu_, sAbo_, ROR #57                  SEP      ldr vvtmpq, [x27], #16
	eor	sAbi, tmp,  sAbi_, ROR #35                  SEP      save x27, STACK_OFFSET_CONST
	bic	tmp, s_Aba_, sAbu_, ROR #50                 SEP      eor v0.16b, v0.16b, vvtmp.16b
	eor	sAbo, tmp,  sAbo_, ROR #43                  SEP      eor2    v31,  v31,  v24
	bic	tmp, sAbe_, s_Aba_, ROR #44                 SEP
	eor	sAbu, tmp,  sAbu_, ROR #30                  SEP      .inst	0xce240c42	//bcax_m0 v2, v2, v4, v3
	eor	s_Aba, s_Aba, cur_const                     SEP      bcax_m1 v3, v3, v25, v4
	SEP	eor2    v30,  v30,  v3
	eor	sC0, sAka, sAsa, ROR #50                    SEP      eor2    v29,  v29,  v2
	eor	sC1, sAse, sAge, ROR #60                    SEP      eor2    v27,  v27,  v0
	eor	sC2, sAmi, sAgi, ROR #59                    SEP      .inst	0xce3a6484	//bcax_m0 v4, v4, v26, v25
	eor	sC3, sAgo, sAso, ROR #30                    SEP      eor2    v31,  v31,  v4
	eor	sC4, sAbu, sAsu, ROR #53                    SEP      ldr q5, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
	eor	sC0, sAma, sC0, ROR #49                     SEP      .unreq vvtmp
	eor	sC1, sAbe, sC1, ROR #44                     SEP      .unreq vvtmpq
	eor	sC2, sAki, sC2, ROR #26                     SEP      vvtmp .req v25
	eor	sC3, sAmo, sC3, ROR #63                     SEP
	eor	sC4, sAmu, sC4, ROR #56                     SEP      .inst	0xce7e8f9a	//rax1_m0 v26, v28, v30
	eor	sC0, sAga, sC0, ROR #57                     SEP      rax1_m1 v30, v30, v27
	eor	sC1, sAme, sC1, ROR #58                     SEP      .inst	0xce7d8f7b	//rax1_m0 v27, v27, v29
	eor	sC2, sAbi, sC2, ROR #60                     SEP      rax1_m1 v29, v29, v31
	eor	sC3, sAko, sC3, ROR #38                     SEP      .inst	0xce7c8fff	//rax1_m0 v31, v31, v28
	eor	sC4, sAgu, sC4, ROR #48                     SEP      .unreq vvtmp
	eor	sC0, s_Aba, sC0, ROR #61                    SEP      vvtmp .req v28
	eor	sC1, sAke, sC1, ROR #57                     SEP      vvtmpq .req q28
	eor	sC2, sAsi, sC2, ROR #52                     SEP      eor v25.16b, v0.16b, v31.16b
	eor	sC3, sAbo, sC3, ROR #63                     SEP      xar_m1 v0, v2, v26, 2
	eor	sC4, sAku, sC4, ROR #50                     SEP
	ror	sC1, sC1, 56                                SEP      xar_m1 v2, v12, v26, 21
	ror	sC4, sC4, 58                                SEP      xar_m1 v12, v13, v29, 39
	ror	sC2, sC2, 62                                SEP      xar_m1 v13, v19, v30, 56
	eor	sE1, sC0, sC2, ROR #63                      SEP      xar_m1 v19, v23, v29, 8
	eor	sE3, sC2, sC4, ROR #63                      SEP      xar_m1 v23, v15, v31, 23
	eor	sE0, sC4, sC1, ROR #63                      SEP      xar_m1 v15, v1, v27, 63
	eor	sE2, sC1, sC3, ROR #63                      SEP      xar_m1 v1, v8, v29, 9
	eor	sE4, sC3, sC0, ROR #63                      SEP      xar_m1 v8, v16, v27, 19
	eor	s_Aba_, sE0, s_Aba                          SEP      xar_m1 v16, v7, v26, 58
	eor	sAsa_, sE2, sAbi, ROR #50                   SEP      xar_m1 v7, v10, v31, 61
	eor	sAbi_, sE2, sAki, ROR #46                   SEP
	eor	sAki_, sE3, sAko, ROR #63                   SEP      xar_m1 v10, v3, v29, 36
	eor	sAko_, sE4, sAmu, ROR #28                   SEP      xar_m1 v3, v18, v29, 43
	eor	sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 v18, v17, v26, 49
	eor	sAso_, sE0, sAma, ROR #54                   SEP      xar_m1 v17, v11, v27, 54
	eor	sAka_, sE1, sAbe, ROR #43                   SEP      xar_m1 v11, v9, v30, 44
	eor	sAse_, sE3, sAgo, ROR #36                   SEP      mov v29.16b, v5.16b
	eor	sAgo_, sE1, sAme, ROR #49                   SEP      bcax_m1 v5, v10, v7, v11
	eor	sAke_, sE2, sAgi, ROR #3                    SEP      xar_m1 v9, v22, v26, 3
	eor	sAgi_, sE0, sAka, ROR #39                   SEP      xar_m1 v22, v14, v30, 25
	eor	sAga_, sE3, sAbo                            SEP      xar_m1 v14, v20, v31, 46
	eor	sAbo_, sE3, sAmo, ROR #37                   SEP
	eor	sAmo_, sE2, sAmi, ROR #8                    SEP      xar_m1 v20, v4, v30, 37
	eor	sAmi_, sE1, sAke, ROR #56                   SEP      xar_m1 v4, v24, v30, 50
	eor	sAge_, sE4, sAgu, ROR #44                   SEP      xar_m1 v24, v21, v27, 62
	eor	sAgu_, sE2, sAsi, ROR #62                   SEP      xar_m1 v21, v29, v31, 28
	eor	sAsi_, sE4, sAku, ROR #58                   SEP      xar_m1 v26, v6, v27, 20
	eor	sAku_, sE0, sAsa, ROR #25                   SEP      bcax_m1 v6, v11, v8, v7
	eor	sAma_, sE4, sAbu, ROR #20                   SEP      .inst	0xce2920e7	//bcax_m0 v7, v7, v9, v8
	eor	sAbu_, sE4, sAsu, ROR #9                    SEP      bcax_m1 v8, v8, v10, v9
	eor	sAsu_, sE1, sAse, ROR #23                   SEP      .inst	0xce2b2929	//bcax_m0 v9, v9, v11, v10
	eor	sAme_, sE0, sAga, ROR #61                   SEP      bcax_m1 v10, v15, v12, v16
	eor	sAbe_, sE1, sAge, ROR #19                   SEP
	load_constant_ptr	SEP      .inst	0xce2d320b	//bcax_m0 v11, v16, v13, v12
	restore	count, STACK_OFFSET_COUNT               SEP      .unreq vvtmp
	bic	tmp, sAgi_, sAge_, ROR #47                  SEP      .unreq vvtmpq
	eor	sAga, tmp,  sAga_, ROR #39                  SEP      eor2    v27,  v10, v5
	bic	tmp, sAgo_, sAgi_, ROR #42                  SEP      str q5, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
	eor	sAge, tmp,  sAge_, ROR #25                  SEP      vvtmp .req v5
	bic	tmp, sAgu_, sAgo_, ROR #16                  SEP      vvtmpq .req q5
	eor	sAgi, tmp,  sAgi_, ROR #58                  SEP      .inst	0xce2e358c	//bcax_m0 v12, v12, v14, v13
	bic	tmp, sAga_, sAgu_, ROR #31                  SEP      bcax_m1 v13, v13, v15, v14
	eor	sAgo, tmp,  sAgo_, ROR #47                  SEP      eor2    v28,  v11, v6
	bic	tmp, sAge_, sAga_, ROR #56                  SEP      .inst	0xce303dce	//bcax_m0 v14, v14, v16, v15
	eor	sAgu, tmp,  sAgu_, ROR #23                  SEP
	bic	tmp, sAki_, sAke_, ROR #19                  SEP      eor2    v29,  v12, v7
	eor	sAka, tmp,  sAka_, ROR #24                  SEP      bcax_m1 v15, v20, v17, v21
	bic	tmp, sAko_, sAki_, ROR #47                  SEP      eor2    v30,  v13, v8
	eor	sAke, tmp,  sAke_, ROR #2                   SEP      .inst	0xce3246b0	//bcax_m0 v16, v21, v18, v17
	bic	tmp, sAku_, sAko_, ROR #10                  SEP      eor2    v31,  v14, v9
	eor	sAki, tmp,  sAki_, ROR #57                  SEP      bcax_m1 v17, v17, v19, v18
	bic	tmp, sAka_, sAku_, ROR #47                  SEP      eor2    v27,  v27,  v15
	eor	sAko, tmp,  sAko_, ROR #57                  SEP      .inst	0xce344e52	//bcax_m0 v18, v18, v20, v19
	bic	tmp, sAke_, sAka_, ROR #5                   SEP      eor2    v28,  v28,  v16
	eor	sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m1 v19, v19, v21, v20
	bic	tmp, sAmi_, sAme_, ROR #38                  SEP
	eor	sAma, tmp,  sAma_, ROR #47                  SEP      eor2    v29,  v29,  v17
	bic	tmp, sAmo_, sAmi_, ROR #5                   SEP      .inst	0xce360414	//bcax_m0 v20, v0, v22, v1
	eor	sAme, tmp,  sAme_, ROR #43                  SEP      eor2    v30,  v30,  v18
	bic	tmp, sAmu_, sAmo_, ROR #41                  SEP      bcax_m1 v21, v1, v23, v22
	eor	sAmi, tmp,  sAmi_, ROR #46                  SEP      eor2    v31,  v31,  v19
	bic	tmp, sAma_, sAmu_, ROR #35                  SEP      .inst	0xce385ed6	//bcax_m0 v22, v22, v24, v23
	eor	sAmo, tmp,  sAmo_, ROR #12                  SEP      eor2    v27,  v27,  v20
	bic	tmp, sAme_, sAma_, ROR #9                   SEP      bcax_m1 v23, v23, v0, v24
	eor	sAmu, tmp,  sAmu_, ROR #44                  SEP      eor2    v28,  v28,  v21
	bic	tmp, sAsi_, sAse_, ROR #48                  SEP      .inst	0xce210318	//bcax_m0 v24, v24, v1, v0
	eor	sAsa, tmp,  sAsa_, ROR #41                  SEP      eor2    v29,  v29,  v22
	bic	tmp, sAso_, sAsi_, ROR #2                   SEP      eor2    v30,  v30,  v23
	eor	sAse, tmp,  sAse_, ROR #50                  SEP      bcax_m1 v0, v25, v2, v26
	bic	tmp, sAsu_, sAso_, ROR #25                  SEP      .inst	0xce230b41	//bcax_m0 v1, v26, v3, v2
	eor	sAsi, tmp,  sAsi_, ROR #27                  SEP      eor2    v28,  v28,  v1
	bic	tmp, sAsa_, sAsu_, ROR #60                  SEP      restore x26, STACK_OFFSET_CONST
	eor	sAso, tmp,  sAso_, ROR #21                  SEP      ldr vvtmpq, [x26], #16
	bic	tmp, sAse_, sAsa_, ROR #57                  SEP      save x26, STACK_OFFSET_CONST
	eor	sAsu, tmp,  sAsu_, ROR #53                  SEP      eor v0.16b, v0.16b, vvtmp.16b
	bic	tmp, sAbi_, sAbe_, ROR #63                  SEP      eor2    v31,  v31,  v24
	eor	s_Aba, s_Aba_, tmp,  ROR #21                SEP
	ldr	cur_const, [const_addr, count, UXTW #3]     SEP
	bic	tmp, sAbo_, sAbi_, ROR #42                  SEP      .inst	0xce240c42	//bcax_m0 v2, v2, v4, v3
	eor	sAbe, tmp,  sAbe_, ROR #41                  SEP      bcax_m1 v3, v3, v25, v4
	bic	tmp, sAbu_, sAbo_, ROR #57                  SEP      eor2    v30,  v30,  v3
	eor	sAbi, tmp,  sAbi_, ROR #35                  SEP      eor2    v29,  v29,  v2
	bic	tmp, s_Aba_, sAbu_, ROR #50                 SEP      eor2    v27,  v27,  v0
	eor	sAbo, tmp,  sAbo_, ROR #43                  SEP      .inst	0xce3a6484	//bcax_m0 v4, v4, v26, v25
	bic	tmp, sAbe_, s_Aba_, ROR #44                 SEP      eor2    v31,  v31,  v4
	eor	sAbu, tmp,  sAbu_, ROR #30                  SEP      ldr q5, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
	add	count, count, #1                            SEP      .unreq vvtmp
	eor	s_Aba, s_Aba, cur_const                     SEP      .unreq vvtmpq
.endm

.macro	hybrid_round_noninitial
	save	count, STACK_OFFSET_COUNT                  SEP
	eor	sC0, sAka, sAsa, ROR #50                    SEP      vvtmp .req v25
	eor	sC1, sAse, sAge, ROR #60                    SEP      .inst	0xce7e8f9a	//rax1_m0 v26, v28, v30
	eor	sC2, sAmi, sAgi, ROR #59                    SEP      rax1_m1 v30, v30, v27
	eor	sC3, sAgo, sAso, ROR #30                    SEP      .inst	0xce7d8f7b	//rax1_m0 v27, v27, v29
	eor	sC4, sAbu, sAsu, ROR #53                    SEP      rax1_m1 v29, v29, v31
	eor	sC0, sAma, sC0, ROR #49                     SEP      .inst	0xce7c8fff	//rax1_m0 v31, v31, v28
	eor	sC1, sAbe, sC1, ROR #44                     SEP
	eor	sC2, sAki, sC2, ROR #26                     SEP      .unreq vvtmp
	eor	sC3, sAmo, sC3, ROR #63                     SEP      vvtmp .req v28
	eor	sC4, sAmu, sC4, ROR #56                     SEP      vvtmpq .req  q28
	eor	sC0, sAga, sC0, ROR #57                     SEP      eor v25.16b, v0.16b, v31.16b
	eor	sC1, sAme, sC1, ROR #58                     SEP      xar_m1 v0, v2, v26, 2
	eor	sC2, sAbi, sC2, ROR #60                     SEP
	eor	sC3, sAko, sC3, ROR #38                     SEP      xar_m1 v2, v12, v26, 21
	eor	sC4, sAgu, sC4, ROR #48                     SEP      xar_m1 v12, v13, v29, 39
	eor	sC0, s_Aba, sC0, ROR #61                    SEP      xar_m1 v13, v19, v30, 56
	eor	sC1, sAke, sC1, ROR #57                     SEP      xar_m1 v19, v23, v29, 8
	eor	sC2, sAsi, sC2, ROR #52                     SEP      xar_m1 v23, v15, v31, 23
	eor	sC3, sAbo, sC3, ROR #63                     SEP      xar_m1 v15, v1, v27, 63
	eor	sC4, sAku, sC4, ROR #50                     SEP
	ror	sC1, sC1, 56                                SEP      xar_m1 v1, v8, v29, 9
	ror	sC4, sC4, 58                                SEP      xar_m1 v8, v16, v27, 19
	ror	sC2, sC2, 62                                SEP      xar_m1 v16, v7, v26, 58
	eor	sE1, sC0, sC2, ROR #63                      SEP      xar_m1 v7, v10, v31, 61
	eor	sE3, sC2, sC4, ROR #63                      SEP      xar_m1 v10, v3, v29, 36
	eor	sE0, sC4, sC1, ROR #63                      SEP
	eor	sE2, sC1, sC3, ROR #63                      SEP      xar_m1 v3, v18, v29, 43
	eor	sE4, sC3, sC0, ROR #63                      SEP      xar_m1 v18, v17, v26, 49
	eor	s_Aba_, sE0, s_Aba                          SEP      xar_m1 v17, v11, v27, 54
	eor	sAsa_, sE2, sAbi, ROR #50                   SEP      xar_m1 v11, v9, v30, 44
	eor	sAbi_, sE2, sAki, ROR #46                   SEP      mov v29.16b, v5.16b
	eor	sAki_, sE3, sAko, ROR #63                   SEP      bcax_m1 v5, v10, v7, v11
	eor	sAko_, sE4, sAmu, ROR #28                   SEP
	eor	sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 v9, v22, v26, 3
	eor	sAso_, sE0, sAma, ROR #54                   SEP      xar_m1 v22, v14, v30, 25
	eor	sAka_, sE1, sAbe, ROR #43                   SEP      xar_m1 v14, v20, v31, 46
	eor	sAse_, sE3, sAgo, ROR #36                   SEP      xar_m1 v20, v4, v30, 37
	eor	sAgo_, sE1, sAme, ROR #49                   SEP      xar_m1 v4, v24, v30, 50
	eor	sAke_, sE2, sAgi, ROR #3                    SEP
	eor	sAgi_, sE0, sAka, ROR #39                   SEP      xar_m1 v24, v21, v27, 62
	eor	sAga_, sE3, sAbo                            SEP      xar_m1 v21, v29, v31, 28
	eor	sAbo_, sE3, sAmo, ROR #37                   SEP      xar_m1 v26, v6, v27, 20
	eor	sAmo_, sE2, sAmi, ROR #8                    SEP      bcax_m1 v6, v11, v8, v7
	eor	sAmi_, sE1, sAke, ROR #56                   SEP      .inst	0xce2920e7	//bcax_m0 v7, v7, v9, v8
	eor	sAge_, sE4, sAgu, ROR #44                   SEP
	eor	sAgu_, sE2, sAsi, ROR #62                   SEP      bcax_m1 v8, v8, v10, v9
	eor	sAsi_, sE4, sAku, ROR #58                   SEP      .inst	0xce2b2929	//bcax_m0 v9, v9, v11, v10
	eor	sAku_, sE0, sAsa, ROR #25                   SEP      bcax_m1 v10, v15, v12, v16
	eor	sAma_, sE4, sAbu, ROR #20                   SEP      .inst	0xce2d320b	//bcax_m0 v11, v16, v13, v12
	eor	sAbu_, sE4, sAsu, ROR #9                    SEP      .unreq vvtmp
	eor	sAsu_, sE1, sAse, ROR #23                   SEP      .unreq vvtmpq
	eor	sAme_, sE0, sAga, ROR #61                   SEP
	eor	sAbe_, sE1, sAge, ROR #19                   SEP      eor2    v27,  v10, v5
	load_constant_ptr	SEP      str q5, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
	restore	count, STACK_OFFSET_COUNT               SEP      vvtmp .req v5
	bic	tmp, sAgi_, sAge_, ROR #47                  SEP      vvtmpq .req q5
	eor	sAga, tmp,  sAga_, ROR #39                  SEP      .inst	0xce2e358c	//bcax_m0 v12, v12, v14, v13
	bic	tmp, sAgo_, sAgi_, ROR #42                  SEP
	eor	sAge, tmp,  sAge_, ROR #25                  SEP      bcax_m1 v13, v13, v15, v14
	bic	tmp, sAgu_, sAgo_, ROR #16                  SEP      eor2    v28,  v11, v6
	eor	sAgi, tmp,  sAgi_, ROR #58                  SEP      .inst	0xce303dce	//bcax_m0 v14, v14, v16, v15
	bic	tmp, sAga_, sAgu_, ROR #31                  SEP      eor2    v29,  v12, v7
	eor	sAgo, tmp,  sAgo_, ROR #47                  SEP      bcax_m1 v15, v20, v17, v21
	bic	tmp, sAge_, sAga_, ROR #56                  SEP      eor2    v30,  v13, v8
	eor	sAgu, tmp,  sAgu_, ROR #23                  SEP
	bic	tmp, sAki_, sAke_, ROR #19                  SEP      .inst	0xce3246b0	//bcax_m0 v16, v21, v18, v17
	eor	sAka, tmp,  sAka_, ROR #24                  SEP      eor2    v31,  v14, v9
	bic	tmp, sAko_, sAki_, ROR #47                  SEP      bcax_m1 v17, v17, v19, v18
	eor	sAke, tmp,  sAke_, ROR #2                   SEP      eor2    v27,  v27,  v15
	bic	tmp, sAku_, sAko_, ROR #10                  SEP      .inst	0xce344e52	//bcax_m0 v18, v18, v20, v19
	eor	sAki, tmp,  sAki_, ROR #57                  SEP
	bic	tmp, sAka_, sAku_, ROR #47                  SEP      eor2    v28,  v28,  v16
	eor	sAko, tmp,  sAko_, ROR #57                  SEP      bcax_m1 v19, v19, v21, v20
	bic	tmp, sAke_, sAka_, ROR #5                   SEP      eor2    v29,  v29,  v17
	eor	sAku, tmp,  sAku_, ROR #52                  SEP      .inst	0xce360414	//bcax_m0 v20, v0, v22, v1
	bic	tmp, sAmi_, sAme_, ROR #38                  SEP      eor2    v30,  v30,  v18
	eor	sAma, tmp,  sAma_, ROR #47                  SEP
	bic	tmp, sAmo_, sAmi_, ROR #5                   SEP      bcax_m1 v21, v1, v23, v22
	eor	sAme, tmp,  sAme_, ROR #43                  SEP      eor2    v31,  v31,  v19
	bic	tmp, sAmu_, sAmo_, ROR #41                  SEP      .inst	0xce385ed6	//bcax_m0 v22, v22, v24, v23
	eor	sAmi, tmp,  sAmi_, ROR #46                  SEP      eor2    v27,  v27,  v20
	bic	tmp, sAma_, sAmu_, ROR #35                  SEP      bcax_m1 v23, v23, v0, v24
	ldr	cur_const, [const_addr, count, UXTW #3]     SEP      eor2    v28,  v28,  v21
	add	count, count, #1                            SEP
	eor	sAmo, tmp,  sAmo_, ROR #12                  SEP      .inst	0xce210318	//bcax_m0 v24, v24, v1, v0
	bic	tmp, sAme_, sAma_, ROR #9                   SEP      eor2    v29,  v29,  v22
	eor	sAmu, tmp,  sAmu_, ROR #44                  SEP      eor2    v30,  v30,  v23
	bic	tmp, sAsi_, sAse_, ROR #48                  SEP      bcax_m1 v0, v25, v2, v26
	eor	sAsa, tmp,  sAsa_, ROR #41                  SEP      .inst	0xce230b41	//bcax_m0 v1, v26, v3, v2
	bic	tmp, sAso_, sAsi_, ROR #2                   SEP
	save	count, STACK_OFFSET_COUNT                  SEP
	eor	sAse, tmp,  sAse_, ROR #50                  SEP      eor2    v28,  v28,  v1
	bic	tmp, sAsu_, sAso_, ROR #25                  SEP      restore x27, STACK_OFFSET_CONST
	eor	sAsi, tmp,  sAsi_, ROR #27                  SEP      ldr vvtmpq, [x27], #16
	bic	tmp, sAsa_, sAsu_, ROR #60                  SEP      save x27, STACK_OFFSET_CONST
	eor	sAso, tmp,  sAso_, ROR #21                  SEP      eor v0.16b, v0.16b, vvtmp.16b
	bic	tmp, sAse_, sAsa_, ROR #57                  SEP      eor2    v31,  v31,  v24
	eor	sAsu, tmp,  sAsu_, ROR #53                  SEP
	bic	tmp, sAbi_, sAbe_, ROR #63                  SEP      .inst	0xce240c42	//bcax_m0 v2, v2, v4, v3
	eor	s_Aba, s_Aba_, tmp,  ROR #21                SEP      bcax_m1 v3, v3, v25, v4
	bic	tmp, sAbo_, sAbi_, ROR #42                  SEP      eor2    v30,  v30,  v3
	eor	sAbe, tmp,  sAbe_, ROR #41                  SEP      eor2    v29,  v29,  v2
	bic	tmp, sAbu_, sAbo_, ROR #57                  SEP      eor2    v27,  v27,  v0
	eor	sAbi, tmp,  sAbi_, ROR #35                  SEP
	bic	tmp, s_Aba_, sAbu_, ROR #50                 SEP      .inst	0xce3a6484	//bcax_m0 v4, v4, v26, v25
	eor	sAbo, tmp,  sAbo_, ROR #43                  SEP      eor2    v31,  v31,  v4
	bic	tmp, sAbe_, s_Aba_, ROR #44                 SEP      ldr q5, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
	eor	sAbu, tmp,  sAbu_, ROR #30                  SEP      .unreq vvtmp
	eor	s_Aba, s_Aba, cur_const                     SEP      .unreq vvtmpq
	eor	sC0, sAka, sAsa, ROR #50                    SEP      vvtmp .req v25
	eor	sC1, sAse, sAge, ROR #60                    SEP      .inst	0xce7e8f9a	//rax1_m0 v26, v28, v30
	eor	sC2, sAmi, sAgi, ROR #59                    SEP      rax1_m1 v30, v30, v27
	eor	sC3, sAgo, sAso, ROR #30                    SEP      .inst	0xce7d8f7b	//rax1_m0 v27, v27, v29
	eor	sC4, sAbu, sAsu, ROR #53                    SEP      rax1_m1 v29, v29, v31
	eor	sC0, sAma, sC0, ROR #49                     SEP      .inst	0xce7c8fff	//rax1_m0 v31, v31, v28
	eor	sC1, sAbe, sC1, ROR #44                     SEP
	eor	sC2, sAki, sC2, ROR #26                     SEP      .unreq vvtmp
	eor	sC3, sAmo, sC3, ROR #63                     SEP      vvtmp .req v28
	eor	sC4, sAmu, sC4, ROR #56                     SEP      vvtmpq .req  q28
	eor	sC0, sAga, sC0, ROR #57                     SEP      eor v25.16b, v0.16b, v31.16b
	eor	sC1, sAme, sC1, ROR #58                     SEP      xar_m1 v0, v2, v26, 2
	eor	sC2, sAbi, sC2, ROR #60                     SEP
	eor	sC3, sAko, sC3, ROR #38                     SEP      xar_m1 v2, v12, v26, 21
	eor	sC4, sAgu, sC4, ROR #48                     SEP      xar_m1 v12, v13, v29, 39
	eor	sC0, s_Aba, sC0, ROR #61                    SEP      xar_m1 v13, v19, v30, 56
	eor	sC1, sAke, sC1, ROR #57                     SEP      xar_m1 v19, v23, v29, 8
	eor	sC2, sAsi, sC2, ROR #52                     SEP      xar_m1 v23, v15, v31, 23
	eor	sC3, sAbo, sC3, ROR #63                     SEP      xar_m1 v15, v1, v27, 63
	eor	sC4, sAku, sC4, ROR #50                     SEP
	ror	sC1, sC1, 56                                SEP      xar_m1 v1, v8, v29, 9
	ror	sC4, sC4, 58                                SEP      xar_m1 v8, v16, v27, 19
	ror	sC2, sC2, 62                                SEP      xar_m1 v16, v7, v26, 58
	eor	sE1, sC0, sC2, ROR #63                      SEP      xar_m1 v7, v10, v31, 61
	eor	sE3, sC2, sC4, ROR #63                      SEP      xar_m1 v10, v3, v29, 36
	eor	sE0, sC4, sC1, ROR #63                      SEP
	eor	sE2, sC1, sC3, ROR #63                      SEP      xar_m1 v3, v18, v29, 43
	eor	sE4, sC3, sC0, ROR #63                      SEP      xar_m1 v18, v17, v26, 49
	eor	s_Aba_, sE0, s_Aba                          SEP      xar_m1 v17, v11, v27, 54
	eor	sAsa_, sE2, sAbi, ROR #50                   SEP      xar_m1 v11, v9, v30, 44
	eor	sAbi_, sE2, sAki, ROR #46                   SEP      mov v29.16b, v5.16b
	eor	sAki_, sE3, sAko, ROR #63                   SEP      bcax_m1 v5, v10, v7, v11
	eor	sAko_, sE4, sAmu, ROR #28                   SEP
	eor	sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 v9, v22, v26, 3
	eor	sAso_, sE0, sAma, ROR #54                   SEP      xar_m1 v22, v14, v30, 25
	eor	sAka_, sE1, sAbe, ROR #43                   SEP      xar_m1 v14, v20, v31, 46
	eor	sAse_, sE3, sAgo, ROR #36                   SEP      xar_m1 v20, v4, v30, 37
	eor	sAgo_, sE1, sAme, ROR #49                   SEP      xar_m1 v4, v24, v30, 50
	eor	sAke_, sE2, sAgi, ROR #3                    SEP
	eor	sAgi_, sE0, sAka, ROR #39                   SEP      xar_m1 v24, v21, v27, 62
	eor	sAga_, sE3, sAbo                            SEP      xar_m1 v21, v29, v31, 28
	eor	sAbo_, sE3, sAmo, ROR #37                   SEP      xar_m1 v26, v6, v27, 20
	eor	sAmo_, sE2, sAmi, ROR #8                    SEP      bcax_m1 v6, v11, v8, v7
	eor	sAmi_, sE1, sAke, ROR #56                   SEP      .inst	0xce2920e7	//bcax_m0 v7, v7, v9, v8
	eor	sAge_, sE4, sAgu, ROR #44                   SEP
	eor	sAgu_, sE2, sAsi, ROR #62                   SEP      bcax_m1 v8, v8, v10, v9
	eor	sAsi_, sE4, sAku, ROR #58                   SEP      .inst	0xce2b2929	//bcax_m0 v9, v9, v11, v10
	eor	sAku_, sE0, sAsa, ROR #25                   SEP      bcax_m1 v10, v15, v12, v16
	eor	sAma_, sE4, sAbu, ROR #20                   SEP      .inst	0xce2d320b	//bcax_m0 v11, v16, v13, v12
	eor	sAbu_, sE4, sAsu, ROR #9                    SEP      .unreq vvtmp
	eor	sAsu_, sE1, sAse, ROR #23                   SEP      .unreq vvtmpq
	eor	sAme_, sE0, sAga, ROR #61                   SEP
	eor	sAbe_, sE1, sAge, ROR #19                   SEP      eor2    v27,  v10, v5
	load_constant_ptr	SEP      str q5, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
	restore	count, STACK_OFFSET_COUNT               SEP      vvtmp .req v5
	bic	tmp, sAgi_, sAge_, ROR #47                  SEP      vvtmpq .req q5
	eor	sAga, tmp,  sAga_, ROR #39                  SEP      bcax_m1 v12, v12, v14, v13
	bic	tmp, sAgo_, sAgi_, ROR #42                  SEP
	eor	sAge, tmp,  sAge_, ROR #25                  SEP      bcax_m1 v13, v13, v15, v14
	bic	tmp, sAgu_, sAgo_, ROR #16                  SEP      eor2    v28,  v11, v6
	eor	sAgi, tmp,  sAgi_, ROR #58                  SEP      .inst	0xce303dce	//bcax_m0 v14, v14, v16, v15
	bic	tmp, sAga_, sAgu_, ROR #31                  SEP      eor2    v29,  v12, v7
	eor	sAgo, tmp,  sAgo_, ROR #47                  SEP      bcax_m1 v15, v20, v17, v21
	bic	tmp, sAge_, sAga_, ROR #56                  SEP      eor2    v30,  v13, v8
	eor	sAgu, tmp,  sAgu_, ROR #23                  SEP
	bic	tmp, sAki_, sAke_, ROR #19                  SEP      .inst	0xce3246b0	//bcax_m0 v16, v21, v18, v17
	eor	sAka, tmp,  sAka_, ROR #24                  SEP      eor2    v31,  v14, v9
	bic	tmp, sAko_, sAki_, ROR #47                  SEP      bcax_m1 v17, v17, v19, v18
	eor	sAke, tmp,  sAke_, ROR #2                   SEP      eor2    v27,  v27,  v15
	bic	tmp, sAku_, sAko_, ROR #10                  SEP      .inst	0xce344e52	//bcax_m0 v18, v18, v20, v19
	eor	sAki, tmp,  sAki_, ROR #57                  SEP
	bic	tmp, sAka_, sAku_, ROR #47                  SEP      eor2    v28,  v28,  v16
	eor	sAko, tmp,  sAko_, ROR #57                  SEP      bcax_m1 v19, v19, v21, v20
	bic	tmp, sAke_, sAka_, ROR #5                   SEP      eor2    v29,  v29,  v17
	eor	sAku, tmp,  sAku_, ROR #52                  SEP      .inst	0xce360414	//bcax_m0 v20, v0, v22, v1
	bic	tmp, sAmi_, sAme_, ROR #38                  SEP      eor2    v30,  v30,  v18
	eor	sAma, tmp,  sAma_, ROR #47                  SEP
	bic	tmp, sAmo_, sAmi_, ROR #5                   SEP      bcax_m1 v21, v1, v23, v22
	eor	sAme, tmp,  sAme_, ROR #43                  SEP      eor2    v31,  v31,  v19
	bic	tmp, sAmu_, sAmo_, ROR #41                  SEP      .inst	0xce385ed6	//bcax_m0 v22, v22, v24, v23
	eor	sAmi, tmp,  sAmi_, ROR #46                  SEP      eor2    v27,  v27,  v20
	bic	tmp, sAma_, sAmu_, ROR #35                  SEP      bcax_m1 v23, v23, v0, v24
	SEP	eor2    v28,  v28,  v21
	eor	sAmo, tmp,  sAmo_, ROR #12                  SEP      .inst	0xce210318	//bcax_m0 v24, v24, v1, v0
	bic	tmp, sAme_, sAma_, ROR #9                   SEP      eor2    v29,  v29,  v22
	eor	sAmu, tmp,  sAmu_, ROR #44                  SEP      eor2    v30,  v30,  v23
	bic	tmp, sAsi_, sAse_, ROR #48                  SEP      bcax_m1 v0, v25, v2, v26
	eor	sAsa, tmp,  sAsa_, ROR #41                  SEP      .inst	0xce230b41	//bcax_m0 v1, v26, v3, v2
	bic	tmp, sAso_, sAsi_, ROR #2                   SEP
	eor	sAse, tmp,  sAse_, ROR #50                  SEP      eor2    v28,  v28,  v1
	bic	tmp, sAsu_, sAso_, ROR #25                  SEP      restore x26, STACK_OFFSET_CONST
	eor	sAsi, tmp,  sAsi_, ROR #27                  SEP      ldr vvtmpq, [x26], #16
	bic	tmp, sAsa_, sAsu_, ROR #60                  SEP      save x26, STACK_OFFSET_CONST
	eor	sAso, tmp,  sAso_, ROR #21                  SEP      eor v0.16b, v0.16b, vvtmp.16b
	bic	tmp, sAse_, sAsa_, ROR #57                  SEP      eor2    v31,  v31,  v24
	eor	sAsu, tmp,  sAsu_, ROR #53                  SEP
	ldr	cur_const, [const_addr, count, UXTW #3]     SEP
	add	count, count, #1                            SEP
	bic	tmp, sAbi_, sAbe_, ROR #63                  SEP      .inst	0xce240c42	//bcax_m0 v2, v2, v4, v3
	eor	s_Aba, s_Aba_, tmp,  ROR #21                SEP      bcax_m1 v3, v3, v25, v4
	bic	tmp, sAbo_, sAbi_, ROR #42                  SEP      eor2    v30,  v30,  v3
	eor	sAbe, tmp,  sAbe_, ROR #41                  SEP      eor2    v29,  v29,  v2
	bic	tmp, sAbu_, sAbo_, ROR #57                  SEP      eor2    v27,  v27,  v0
	eor	sAbi, tmp,  sAbi_, ROR #35                  SEP
	bic	tmp, s_Aba_, sAbu_, ROR #50                 SEP      .inst	0xce3a6484	//bcax_m0 v4, v4, v26, v25
	eor	sAbo, tmp,  sAbo_, ROR #43                  SEP      eor2    v31,  v31,  v4
	bic	tmp, sAbe_, s_Aba_, ROR #44                 SEP      ldr q5, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
	eor	sAbu, tmp,  sAbu_, ROR #30                  SEP      .unreq vvtmp
	eor	s_Aba, s_Aba, cur_const                     SEP      .unreq vvtmpq
.endm


.macro	hybrid_round_final
	save	count, STACK_OFFSET_COUNT                  SEP
	eor	sC0, sAka, sAsa, ROR #50                    SEP      vvtmp .req v25
	eor	sC1, sAse, sAge, ROR #60                    SEP      .inst	0xce7e8f9a	//rax1_m0 v26, v28, v30
	eor	sC2, sAmi, sAgi, ROR #59                    SEP
	eor	sC3, sAgo, sAso, ROR #30                    SEP      rax1_m1 v30, v30, v27
	eor	sC4, sAbu, sAsu, ROR #53                    SEP      .inst	0xce7d8f7b	//rax1_m0 v27, v27, v29
	eor	sC0, sAma, sC0, ROR #49                     SEP
	eor	sC1, sAbe, sC1, ROR #44                     SEP      rax1_m1 v29, v29, v31
	eor	sC2, sAki, sC2, ROR #26                     SEP      .inst	0xce7c8fff	//rax1_m0 v31, v31, v28
	eor	sC3, sAmo, sC3, ROR #63                     SEP
	eor	sC4, sAmu, sC4, ROR #56                     SEP      .unreq vvtmp
	eor	sC0, sAga, sC0, ROR #57                     SEP      vvtmp .req v28
	eor	sC1, sAme, sC1, ROR #58                     SEP
	eor	sC2, sAbi, sC2, ROR #60                     SEP      vvtmpq .req  q28
	eor	sC3, sAko, sC3, ROR #38                     SEP      eor v25.16b, v0.16b, v31.16b
	eor	sC4, sAgu, sC4, ROR #48                     SEP
	eor	sC0, s_Aba, sC0, ROR #61                    SEP      xar_m1 v0, v2, v26, 2
	eor	sC1, sAke, sC1, ROR #57                     SEP      xar_m1 v2, v12, v26, 21
	eor	sC2, sAsi, sC2, ROR #52                     SEP
	eor	sC3, sAbo, sC3, ROR #63                     SEP      xar_m1 v12, v13, v29, 39
	eor	sC4, sAku, sC4, ROR #50                     SEP      xar_m1 v13, v19, v30, 56
	ror	sC1, sC1, 56                                SEP
	ror	sC4, sC4, 58                                SEP      xar_m1 v19, v23, v29, 8
	ror	sC2, sC2, 62                                SEP      xar_m1 v23, v15, v31, 23
	eor	sE1, sC0, sC2, ROR #63                      SEP
	eor	sE3, sC2, sC4, ROR #63                      SEP      xar_m1 v15, v1, v27, 63
	eor	sE0, sC4, sC1, ROR #63                      SEP      xar_m1 v1, v8, v29, 9
	eor	sE2, sC1, sC3, ROR #63                      SEP
	eor	sE4, sC3, sC0, ROR #63                      SEP      xar_m1 v8, v16, v27, 19
	eor	s_Aba_, sE0, s_Aba                          SEP      xar_m1 v16, v7, v26, 58
	eor	sAsa_, sE2, sAbi, ROR #50                   SEP
	eor	sAbi_, sE2, sAki, ROR #46                   SEP      xar_m1 v7, v10, v31, 61
	eor	sAki_, sE3, sAko, ROR #63                   SEP
	eor	sAko_, sE4, sAmu, ROR #28                   SEP      xar_m1 v10, v3, v29, 36
	eor	sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 v3, v18, v29, 43
	eor	sAso_, sE0, sAma, ROR #54                   SEP
	eor	sAka_, sE1, sAbe, ROR #43                   SEP      xar_m1 v18, v17, v26, 49
	eor	sAse_, sE3, sAgo, ROR #36                   SEP      xar_m1 v17, v11, v27, 54
	eor	sAgo_, sE1, sAme, ROR #49                   SEP
	eor	sAke_, sE2, sAgi, ROR #3                    SEP      xar_m1 v11, v9, v30, 44
	eor	sAgi_, sE0, sAka, ROR #39                   SEP      mov v29.16b, v5.16b
	eor	sAga_, sE3, sAbo                            SEP
	eor	sAbo_, sE3, sAmo, ROR #37                   SEP      bcax_m1 v5, v10, v7, v11
	eor	sAmo_, sE2, sAmi, ROR #8                    SEP      xar_m1 v9, v22, v26, 3
	eor	sAmi_, sE1, sAke, ROR #56                   SEP
	eor	sAge_, sE4, sAgu, ROR #44                   SEP      xar_m1 v22, v14, v30, 25
	eor	sAgu_, sE2, sAsi, ROR #62                   SEP      xar_m1 v14, v20, v31, 46
	eor	sAsi_, sE4, sAku, ROR #58                   SEP
	eor	sAku_, sE0, sAsa, ROR #25                   SEP      xar_m1 v20, v4, v30, 37
	eor	sAma_, sE4, sAbu, ROR #20                   SEP      xar_m1 v4, v24, v30, 50
	eor	sAbu_, sE4, sAsu, ROR #9                    SEP
	eor	sAsu_, sE1, sAse, ROR #23                   SEP      xar_m1 v24, v21, v27, 62
	eor	sAme_, sE0, sAga, ROR #61                   SEP      xar_m1 v21, v29, v31, 28
	eor	sAbe_, sE1, sAge, ROR #19                   SEP
	load_constant_ptr	SEP      xar_m1 v26, v6, v27, 20
	restore	count, STACK_OFFSET_COUNT               SEP      bcax_m1 v6, v11, v8, v7
	bic	tmp, sAgi_, sAge_, ROR #47                  SEP
	eor	sAga, tmp,  sAga_, ROR #39                  SEP      .inst	0xce2920e7	//bcax_m0 v7, v7, v9, v8
	bic	tmp, sAgo_, sAgi_, ROR #42                  SEP      bcax_m1 v8, v8, v10, v9
	eor	sAge, tmp,  sAge_, ROR #25                  SEP
	bic	tmp, sAgu_, sAgo_, ROR #16                  SEP      .inst	0xce2b2929	//bcax_m0 v9, v9, v11, v10
	eor	sAgi, tmp,  sAgi_, ROR #58                  SEP
	bic	tmp, sAga_, sAgu_, ROR #31                  SEP      bcax_m1 v10, v15, v12, v16
	eor	sAgo, tmp,  sAgo_, ROR #47                  SEP      .inst	0xce2d320b	//bcax_m0 v11, v16, v13, v12
	bic	tmp, sAge_, sAga_, ROR #56                  SEP
	eor	sAgu, tmp,  sAgu_, ROR #23                  SEP      .unreq vvtmp
	bic	tmp, sAki_, sAke_, ROR #19                  SEP      .unreq vvtmpq
	eor	sAka, tmp,  sAka_, ROR #24                  SEP
	bic	tmp, sAko_, sAki_, ROR #47                  SEP      eor2    v27,  v10, v5
	eor	sAke, tmp,  sAke_, ROR #2                   SEP      str q5, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
	bic	tmp, sAku_, sAko_, ROR #10                  SEP
	eor	sAki, tmp,  sAki_, ROR #57                  SEP      vvtmp .req v5
	bic	tmp, sAka_, sAku_, ROR #47                  SEP      vvtmpq .req q5
	eor	sAko, tmp,  sAko_, ROR #57                  SEP
	bic	tmp, sAke_, sAka_, ROR #5                   SEP      .inst	0xce2e358c	//bcax_m0 v12, v12, v14, v13
	eor	sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m1 v13, v13, v15, v14
	bic	tmp, sAmi_, sAme_, ROR #38                  SEP
	eor	sAma, tmp,  sAma_, ROR #47                  SEP      eor2    v28,  v11, v6
	bic	tmp, sAmo_, sAmi_, ROR #5                   SEP      .inst	0xce303dce	//bcax_m0 v14, v14, v16, v15
	eor	sAme, tmp,  sAme_, ROR #43                  SEP
	bic	tmp, sAmu_, sAmo_, ROR #41                  SEP      eor2    v29,  v12, v7
	eor	sAmi, tmp,  sAmi_, ROR #46                  SEP      bcax_m1 v15, v20, v17, v21
	bic	tmp, sAma_, sAmu_, ROR #35                  SEP
	ldr	cur_const, [const_addr, count, UXTW #3]     SEP      eor2    v30,  v13, v8
	add	count, count, #1                            SEP      .inst	0xce3246b0	//bcax_m0 v16, v21, v18, v17
	eor	sAmo, tmp,  sAmo_, ROR #12                  SEP
	bic	tmp, sAme_, sAma_, ROR #9                   SEP      eor2    v31,  v14, v9
	eor	sAmu, tmp,  sAmu_, ROR #44                  SEP      bcax_m1 v17, v17, v19, v18
	bic	tmp, sAsi_, sAse_, ROR #48                  SEP
	eor	sAsa, tmp,  sAsa_, ROR #41                  SEP      eor2    v27,  v27,  v15
	bic	tmp, sAso_, sAsi_, ROR #2                   SEP      .inst	0xce344e52	//bcax_m0 v18, v18, v20, v19
	eor	sAse, tmp,  sAse_, ROR #50                  SEP
	bic	tmp, sAsu_, sAso_, ROR #25                  SEP      eor2    v28,  v28,  v16
	eor	sAsi, tmp,  sAsi_, ROR #27                  SEP
	bic	tmp, sAsa_, sAsu_, ROR #60                  SEP      bcax_m1 v19, v19, v21, v20
	eor	sAso, tmp,  sAso_, ROR #21                  SEP      eor2    v29,  v29,  v17
	bic	tmp, sAse_, sAsa_, ROR #57                  SEP
	eor	sAsu, tmp,  sAsu_, ROR #53                  SEP      .inst	0xce360414	//bcax_m0 v20, v0, v22, v1
	bic	tmp, sAbi_, sAbe_, ROR #63                  SEP      eor2    v30,  v30,  v18
	eor	s_Aba, s_Aba_, tmp,  ROR #21                SEP
	bic	tmp, sAbo_, sAbi_, ROR #42                  SEP      bcax_m1 v21, v1, v23, v22
	eor	sAbe, tmp,  sAbe_, ROR #41                  SEP      eor2    v31,  v31,  v19
	bic	tmp, sAbu_, sAbo_, ROR #57                  SEP
	eor	sAbi, tmp,  sAbi_, ROR #35                  SEP      .inst	0xce385ed6	//bcax_m0 v22, v22, v24, v23
	bic	tmp, s_Aba_, sAbu_, ROR #50                 SEP      eor2    v27,  v27,  v20
	eor	sAbo, tmp,  sAbo_, ROR #43                  SEP
	bic	tmp, sAbe_, s_Aba_, ROR #44                 SEP      bcax_m1 v23, v23, v0, v24
	eor	sAbu, tmp,  sAbu_, ROR #30                  SEP      eor2    v28,  v28,  v21
	eor	s_Aba, s_Aba, cur_const                     SEP
	save	count, STACK_OFFSET_COUNT                  SEP      .inst	0xce210318	//bcax_m0 v24, v24, v1, v0
	eor	sC0, sAka, sAsa, ROR #50                    SEP      eor2    v29,  v29,  v22
	eor	sC1, sAse, sAge, ROR #60                    SEP
	eor	sC2, sAmi, sAgi, ROR #59                    SEP      eor2    v30,  v30,  v23
	eor	sC3, sAgo, sAso, ROR #30                    SEP      bcax_m1 v0, v25, v2, v26
	eor	sC4, sAbu, sAsu, ROR #53                    SEP
	eor	sC0, sAma, sC0, ROR #49                     SEP      .inst	0xce230b41	//bcax_m0 v1, v26, v3, v2
	eor	sC1, sAbe, sC1, ROR #44                     SEP      eor2    v28,  v28,  v1
	eor	sC2, sAki, sC2, ROR #26                     SEP
	eor	sC3, sAmo, sC3, ROR #63                     SEP      restore x30, STACK_OFFSET_CONST
	eor	sC4, sAmu, sC4, ROR #56                     SEP      ldr vvtmpq, [x30], #16
	eor	sC0, sAga, sC0, ROR #57                     SEP
	eor	sC1, sAme, sC1, ROR #58                     SEP      save x30, STACK_OFFSET_CONST
	eor	sC2, sAbi, sC2, ROR #60                     SEP
	eor	sC3, sAko, sC3, ROR #38                     SEP      eor v0.16b, v0.16b, vvtmp.16b
	eor	sC4, sAgu, sC4, ROR #48                     SEP      eor2    v31,  v31,  v24
	eor	sC0, s_Aba, sC0, ROR #61                    SEP
	eor	sC1, sAke, sC1, ROR #57                     SEP      .inst	0xce240c42	//bcax_m0 v2, v2, v4, v3
	eor	sC2, sAsi, sC2, ROR #52                     SEP      bcax_m1 v3, v3, v25, v4
	eor	sC3, sAbo, sC3, ROR #63                     SEP
	eor	sC4, sAku, sC4, ROR #50                     SEP      eor2    v30,  v30,  v3
	ror	sC1, sC1, 56                                SEP      eor2    v29,  v29,  v2
	ror	sC4, sC4, 58                                SEP
	ror	sC2, sC2, 62                                SEP      eor2    v27,  v27,  v0
	eor	sE1, sC0, sC2, ROR #63                      SEP      .inst	0xce3a6484	//bcax_m0 v4, v4, v26, v25
	eor	sE3, sC2, sC4, ROR #63                      SEP
	eor	sE0, sC4, sC1, ROR #63                      SEP      eor2    v31,  v31,  v4
	eor	sE2, sC1, sC3, ROR #63                      SEP      ldr q5, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
	eor	sE4, sC3, sC0, ROR #63                      SEP
	eor	s_Aba_, sE0, s_Aba                          SEP      .unreq vvtmp
	eor	sAsa_, sE2, sAbi, ROR #50                   SEP      .unreq vvtmpq
	eor	sAbi_, sE2, sAki, ROR #46                   SEP
	eor	sAki_, sE3, sAko, ROR #63                   SEP      vvtmp .req v25
	eor	sAko_, sE4, sAmu, ROR #28                   SEP      .inst	0xce7e8f9a	//rax1_m0 v26, v28, v30
	eor	sAmu_, sE3, sAso, ROR #2                    SEP
	eor	sAso_, sE0, sAma, ROR #54                   SEP      rax1_m1 v30, v30, v27
	eor	sAka_, sE1, sAbe, ROR #43                   SEP      .inst	0xce7d8f7b	//rax1_m0 v27, v27, v29
	eor	sAse_, sE3, sAgo, ROR #36                   SEP
	eor	sAgo_, sE1, sAme, ROR #49                   SEP      rax1_m1 v29, v29, v31
	eor	sAke_, sE2, sAgi, ROR #3                    SEP      .inst	0xce7c8fff	//rax1_m0 v31, v31, v28
	eor	sAgi_, sE0, sAka, ROR #39                   SEP
	eor	sAga_, sE3, sAbo                            SEP      .unreq vvtmp
	eor	sAbo_, sE3, sAmo, ROR #37                   SEP
	eor	sAmo_, sE2, sAmi, ROR #8                    SEP      vvtmp .req v28
	eor	sAmi_, sE1, sAke, ROR #56                   SEP      vvtmpq .req  q28
	eor	sAge_, sE4, sAgu, ROR #44                   SEP
	eor	sAgu_, sE2, sAsi, ROR #62                   SEP      eor v25.16b, v0.16b, v31.16b
	eor	sAsi_, sE4, sAku, ROR #58                   SEP      xar_m1 v0, v2, v26, 2
	eor	sAku_, sE0, sAsa, ROR #25                   SEP
	eor	sAma_, sE4, sAbu, ROR #20                   SEP      xar_m1 v2, v12, v26, 21
	eor	sAbu_, sE4, sAsu, ROR #9                    SEP      xar_m1 v12, v13, v29, 39
	eor	sAsu_, sE1, sAse, ROR #23                   SEP
	eor	sAme_, sE0, sAga, ROR #61                   SEP      xar_m1 v13, v19, v30, 56
	eor	sAbe_, sE1, sAge, ROR #19                   SEP      xar_m1 v19, v23, v29, 8
	load_constant_ptr	SEP
	restore	count, STACK_OFFSET_COUNT               SEP      xar_m1 v23, v15, v31, 23
	bic	tmp, sAgi_, sAge_, ROR #47                  SEP      xar_m1 v15, v1, v27, 63
	eor	sAga, tmp,  sAga_, ROR #39                  SEP
	bic	tmp, sAgo_, sAgi_, ROR #42                  SEP      xar_m1 v1, v8, v29, 9
	eor	sAge, tmp,  sAge_, ROR #25                  SEP      xar_m1 v8, v16, v27, 19
	bic	tmp, sAgu_, sAgo_, ROR #16                  SEP
	eor	sAgi, tmp,  sAgi_, ROR #58                  SEP      xar_m1 v16, v7, v26, 58
	bic	tmp, sAga_, sAgu_, ROR #31                  SEP      xar_m1 v7, v10, v31, 61
	eor	sAgo, tmp,  sAgo_, ROR #47                  SEP
	bic	tmp, sAge_, sAga_, ROR #56                  SEP      xar_m1 v10, v3, v29, 36
	eor	sAgu, tmp,  sAgu_, ROR #23                  SEP      xar_m1 v3, v18, v29, 43
	bic	tmp, sAki_, sAke_, ROR #19                  SEP
	eor	sAka, tmp,  sAka_, ROR #24                  SEP      xar_m1 v18, v17, v26, 49
	bic	tmp, sAko_, sAki_, ROR #47                  SEP      xar_m1 v17, v11, v27, 54
	eor	sAke, tmp,  sAke_, ROR #2                   SEP
	bic	tmp, sAku_, sAko_, ROR #10                  SEP      xar_m1 v11, v9, v30, 44
	eor	sAki, tmp,  sAki_, ROR #57                  SEP      mov v29.16b, v5.16b
	bic	tmp, sAka_, sAku_, ROR #47                  SEP
	eor	sAko, tmp,  sAko_, ROR #57                  SEP      bcax_m1 v5, v10, v7, v11
	bic	tmp, sAke_, sAka_, ROR #5                   SEP
	eor	sAku, tmp,  sAku_, ROR #52                  SEP      xar_m1 v9, v22, v26, 3
	bic	tmp, sAmi_, sAme_, ROR #38                  SEP      xar_m1 v22, v14, v30, 25
	eor	sAma, tmp,  sAma_, ROR #47                  SEP
	bic	tmp, sAmo_, sAmi_, ROR #5                   SEP      xar_m1 v14, v20, v31, 46
	eor	sAme, tmp,  sAme_, ROR #43                  SEP      xar_m1 v20, v4, v30, 37
	bic	tmp, sAmu_, sAmo_, ROR #41                  SEP
	eor	sAmi, tmp,  sAmi_, ROR #46                  SEP      xar_m1 v4, v24, v30, 50
	bic	tmp, sAma_, sAmu_, ROR #35                  SEP      xar_m1 v24, v21, v27, 62
	ldr	cur_const, [const_addr, count, UXTW #3]     SEP
	add	count, count, #1                            SEP      .inst	0xce9f73b5	//xar v21, v29, v31, #28
	eor	sAmo, tmp,  sAmo_, ROR #12                  SEP      xar_m1 v26, v6, v27, 20
	bic	tmp, sAme_, sAma_, ROR #9                   SEP
	eor	sAmu, tmp,  sAmu_, ROR #44                  SEP      .inst	0xce281d66	//bcax_m0 v6, v11, v8, v7
	bic	tmp, sAsi_, sAse_, ROR #48                  SEP      bcax_m1 v7, v7, v9, v8
	eor	sAsa, tmp,  sAsa_, ROR #41                  SEP
	bic	tmp, sAso_, sAsi_, ROR #2                   SEP      .inst	0xce2a2508	//bcax_m0 v8, v8, v10, v9
	eor	sAse, tmp,  sAse_, ROR #50                  SEP      bcax_m1 v9, v9, v11, v10
	bic	tmp, sAsu_, sAso_, ROR #25                  SEP
	eor	sAsi, tmp,  sAsi_, ROR #27                  SEP      .inst	0xce2c41ea	//bcax_m0 v10, v15, v12, v16
	bic	tmp, sAsa_, sAsu_, ROR #60                  SEP      bcax_m1 v11, v16, v13, v12
	eor	sAso, tmp,  sAso_, ROR #21                  SEP
	bic	tmp, sAse_, sAsa_, ROR #57                  SEP      .inst	0xce2e358c	//bcax_m0 v12, v12, v14, v13
	eor	sAsu, tmp,  sAsu_, ROR #53                  SEP      bcax_m1 v13, v13, v15, v14
	bic	tmp, sAbi_, sAbe_, ROR #63                  SEP
	eor	s_Aba, s_Aba_, tmp,  ROR #21                SEP      .inst	0xce303dce	//bcax_m0 v14, v14, v16, v15
	bic	tmp, sAbo_, sAbi_, ROR #42                  SEP      bcax_m1 v15, v20, v17, v21
	eor	sAbe, tmp,  sAbe_, ROR #41                  SEP
	bic	tmp, sAbu_, sAbo_, ROR #57                  SEP      .inst	0xce3246b0	//bcax_m0 v16, v21, v18, v17
	eor	sAbi, tmp,  sAbi_, ROR #35                  SEP
	bic	tmp, s_Aba_, sAbu_, ROR #50                 SEP      bcax_m1 v17, v17, v19, v18
	eor	sAbo, tmp,  sAbo_, ROR #43                  SEP      .inst	0xce344e52	//bcax_m0 v18, v18, v20, v19
	bic	tmp, sAbe_, s_Aba_, ROR #44                 SEP
	eor	sAbu, tmp,  sAbu_, ROR #30                  SEP      bcax_m1 v19, v19, v21, v20
	eor	s_Aba, s_Aba, cur_const                     SEP      .inst	0xce360414	//bcax_m0 v20, v0, v22, v1
	ror	sAga, sAga,(64-3)                           SEP
	ror	sAka, sAka,(64-25)                          SEP      bcax_m1 v21, v1, v23, v22
	ror	sAma, sAma,(64-10)                          SEP      .inst	0xce385ed6	//bcax_m0 v22, v22, v24, v23
	ror	sAsa, sAsa,(64-39)                          SEP
	ror	sAbe, sAbe,(64-21)                          SEP      bcax_m1 v23, v23, v0, v24
	ror	sAge, sAge,(64-45)                          SEP      .inst	0xce210318	//bcax_m0 v24, v24, v1, v0
	ror	sAke, sAke,(64-8)                           SEP
	ror	sAme, sAme,(64-15)                          SEP      bcax_m1 v0, v25, v2, v26
	ror	sAse, sAse,(64-41)                          SEP      .inst	0xce230b41	//bcax_m0 v1, v26, v3, v2
	ror	sAbi, sAbi,(64-14)                          SEP
	ror	sAgi, sAgi,(64-61)                          SEP      bcax_m1 v2, v2, v4, v3
	ror	sAki, sAki,(64-18)                          SEP      .inst	0xce391063	//bcax_m0 v3, v3, v25, v4
	ror	sAmi, sAmi,(64-56)                          SEP
	ror	sAsi, sAsi,(64-2)                           SEP      bcax_m1 v4, v4, v26, v25
	ror	sAgo, sAgo,(64-28)                          SEP
	ror	sAko, sAko,(64-1)                           SEP
	ror	sAmo, sAmo,(64-27)                          SEP      restore x26, STACK_OFFSET_CONST
	ror	sAso, sAso,(64-62)                          SEP      ldr vvtmpq, [x26], #16
	ror	sAbu, sAbu,(64-44)                          SEP
	ror	sAgu, sAgu,(64-20)                          SEP      save x26, STACK_OFFSET_CONST
	ror	sAku, sAku,(64-6)                           SEP      eor v0.16b, v0.16b, vvtmp.16b
	SEP	//movi v0.4s, #0
	SEP	//movi v1.4s, #1
	SEP	//.inst	0xce800020	//xar v0.2d, v1.2d, v0.2d, 2
	SEP	//.inst	0xce800000	//xar v0.2d, v0.2d, v0.2d, 2
	SEP	//movi v24.4s, #0

	SEP	//.inst	0xce9a0040	//xar v0, v2, v26, 2
	ror	sAmu, sAmu,(64-36)                          SEP      .unreq vvtmp
	ror	sAsu, sAsu,(64-55)                          SEP      .unreq vvtmpq
.endm

#define KECCAK_F1600_ROUNDS 24

.text
.align	4
.globl	keccak_f1600_x3_hybrid_asm_v6

.globl	_keccak_f1600_x3_hybrid_asm_v6


keccak_f1600_x3_hybrid_asm_v6:
_keccak_f1600_x3_hybrid_asm_v6:
	alloc_stack
	save_gprs
	save_vregs
	save	input_addr, STACK_OFFSET_INPUT


	adr	const_addr, round_constants_vec

	save	const_addr, STACK_OFFSET_CONST
	load_input_vector	1,0

	add	input_addr, input_addr, #16
	load_input_scalar	1,0
	hybrid_round_initial
loop_0:
	hybrid_round_noninitial
	cmp	count, #(KECCAK_F1600_ROUNDS-3)
	ble	loop_0

	hybrid_round_final

	restore	input_addr, STACK_OFFSET_INPUT
	store_input_vector	1,0
	add	input_addr, input_addr, #16
	store_input_scalar	1,0

	restore_vregs
	restore_gprs
	free_stack
	ret
//1100 1110 10 0 11111 000000 11101 10101
.byte	75,101,99,99,97,107,45,49,54,48,48,32,97,98,115,111,114,98,32,97,110,100,32,115,113,117,101,101,122,101,32,102,111,114,32,65,82,77,118,56,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	2
#endif  // !OPENSSL_NO_ASM && defined(__AARCH64EL__) && defined(_WIN32)
#if defined(__ELF__)
// See https://www.airs.com/blog/archives/518.
.section .note.GNU-stack,"",%progbits
#endif
