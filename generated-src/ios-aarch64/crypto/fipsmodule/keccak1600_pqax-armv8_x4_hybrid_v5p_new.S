// This file is generated from a similarly-named Perl script in the BoringSSL
// source tree. Do not edit by hand.

#if !defined(__has_feature)
#define __has_feature(x) 0
#endif
#if __has_feature(memory_sanitizer) && !defined(OPENSSL_NO_ASM)
#define OPENSSL_NO_ASM
#endif

#if !defined(OPENSSL_NO_ASM) && defined(__AARCH64EL__) && defined(__APPLE__)
#if defined(BORINGSSL_PREFIX)
#include <boringssl_prefix_symbols_asm.h>
#endif
#include <openssl/arm_arch.h>
#define SEP ;
.text
.balign	64


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
	out_count	.req w27
	x26	.req x26

	/*	Mapping of Kecck-f1600 SIMD state to vector registers
	*	at the beginning and end of each round. */

	/*	Mapping of Kecck-f1600 state to vector registers
	*	at the beginning and end of each round. */
	vAba	.req v0
	vAbe	.req v1
	vAbi	.req v2
	vAbo	.req v3
	vAbu	.req v4
	vAga	.req v5
	vAge	.req v6
	vAgi	.req v7
	vAgo	.req v8
	vAgu	.req v9
	vAka	.req v10
	vAke	.req v11
	vAki	.req v12
	vAko	.req v13
	vAku	.req v14
	vAma	.req v15
	vAme	.req v16
	vAmi	.req v17
	vAmo	.req v18
	vAmu	.req v19
	vAsa	.req v20
	vAse	.req v21
	vAsi	.req v22
	vAso	.req v23
	vAsu	.req v24


	vAbaq	.req q0
	vAbeq	.req q1
	vAbiq	.req q2
	vAboq	.req q3
	vAbuq	.req q4
	vAgaq	.req q5
	vAgeq	.req q6
	vAgiq	.req q7
	vAgoq	.req q8
	vAguq	.req q9
	vAkaq	.req q10
	vAkeq	.req q11
	vAkiq	.req q12
	vAkoq	.req q13
	vAkuq	.req q14
	vAmaq	.req q15
	vAmeq	.req q16
	vAmiq	.req q17
	vAmoq	.req q18
	vAmuq	.req q19
	vAsaq	.req q20
	vAseq	.req q21
	vAsiq	.req q22
	vAsoq	.req q23
	vAsuq	.req q24


	C0	.req v27
	C1	.req v28
	C2	.req v29
	C3	.req v30
	C4	.req v31

	C0q	.req q27
	C1q	.req q28
	C2q	.req q29
	C3q	.req q30
	C4q	.req q31


	vBba	.req v25 // fresh
	vBbe	.req v26 // fresh
	vBbi	.req vAbi
	vBbo	.req vAbo
	vBbu	.req vAbu
	vBga	.req vAka
	vBge	.req vAke
	vBgi	.req vAgi
	vBgo	.req vAgo
	vBgu	.req vAgu
	vBka	.req vAma
	vBke	.req vAme
	vBki	.req vAki
	vBko	.req vAko
	vBku	.req vAku
	vBma	.req vAsa
	vBme	.req vAse
	vBmi	.req vAmi
	vBmo	.req vAmo
	vBmu	.req vAmu
	vBsa	.req vAba
	vBse	.req vAbe
	vBsi	.req vAsi
	vBso	.req vAso
	vBsu	.req vAsu

	vBbaq	.req q25 // fresh
	vBbeq	.req q26 // fresh
	vBbiq	.req vAbiq
	vBboq	.req vAboq
	vBbuq	.req vAbuq
	vBgaq	.req vAkaq
	vBgeq	.req vAkeq
	vBgiq	.req vAgiq
	vBgoq	.req vAgoq
	vBguq	.req vAguq
	vBkaq	.req vAmaq
	vBkeq	.req vAmeq
	vBkiq	.req vAkiq
	vBkoq	.req vAkoq
	vBkuq	.req vAkuq
	vBmaq	.req vAsaq
	vBmeq	.req vAseq
	vBmiq	.req vAmiq
	vBmoq	.req vAmoq
	vBmuq	.req vAmuq
	vBsaq	.req vAbaq
	vBseq	.req vAbeq
	vBsiq	.req vAsiq
	vBsoq	.req vAsoq
	vBsuq	.req vAsuq


	E0	.req C4
	E1	.req C0
	E2	.req vBbe // fresh
	E3	.req C2
	E4	.req C3

	E0q	.req C4q
	E1q	.req C0q
	E2q	.req vBbeq // fresh
	E3q	.req C2q
	E4q	.req C3q

	tmp	.req x30





.macro	load_constant_ptr_stack
	ldr	x26, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]
.endm

.macro	load_constant_ptr
	adr	x26, round_constants
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
	eor3_m1_0	\d\(), \s0\(), \s1\(), \s2\()
	eor3_m1_1	\d\(), \s0\(), \s1\(), \s2\()
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

.macro	load_input_vector
	ldr	vAbaq, [input_addr, #(32*0)]
	ldr	vAbeq, [input_addr, #(32*0+32)]
	ldr	vAbiq, [input_addr, #(32*2)]
	ldr	vAboq, [input_addr, #(32*2+32)]
	ldr	vAbuq, [input_addr, #(32*4)]
	ldr	vAgaq, [input_addr, #(32*4+32)]
	ldr	vAgeq, [input_addr, #(32*6)]
	ldr	vAgiq, [input_addr, #(32*6+32)]
	ldr	vAgoq, [input_addr, #(32*8)]
	ldr	vAguq, [input_addr, #(32*8+32)]
	ldr	vAkaq, [input_addr, #(32*10)]
	ldr	vAkeq, [input_addr, #(32*10+32)]
	ldr	vAkiq, [input_addr, #(32*12)]
	ldr	vAkoq, [input_addr, #(32*12+32)]
	ldr	vAkuq, [input_addr, #(32*14)]
	ldr	vAmaq, [input_addr, #(32*14+32)]
	ldr	vAmeq, [input_addr, #(32*16)]
	ldr	vAmiq, [input_addr, #(32*16+32)]
	ldr	vAmoq, [input_addr, #(32*18)]
	ldr	vAmuq, [input_addr, #(32*18+32)]
	ldr	vAsaq, [input_addr, #(32*20)]
	ldr	vAseq, [input_addr, #(32*20+32)]
	ldr	vAsiq, [input_addr, #(32*22)]
	ldr	vAsoq, [input_addr, #(32*22+32)]
	ldr	vAsuq, [input_addr, #(32*24)]
.endm

.macro	store_input_vector
	str	vAbaq, [input_addr, #(32*0)]
	str	vAbeq, [input_addr, #(32*0+32)]
	str	vAbiq, [input_addr, #(32*2)]
	str	vAboq, [input_addr, #(32*2+32)]
	str	vAbuq, [input_addr, #(32*4)]
	str	vAgaq, [input_addr, #(32*4+32)]
	str	vAgeq, [input_addr, #(32*6)]
	str	vAgiq, [input_addr, #(32*6+32)]
	str	vAgoq, [input_addr, #(32*8)]
	str	vAguq, [input_addr, #(32*8+32)]
	str	vAkaq, [input_addr, #(32*10)]
	str	vAkeq, [input_addr, #(32*10+32)]
	str	vAkiq, [input_addr, #(32*12)]
	str	vAkoq, [input_addr, #(32*12+32)]
	str	vAkuq, [input_addr, #(32*14)]
	str	vAmaq, [input_addr, #(32*14+32)]
	str	vAmeq, [input_addr, #(32*16)]
	str	vAmiq, [input_addr, #(32*16+32)]
	str	vAmoq, [input_addr, #(32*18)]
	str	vAmuq, [input_addr, #(32*18+32)]
	str	vAsaq, [input_addr, #(32*20)]
	str	vAseq, [input_addr, #(32*20+32)]
	str	vAsiq, [input_addr, #(32*22)]
	str	vAsoq, [input_addr, #(32*22+32)]
	str	vAsuq, [input_addr, #(32*24)]
.endm

.macro	store_input_scalar
	str	x1,[input_addr, 32*0 ]
	str	x6, [input_addr, 32*1 ]
	str	x11, [input_addr, 32*2 ]
	str	x16, [input_addr, 32*3 ]
	str	x21, [input_addr, 32*4 ]
	str	x2, [input_addr, 32*5 ]
	str	x7, [input_addr, 32*6 ]
	str	x12, [input_addr, 32*7 ]
	str	x17, [input_addr, 32*8 ]
	str	x22, [input_addr, 32*9 ]
	str	x3, [input_addr, 32*10]
	str	x8, [input_addr, 32*11]
	str	x13, [input_addr, 32*12]
	str	x25, [input_addr, 32*13]
	str	x23, [input_addr, 32*14]
	str	x4, [input_addr, 32*15]
	str	x9, [input_addr, 32*16]
	str	x14, [input_addr, 32*17]
	str	x19, [input_addr, 32*18]
	str	x24, [input_addr, 32*19]
	str	x5, [input_addr, 32*20]
	str	x10, [input_addr, 32*21]
	str	x15, [input_addr, 32*22]
	str	x20, [input_addr, 32*23]
	str	x18, [input_addr, 32*24]
.endm

.macro	load_input_scalar
	ldr	x1,[input_addr, 32*0 ]
	ldr	x6, [input_addr, 32*1 ]
	ldr	x11, [input_addr, 32*2 ]
	ldr	x16, [input_addr, 32*3 ]
	ldr	x21, [input_addr, 32*4 ]
	ldr	x2, [input_addr, 32*5 ]
	ldr	x7, [input_addr, 32*6 ]
	ldr	x12, [input_addr, 32*7 ]
	ldr	x17, [input_addr, 32*8 ]
	ldr	x22, [input_addr, 32*9 ]
	ldr	x3, [input_addr, 32*10]
	ldr	x8, [input_addr, 32*11]
	ldr	x13, [input_addr, 32*12]
	ldr	x25, [input_addr, 32*13]
	ldr	x23, [input_addr, 32*14]
	ldr	x4, [input_addr, 32*15]
	ldr	x9, [input_addr, 32*16]
	ldr	x14, [input_addr, 32*17]
	ldr	x19, [input_addr, 32*18]
	ldr	x24, [input_addr, 32*19]
	ldr	x5, [input_addr, 32*20]
	ldr	x10, [input_addr, 32*21]
	ldr	x15, [input_addr, 32*22]
	ldr	x20, [input_addr, 32*23]
	ldr	x18, [input_addr, 32*24]
.endm

#define STACK_SIZE             (4*16 + 12*8 + 8*8 + 3*16)
#define STACK_BASE_VREGS       (0)
#define STACK_BASE_GPRS        (4*16)
#define STACK_BASE_TMP_GPRS    (4*16 + 12*8)
#define STACK_BASE_TMP_VREGS   (4*16 + 12*8 + 8*8)
#define STACK_OFFSET_INPUT     (0*8)
#define STACK_OFFSET_CONST     (1*8)
#define STACK_OFFSET_COUNT     (2*8)
#define STACK_OFFSET_COUNT_OUT (3*8)
#define STACK_OFFSET_CUR_INPUT (4*8)
#define STACK_OFFSET_x27_A44   (6*8)
#define STACK_OFFSET_x27_C2_E3 (7*8)

#define vAgi_offset 0
#define vAga_offset 1
#define vAge_offset 2

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
	eor	\d\()st, \src0, \src1
	eor	\d\()st, \d\()st,  \src2
	eor	\d\()st, \d\()st,  \src3
	eor	\d\()st, \d\()st,  \src4
.endm

.macro	xor_rol dst, src1, src0, imm
	eor	\d\()st, \src0, \src1, ROR  #(64-\imm)
.endm

.macro	bic_rol dst, src1, src0, imm
	bic	\d\()st, \src0, \src1, ROR  #(64-\imm)
.endm

.macro	rotate dst, src, imm
	ror	\d\()st, \src, #(64-\imm)
.endm

.macro	hybrid_round_initial
	eor	x30, x4, x5                             SEP      eor3_m1_0 C1,vAbe,vAge,vAke
	eor	x26, x9, x10                             SEP
	eor	x27, x14, x15                             SEP      eor3_m1_0 C3,vAbo,vAgo,vAko
	eor	x28, x19, x20                             SEP
	eor	x29, x24, x18                             SEP      eor3_m1_0 C0,vAba,vAga,vAka
	eor	x30, x3, x30                              SEP
	eor	x26, x8, x26                              SEP      eor3_m1_0 C2,vAbi,vAgi,vAki
	eor	x27, x13, x27                              SEP
	eor	x28, x25, x28                              SEP      eor3_m1_0 C4,vAbu,vAgu,vAku
	eor	x29, x23, x29                              SEP
	eor	x30, x2, x30                              SEP      eor3_m1_1 C1,vAbe,vAge,vAke
	eor	x26, x7, x26                              SEP      eor3_m1_1 C3,vAbo,vAgo,vAko
	eor	x27, x12, x27                              SEP
	eor	x28, x17, x28                              SEP      eor3_m1_1 C0,vAba,vAga,vAka
	eor	x29, x22, x29                              SEP
	eor	x30, x1, x30                             SEP      eor3_m1_1 C2,vAbi,vAgi,vAki
	eor	x26, x6, x26                              SEP
	eor	x27, x11, x27                              SEP      eor3_m1_1 C4,vAbu,vAgu,vAku
	eor	x28, x16, x28                              SEP
	eor	x29, x21, x29                              SEP      eor3_m1_0 C1, C1,vAme, vAse
	eor	x0, x30, x27, ROR #63                      SEP      eor3_m1_0 C3, C3,vAmo, vAso
	eor	x27, x27, x29, ROR #63                      SEP
	eor	x29, x29, x26, ROR #63                      SEP      eor3_m1_0 C0, C0,vAma, vAsa
	eor	x26, x26, x28, ROR #63                      SEP
	eor	x28, x28, x30, ROR #63                      SEP      eor3_m1_0 C2, C2,vAmi, vAsi
	eor	x30, x1, x29                          SEP
	eor	x1, x11, x26                            SEP      eor3_m1_0 C4, C4,vAmu, vAsu
	eor	x11, x13, x26                            SEP
	eor	x13, x25, x27                            SEP      eor3_m1_1 C1, C1,vAme, vAse
	eor	x25, x24, x28                            SEP      eor3_m1_1 C3, C3,vAmo, vAso
	eor	x24, x20, x27                            SEP
	eor	x20, x4, x29                            SEP      eor3_m1_1 C0, C0,vAma, vAsa
	eor	x4, x6, x0                            SEP
	eor	x6, x17, x27                            SEP      eor3_m1_1 C2, C2,vAmi, vAsi
	eor	x17, x9, x0                            SEP
	eor	x9, x12, x26                            SEP      eor3_m1_1 C4, C4,vAmu, vAsu
	eor	x12, x3, x29                            SEP
	eor	x3, x16, x27                            SEP      vvtmp .req vBba
	eor	x16, x19, x27                            SEP      rax1_m1 E2, C1, C3
	eor	x19, x14, x26                            SEP
	eor	x14, x8, x0                            SEP      rax1_m1 E4, C3, C0
	eor	x8, x22, x28                            SEP
	eor	x22, x15, x26                            SEP      rax1_m1 E1, C0, C2
	eor	x15, x23, x28                            SEP
	eor	x23, x5, x29                            SEP      rax1_m1 E3, C2, C4
	eor	x5, x21, x28                            SEP
	eor	x21, x18, x28                            SEP      str vAgiq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
	eor	x18, x10, x0                            SEP      rax1_m1 E0, C4, C1
	eor	x10, x2, x29                            SEP
	eor	x28, x7, x0                            SEP
	load_constant_ptr	SEP
	bic	x0, x12, x8, ROR #47                                      SEP      .unreq vvtmp
	bic	x29, x17, x12, ROR #42                                         SEP
	eor	x2, x0, x3, ROR #39                                      SEP      vvtmp .req C1
	bic	x0, x22, x17, ROR #16                                      SEP
	eor	x7, x29, x8, ROR #25                                      SEP      vvtmpq .req C1q
	bic	x29, x3, x22, ROR #31                                      SEP      xar_m1 vBgi, vAka, E0, 61
	eor	x12, x0, x12, ROR #58                                      SEP
	bic	x0, x8, x3, ROR #56                                      SEP      xar_m1 vBga, vAbo, E3, 36
	eor	x17, x29, x17, ROR #47                                      SEP
	bic	x29, x13, x9, ROR #19                                    SEP      str vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
	eor	x22, x0, x22, ROR #23                                     SEP
	bic	x0, x25, x13, ROR #47                                    SEP      xar_m1 vBbo, vAmo, E3, 43
	eor	x3, x29, x4, ROR #24                                     SEP
	bic	x29, x23, x25, ROR #10                                    SEP      xar_m1 vBmo, vAmi, E2, 49
	eor	x8, x0, x9, ROR #2                                      SEP      str vAgeq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAge_offset)]
	bic	x0, x4, x23, ROR #47                                    SEP
	eor	x13, x29, x13, ROR #57                                     SEP      xar_m1 vBmi, vAke, E1, 54
	bic	x29, x9, x4, ROR #5                                     SEP
	eor	x25, x0, x25, ROR #57                                     SEP      xar_m1 vBge, vAgu, E4, 44
	bic	x0, x14, x10, ROR #38                                    SEP
	eor	x23, x29, x23, ROR #52                                     SEP      bcax_m1 vAga, vBga, vBgi, vBge
	bic	x29, x19, x14, ROR #5                                     SEP
	eor	x4, x0, x5, ROR #47                                     SEP      eor vBba.16b, vAba.16b, E0.16b
	bic	x0, x24, x19, ROR #41                                    SEP
	eor	x9, x29, x10, ROR #43                                     SEP      xar_m1 vBsa, vAbi, E2, 2
	bic	x29, x5, x24, ROR #35                                    SEP      xar_m1 vBbi, vAki, E2, 21
	eor	x14, x0, x14, ROR #46                             SEP
	bic	x0, x10, x5, ROR #9                             SEP      xar_m1 vBki, vAko, E3, 39
	str	x26, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]                                    SEP
	ldr	x26, [x26]                                    SEP      xar_m1 vBko, vAmu, E4, 56
	eor	x19, x29, x19, ROR #12                                     SEP
	bic	x29, x15, x6, ROR #48                                    SEP      xar_m1 vBmu, vAso, E3, 8
	eor	x24, x0, x24, ROR #44                                     SEP
	bic	x0, x20, x15, ROR #2                                     SEP      xar_m1 vBso, vAma, E0, 23
	eor	x5, x29, x1, ROR #41                                     SEP      xar_m1 vBka, vAbe, E1, 63
	bic	x29, x18, x20, ROR #25                                    SEP
	eor	x10, x0, x6, ROR #50                                     SEP      xar_m1 vBse, vAgo, E3, 9
	bic	x0, x1, x18, ROR #60                                    SEP
	eor	x15, x29, x15, ROR #27                                     SEP      xar_m1 vBgo, vAme, E1, 19
	bic	x29, x6, x1, ROR #57                                    SEP
	eor	x20, x0, x20, ROR #21                                     SEP      bcax_m1 vAge, vBge, vBgo, vBgi
	bic	x0, x11, x28, ROR #63                                    SEP
	eor	x18, x29, x18, ROR #53                                     SEP      ldr vvtmpq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
	str	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                                  SEP      xar_m1 vBke, vvtmp, E2, 58
	bic	x29, x16, x11, ROR #42                                    SEP
	eor	x1, x30, x0, ROR #21                                     SEP      xar_m1 vBgu, vAsi, E2, 3
	bic	x0, x21, x16, ROR #57                                    SEP
	eor	x6, x29, x28, ROR #41                                     SEP      bcax_m1 vAgi, vBgi, vBgu, vBgo
	bic	x29, x30, x21, ROR #50                                   SEP
	eor	x11, x0, x11, ROR #35                                     SEP      xar_m1 vBsi, vAku, E4, 25
	bic	x0, x28, x30, ROR #44                                   SEP
	eor	x16, x29, x16, ROR #43                                     SEP      xar_m1 vBku, vAsa, E0, 46
	eor	x21, x0, x21, ROR #30                                   SEP      xar_m1 vBma, vAbu, E4, 37
	mov	w27, #1                                                              SEP
	eor	x1, x1, x26                                           SEP
	str	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]                                     SEP
	eor	x27, x15, x11, ROR #52                    SEP      xar_m1 vBbu, vAsu, E4, 50
	eor	x30, x1, x2, ROR #61                    SEP
	eor	x29, x23, x22, ROR #50                    SEP      xar_m1 vBsu, vAse, E1, 62
	eor	x26, x8, x9, ROR #57                    SEP
	eor	x28, x16, x25, ROR #63                    SEP      ldp vvtmpq, E3q, [sp, #(STACK_BASE_TMP_VREGS + 16*vAga_offset)]
	eor	x27, x27, x13, ROR #48                       SEP
	eor	x30, x30, x4, ROR #54                       SEP      xar_m1 vBme, vvtmp, E0, 28
	eor	x29, x29, x24, ROR #34                       SEP      xar_m1 vBbe, E3,  E1, 20
	eor	x26, x26, x6, ROR #51                       SEP
	eor	x28, x28, x19, ROR #37                       SEP
	eor	x27, x27, x14, ROR #10                       SEP
	eor	x30, x30, x3, ROR #39                       SEP      bcax_m1 vAgo, vBgo, vBga, vBgu
	eor	x29, x29, x21, ROR #26                       SEP
	eor	x26, x26, x10, ROR #31                       SEP      bcax_m1 vAgu, vBgu, vBge, vBga
	eor	x28, x28, x17, ROR #36                       SEP
	eor	x27, x27, x12, ROR #5                        SEP      bcax_m1 vAka, vBka, vBki, vBke
	str	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]                       SEP      bcax_m1 vAke, vBke, vBko, vBki
	eor	x30, x30, x5, ROR #25                       SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                       SEP      .unreq vvtmp
	eor	x29, x29, x18, ROR #15                       SEP
	eor	x26, x26, x7, ROR #27                       SEP      .unreq vvtmpq
	eor	x28, x28, x20, ROR #2                        SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]                                      SEP      eor2    C0,  vAka, vAga
	eor	x0, x30, x27, ROR #61                          SEP
	ror	x27, x27, 62                                      SEP      str vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
	eor	x27, x27, x29, ROR #57                          SEP      vvtmp .req vAga
	ror	x29, x29, 58                                      SEP
	eor	x29, x29, x26, ROR #55                          SEP      vvtmpq .req vAgaq
	ror	x26, x26, 56
	eor	x26, x26, x28, ROR #63
	eor	x28, x28, x30, ROR #63
	eor	x30, x29, x1                            SEP
	eor	x1, x26, x11, ROR #50                   SEP      bcax_m1 vAki, vBki, vBku, vBko
	eor	x11, x26, x13, ROR #46                   SEP
	eor	x13, x27, x25, ROR #63                   SEP      bcax_m1 vAko, vBko, vBka, vBku
	eor	x25, x28, x24, ROR #28                   SEP
	eor	x24, x27, x20, ROR #2                    SEP      eor2    C1,  vAke, vAge
	eor	x20, x29, x4, ROR #54                   SEP      bcax_m1 vAku, vBku, vBke, vBka
	eor	x4, x0, x6, ROR #43                   SEP
	eor	x6, x27, x17, ROR #36                   SEP      eor2    C2,  vAki, vAgi
	eor	x17, x0, x9, ROR #49                   SEP
	eor	x9, x26, x12, ROR #3                    SEP      bcax_m1 vAma, vBma, vBmi, vBme
	eor	x12, x29, x3, ROR #39                   SEP
	eor	x3, x27, x16                            SEP      eor2    C3,  vAko, vAgo
	eor	x16, x27, x19, ROR #37                   SEP
	eor	x19, x26, x14, ROR #8                    SEP      bcax_m1 vAme, vBme, vBmo, vBmi
	eor	x14, x0, x8, ROR #56                   SEP
	eor	x8, x28, x22, ROR #44                   SEP      eor2    C4,  vAku, vAgu
	eor	x22, x26, x15, ROR #62                   SEP      bcax_m1 vAmi, vBmi, vBmu, vBmo
	eor	x15, x28, x23, ROR #58                   SEP
	eor	x23, x29, x5, ROR #25                   SEP      eor2    C0,  C0,  vAma
	eor	x5, x28, x21, ROR #20                   SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]
	eor	x21, x28, x18, ROR #9                    SEP      bcax_m1 vAmo, vBmo, vBma, vBmu
	eor	x18, x0, x10, ROR #23                   SEP
	eor	x10, x29, x2, ROR #61                   SEP      eor2    C1,  C1,  vAme
	eor	x28, x0, x7, ROR #19                   SEP
	SEP	bcax_m1 vAmu, vBmu, vBme, vBma
	bic	x0, x12, x8, ROR #47                  SEP      eor2    C2,  C2,  vAmi
	bic	x29, x17, x12, ROR #42                  SEP
	eor	x2, x0, x3, ROR #39                   SEP      bcax_m1 vAsa, vBsa, vBsi, vBse
	bic	x0, x22, x17, ROR #16                  SEP
	eor	x7, x29, x8, ROR #25                   SEP      eor2    C3,  C3,  vAmo
	bic	x29, x3, x22, ROR #31                  SEP
	eor	x12, x0, x12, ROR #58                   SEP      bcax_m1 vAse, vBse, vBso, vBsi
	bic	x0, x8, x3, ROR #56                  SEP
	eor	x17, x29, x17, ROR #47                   SEP      eor2    C4,  C4,  vAmu
	bic	x29, x13, x9, ROR #19                  SEP      bcax_m1 vAsi, vBsi, vBsu, vBso
	eor	x22, x0, x22, ROR #23                   SEP
	bic	x0, x25, x13, ROR #47                  SEP      eor2    C0,  C0,  vAsa
	eor	x3, x29, x4, ROR #24                   SEP
	bic	x29, x23, x25, ROR #10                  SEP      bcax_m1 vAso, vBso, vBsa, vBsu
	eor	x8, x0, x9, ROR #2                    SEP
	bic	x0, x4, x23, ROR #47                  SEP      eor2    C1,  C1,  vAse
	eor	x13, x29, x13, ROR #57                   SEP
	bic	x29, x9, x4, ROR #5                   SEP      bcax_m1 vAsu, vBsu, vBse, vBsa
	eor	x25, x0, x25, ROR #57                   SEP      eor2    C2,  C2,  vAsi
	bic	x0, x14, x10, ROR #38                  SEP
	eor	x23, x29, x23, ROR #52                   SEP      eor2    C3,  C3,  vAso
	bic	x29, x19, x14, ROR #5                   SEP
	eor	x4, x0, x5, ROR #47                   SEP      bcax_m1 vAba, vBba, vBbi, vBbe
	bic	x0, x24, x19, ROR #41                  SEP
	eor	x9, x29, x10, ROR #43                   SEP      bcax_m1 vAbe, vBbe, vBbo, vBbi
	bic	x29, x5, x24, ROR #35                  SEP
	eor	x14, x0, x14, ROR #46                   SEP      eor2    C1,  C1,  vAbe
	bic	x0, x10, x5, ROR #9                   SEP      ldr x26, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]
	SEP	ldr vvtmpq, [x26], #16
	SEP
	eor	x19, x29, x19, ROR #12                   SEP      str x26, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]
	bic	x29, x15, x6, ROR #48                  SEP
	eor	x24, x0, x24, ROR #44                   SEP
	bic	x0, x20, x15, ROR #2                   SEP      eor vAba.16b, vAba.16b, vvtmp.16b
	eor	x5, x29, x1, ROR #41                   SEP
	bic	x29, x18, x20, ROR #25                  SEP      eor2    C4,  C4,  vAsu
	eor	x10, x0, x6, ROR #50                   SEP      bcax_m1 vAbi, vBbi, vBbu, vBbo
	bic	x0, x1, x18, ROR #60                  SEP
	eor	x15, x29, x15, ROR #27                   SEP      bcax_m1 vAbo, vBbo, vBba, vBbu
	bic	x29, x6, x1, ROR #57                  SEP
	eor	x20, x0, x20, ROR #21                   SEP      eor2    C3,  C3,  vAbo
	bic	x0, x11, x28, ROR #63                  SEP
	eor	x18, x29, x18, ROR #53                   SEP      eor2    C2,  C2,  vAbi
	str	x27, [sp,(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                       SEP
	ldr	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
	load_constant_ptr_stack
	ldr	x26, [x26, w27, UXTW #3]
	add	w27, w27, #1
	str	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
	bic	x29, x16, x11, ROR #42                  SEP      eor2    C0,  C0,  vAba
	eor	x1, x30, x0, ROR #21                   SEP      bcax_m1 vAbu, vBbu, vBbe, vBba
	bic	x0, x21, x16, ROR #57                  SEP
	eor	x6, x29, x28, ROR #41                   SEP      eor2    C4,  C4,  vAbu
	bic	x29, x30, x21, ROR #50                  SEP
	eor	x11, x0, x11, ROR #35                   SEP      ldr vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
	bic	x0, x28, x30, ROR #44                  SEP
	eor	x16, x29, x16, ROR #43                   SEP      .unreq vvtmp
	eor	x21, x0, x21, ROR #30                   SEP
	SEP
	eor	x1, x1, x26                         SEP      .unreq vvtmpq

.endm


.macro	hybrid_round_noninitial
	str	count, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]                  SEP
	eor	x27, x15, x11, ROR #52                    SEP      vvtmp .req vBba
	eor	x30, x1, x2, ROR #61                    SEP      rax1_m1 E2, C1, C3
	eor	x29, x23, x22, ROR #50                    SEP      rax1_m1 E4, C3, C0
	eor	x26, x8, x9, ROR #57                    SEP
	eor	x28, x16, x25, ROR #63                    SEP
	eor	x27, x27, x13, ROR #48                     SEP
	eor	x30, x30, x4, ROR #54                     SEP      rax1_m1 E1, C0, C2
	eor	x29, x29, x24, ROR #34                     SEP
	eor	x26, x26, x6, ROR #51                     SEP
	eor	x28, x28, x19, ROR #37                     SEP      rax1_m1 E3, C2, C4
	eor	x27, x27, x14, ROR #10                     SEP
	eor	x30, x30, x3, ROR #39                     SEP      str vAgiq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
	eor	x29, x29, x21, ROR #26                     SEP
	eor	x26, x26, x10, ROR #31                     SEP      rax1_m1 E0, C4, C1
	eor	x28, x28, x17, ROR #36                     SEP
	eor	x27, x27, x12, ROR #5                     SEP      .unreq vvtmp
	str	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]                   SEP
	eor	x30, x30, x5, ROR #25                     SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                     SEP      vvtmp .req C1
	eor	x29, x29, x18, ROR #15                     SEP
	eor	x26, x26, x7, ROR #27                 SEP      vvtmpq .req C1q
	eor	x28, x28, x20, ROR #2                  SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP      xar_m1 vBgi, vAka, E0, 61
	eor	x0, x30, x27, ROR #61                      SEP
	ror	x27, x27, 62                                  SEP      xar_m1 vBga, vAbo, E3, 36
	eor	x27, x27, x29, ROR #57                      SEP
	ror	x29, x29, 58                                  SEP
	eor	x29, x29, x26, ROR #55                      SEP      str vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
	ror	x26, x26, 56
	eor	x26, x26, x28, ROR #63
	eor	x28, x28, x30, ROR #63
	eor	x30, x29, x1                          SEP
	eor	x1, x26, x11, ROR #50                   SEP      xar_m1 vBbo, vAmo, E3, 43
	eor	x11, x26, x13, ROR #46                   SEP
	eor	x13, x27, x25, ROR #63                   SEP      xar_m1 vBmo, vAmi, E2, 49
	eor	x25, x28, x24, ROR #28                   SEP
	eor	x24, x27, x20, ROR #2                    SEP
	eor	x20, x29, x4, ROR #54                   SEP      str vAgeq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAge_offset)]
	eor	x4, x0, x6, ROR #43                   SEP
	eor	x6, x27, x17, ROR #36                   SEP      xar_m1 vBmi, vAke, E1, 54
	eor	x17, x0, x9, ROR #49                   SEP
	eor	x9, x26, x12, ROR #3                    SEP      xar_m1 vBge, vAgu, E4, 44
	eor	x12, x29, x3, ROR #39                   SEP
	eor	x3, x27, x16                            SEP      bcax_m1 vAga, vBga, vBgi, vBge
	eor	x16, x27, x19, ROR #37                   SEP
	eor	x19, x26, x14, ROR #8                    SEP
	eor	x14, x0, x8, ROR #56                   SEP      eor vBba.16b, vAba.16b, E0.16b
	eor	x8, x28, x22, ROR #44                   SEP
	eor	x22, x26, x15, ROR #62                   SEP      xar_m1 vBsa, vAbi, E2, 2
	eor	x15, x28, x23, ROR #58                   SEP
	eor	x23, x29, x5, ROR #25                   SEP      xar_m1 vBbi, vAki, E2, 21
	eor	x5, x28, x21, ROR #20                   SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]
	eor	x21, x28, x18, ROR #9                    SEP      xar_m1 vBki, vAko, E3, 39
	eor	x18, x0, x10, ROR #23                   SEP
	eor	x10, x29, x2, ROR #61                   SEP
	eor	x28, x0, x7, ROR #19                   SEP      xar_m1 vBko, vAmu, E4, 56
	SEP
	bic	x0, x12, x8, ROR #47                 SEP      xar_m1 vBmu, vAso, E3, 8
	bic	x29, x17, x12, ROR #42                 SEP
	eor	x2, x0, x3, ROR #39                  SEP      xar_m1 vBso, vAma, E0, 23
	bic	x0, x22, x17, ROR #16                 SEP
	eor	x7, x29, x8, ROR #25                  SEP
	bic	x29, x3, x22, ROR #31                 SEP      xar_m1 vBka, vAbe, E1, 63
	eor	x12, x0, x12, ROR #58                  SEP
	bic	x0, x8, x3, ROR #56                 SEP      xar_m1 vBse, vAgo, E3, 9
	eor	x17, x29, x17, ROR #47                  SEP
	bic	x29, x13, x9, ROR #19                 SEP      xar_m1 vBgo, vAme, E1, 19
	eor	x22, x0, x22, ROR #23                  SEP
	bic	x0, x25, x13, ROR #47                 SEP      bcax_m1 vAge, vBge, vBgo, vBgi
	eor	x3, x29, x4, ROR #24                  SEP
	bic	x29, x23, x25, ROR #10                 SEP
	eor	x8, x0, x9, ROR #2                   SEP      ldr vvtmpq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
	bic	x0, x4, x23, ROR #47                 SEP
	eor	x13, x29, x13, ROR #57                  SEP      xar_m1 vBke, vvtmp, E2, 58
	bic	x29, x9, x4, ROR #5                  SEP
	eor	x25, x0, x25, ROR #57                  SEP      xar_m1 vBgu, vAsi, E2, 3
	bic	x0, x14, x10, ROR #38                 SEP
	eor	x23, x29, x23, ROR #52                  SEP      bcax_m1 vAgi, vBgi, vBgu, vBgo
	bic	x29, x19, x14, ROR #5                  SEP
	eor	x4, x0, x5, ROR #47                  SEP
	bic	x0, x24, x19, ROR #41                 SEP      xar_m1 vBsi, vAku, E4, 25
	eor	x9, x29, x10, ROR #43                  SEP
	bic	x29, x5, x24, ROR #35                 SEP      xar_m1 vBku, vAsa, E0, 46
	eor	x14, x0, x14, ROR #46                  SEP
	bic	x0, x10, x5, ROR #9                  SEP      xar_m1 vBma, vAbu, E4, 37
	SEP
	SEP
	eor	x19, x29, x19, ROR #12                  SEP      xar_m1 vBbu, vAsu, E4, 50
	bic	x29, x15, x6, ROR #48                 SEP
	eor	x24, x0, x24, ROR #44                  SEP      xar_m1 vBsu, vAse, E1, 62
	bic	x0, x20, x15, ROR #2                  SEP
	eor	x5, x29, x1, ROR #41                  SEP      ldp vvtmpq, E3q, [sp, #(STACK_BASE_TMP_VREGS + 16*vAga_offset)]
	bic	x29, x18, x20, ROR #25                 SEP
	eor	x10, x0, x6, ROR #50                  SEP      xar_m1 vBme, vvtmp, E0, 28
	bic	x0, x1, x18, ROR #60                 SEP
	eor	x15, x29, x15, ROR #27                  SEP
	bic	x29, x6, x1, ROR #57                 SEP      xar_m1 vBbe, E3,  E1, 20
	eor	x20, x0, x20, ROR #21                  SEP
	bic	x0, x11, x28, ROR #63                 SEP      bcax_m1 vAgo, vBgo, vBga, vBgu
	eor	x18, x29, x18, ROR #53                  SEP
	str	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                      SEP      bcax_m1 vAgu, vBgu, vBge, vBga
	ldr	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
	load_constant_ptr_stack
	ldr	x26, [x26, w27, UXTW #3]
	add	w27, w27, #1
	str	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
	bic	x29, x16, x11, ROR #42                  SEP
	eor	x1, x30, x0, ROR #21                   SEP      bcax_m1 vAka, vBka, vBki, vBke
	bic	x0, x21, x16, ROR #57                  SEP
	eor	x6, x29, x28, ROR #41                   SEP
	bic	x29, x30, x21, ROR #50                  SEP      bcax_m1 vAke, vBke, vBko, vBki
	eor	x11, x0, x11, ROR #35                   SEP
	bic	x0, x28, x30, ROR #44                  SEP      .unreq vvtmp
	eor	x16, x29, x16, ROR #43                   SEP
	eor	x21, x0, x21, ROR #30                   SEP      .unreq vvtmpq
	eor	x1, x1, x26                         SEP
	SEP
	eor	x27, x15, x11, ROR #52                    SEP      eor2    C0,  vAka, vAga
	eor	x30, x1, x2, ROR #61                    SEP
	eor	x29, x23, x22, ROR #50                    SEP      str vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
	eor	x26, x8, x9, ROR #57                    SEP
	eor	x28, x16, x25, ROR #63                    SEP      vvtmp .req vAga
	eor	x27, x27, x13, ROR #48                      SEP
	eor	x30, x30, x4, ROR #54                      SEP      vvtmpq .req vAgaq
	eor	x29, x29, x24, ROR #34                      SEP
	eor	x26, x26, x6, ROR #51                      SEP
	eor	x28, x28, x19, ROR #37                      SEP      bcax_m1 vAki, vBki, vBku, vBko
	eor	x27, x27, x14, ROR #10                      SEP
	eor	x30, x30, x3, ROR #39                      SEP      bcax_m1 vAko, vBko, vBka, vBku
	eor	x29, x29, x21, ROR #26                      SEP
	eor	x26, x26, x10, ROR #31                      SEP      eor2    C1,  vAke, vAge
	eor	x28, x28, x17, ROR #36                      SEP
	eor	x27, x27, x12, ROR #5                       SEP      bcax_m1 vAku, vBku, vBke, vBka
	str	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]                    SEP
	eor	x30, x30, x5, ROR #25                      SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                      SEP      eor2    C2,  vAki, vAgi
	eor	x29, x29, x18, ROR #15                      SEP
	eor	x26, x26, x7, ROR #27                      SEP      bcax_m1 vAma, vBma, vBmi, vBme
	eor	x28, x28, x20, ROR #2                       SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]                    SEP      eor2    C3,  vAko, vAgo
	eor	x0, x30, x27, ROR #61                         SEP
	ror	x27, x27, 62                                     SEP      bcax_m1 vAme, vBme, vBmo, vBmi
	eor	x27, x27, x29, ROR #57                         SEP
	ror	x29, x29, 58                                     SEP
	eor	x29, x29, x26, ROR #55                         SEP      eor2    C4,  vAku, vAgu
	ror	x26, x26, 56
	eor	x26, x26, x28, ROR #63
	eor	x28, x28, x30, ROR #63
	eor	x30, x29, x1                           SEP
	eor	x1, x26, x11, ROR #50                   SEP      bcax_m1 vAmi, vBmi, vBmu, vBmo
	eor	x11, x26, x13, ROR #46                   SEP
	eor	x13, x27, x25, ROR #63                   SEP      eor2    C0,  C0,  vAma
	eor	x25, x28, x24, ROR #28                   SEP
	eor	x24, x27, x20, ROR #2                    SEP
	eor	x20, x29, x4, ROR #54                   SEP      bcax_m1 vAmo, vBmo, vBma, vBmu
	eor	x4, x0, x6, ROR #43                   SEP
	eor	x6, x27, x17, ROR #36                   SEP      eor2    C1,  C1,  vAme
	eor	x17, x0, x9, ROR #49                   SEP
	eor	x9, x26, x12, ROR #3                    SEP      bcax_m1 vAmu, vBmu, vBme, vBma
	eor	x12, x29, x3, ROR #39                   SEP
	eor	x3, x27, x16                            SEP      eor2    C2,  C2,  vAmi
	eor	x16, x27, x19, ROR #37                   SEP
	eor	x19, x26, x14, ROR #8                    SEP
	eor	x14, x0, x8, ROR #56                   SEP      bcax_m1 vAsa, vBsa, vBsi, vBse
	eor	x8, x28, x22, ROR #44                   SEP
	eor	x22, x26, x15, ROR #62                   SEP      eor2    C3,  C3,  vAmo
	eor	x15, x28, x23, ROR #58                   SEP
	eor	x23, x29, x5, ROR #25                   SEP      bcax_m1 vAse, vBse, vBso, vBsi
	eor	x5, x28, x21, ROR #20                   SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]
	eor	x21, x28, x18, ROR #9                    SEP      eor2    C4,  C4,  vAmu
	eor	x18, x0, x10, ROR #23                   SEP
	eor	x10, x29, x2, ROR #61                   SEP
	eor	x28, x0, x7, ROR #19                   SEP      bcax_m1 vAsi, vBsi, vBsu, vBso
	SEP
	bic	x0, x12, x8, ROR #47                 SEP      eor2    C0,  C0,  vAsa
	bic	x29, x17, x12, ROR #42                 SEP
	eor	x2, x0, x3, ROR #39                  SEP      bcax_m1 vAso, vBso, vBsa, vBsu
	bic	x0, x22, x17, ROR #16                 SEP
	eor	x7, x29, x8, ROR #25                  SEP
	bic	x29, x3, x22, ROR #31                 SEP      eor2    C1,  C1,  vAse
	eor	x12, x0, x12, ROR #58                  SEP
	bic	x0, x8, x3, ROR #56                 SEP      bcax_m1 vAsu, vBsu, vBse, vBsa
	eor	x17, x29, x17, ROR #47                  SEP
	bic	x29, x13, x9, ROR #19                 SEP      eor2    C2,  C2,  vAsi
	eor	x22, x0, x22, ROR #23                  SEP
	bic	x0, x25, x13, ROR #47                 SEP      eor2    C3,  C3,  vAso
	eor	x3, x29, x4, ROR #24                  SEP
	bic	x29, x23, x25, ROR #10                 SEP
	eor	x8, x0, x9, ROR #2                   SEP      bcax_m1 vAba, vBba, vBbi, vBbe
	bic	x0, x4, x23, ROR #47                 SEP
	eor	x13, x29, x13, ROR #57                  SEP      bcax_m1 vAbe, vBbe, vBbo, vBbi
	bic	x29, x9, x4, ROR #5                  SEP
	eor	x25, x0, x25, ROR #57                  SEP      eor2    C1,  C1,  vAbe
	bic	x0, x14, x10, ROR #38                 SEP
	eor	x23, x29, x23, ROR #52                  SEP      ldr x26, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]
	bic	x29, x19, x14, ROR #5                  SEP
	eor	x4, x0, x5, ROR #47                  SEP
	bic	x0, x24, x19, ROR #41                 SEP      ldr vvtmpq, [x26], #16
	eor	x9, x29, x10, ROR #43                  SEP
	bic	x29, x5, x24, ROR #35                 SEP      str x26, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]
	eor	x14, x0, x14, ROR #46                  SEP
	bic	x0, x10, x5, ROR #9                  SEP      eor vAba.16b, vAba.16b, vvtmp.16b
	SEP
	SEP
	eor	x19, x29, x19, ROR #12                  SEP      eor2    C4,  C4,  vAsu
	bic	x29, x15, x6, ROR #48                 SEP
	eor	x24, x0, x24, ROR #44                  SEP      bcax_m1 vAbi, vBbi, vBbu, vBbo
	bic	x0, x20, x15, ROR #2                  SEP
	eor	x5, x29, x1, ROR #41                  SEP      bcax_m1 vAbo, vBbo, vBba, vBbu
	bic	x29, x18, x20, ROR #25                 SEP
	eor	x10, x0, x6, ROR #50                  SEP      eor2    C3,  C3,  vAbo
	bic	x0, x1, x18, ROR #60                 SEP
	eor	x15, x29, x15, ROR #27                  SEP
	bic	x29, x6, x1, ROR #57                 SEP      eor2    C2,  C2,  vAbi
	eor	x20, x0, x20, ROR #21                  SEP
	bic	x0, x11, x28, ROR #63                 SEP      eor2    C0,  C0,  vAba
	eor	x18, x29, x18, ROR #53                  SEP
	str	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                      SEP      bcax_m1 vAbu, vBbu, vBbe, vBba
	ldr	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
	load_constant_ptr_stack
	ldr	x26, [x26, w27, UXTW #3]
	add	w27, w27, #1
	str	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
	bic	x29, x16, x11, ROR #42               SEP
	eor	x1, x30, x0, ROR #21                  SEP      eor2    C4,  C4,  vAbu
	bic	x0, x21, x16, ROR #57                 SEP
	eor	x6, x29, x28, ROR #41                  SEP
	bic	x29, x30, x21, ROR #50                 SEP      ldr vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
	eor	x11, x0, x11, ROR #35                 SEP
	bic	x0, x28, x30, ROR #44                 SEP      .unreq vvtmp
	eor	x16, x29, x16, ROR #43                 SEP
	eor	x21, x0, x21, ROR #30                  SEP      .unreq vvtmpq
	eor	x1, x1, x26                     SEP
.endm
.macro	hybrid_round_final
	SEP	vvtmp .req vBba
	SEP	rax1_m1 E2, C1, C3
	eor	x27, x15, x11, ROR #52                    SEP
	eor	x30, x1, x2, ROR #61                    SEP      rax1_m1 E4, C3, C0
	eor	x29, x23, x22, ROR #50                    SEP
	eor	x26, x8, x9, ROR #57                    SEP      rax1_m1 E1, C0, C2
	eor	x28, x16, x25, ROR #63                    SEP
	eor	x27, x27, x13, ROR #48                     SEP
	eor	x30, x30, x4, ROR #54                     SEP
	eor	x29, x29, x24, ROR #34                     SEP
	eor	x26, x26, x6, ROR #51                     SEP
	eor	x28, x28, x19, ROR #37                     SEP
	eor	x27, x27, x14, ROR #10                     SEP
	eor	x30, x30, x3, ROR #39                     SEP
	eor	x29, x29, x21, ROR #26                     SEP
	eor	x26, x26, x10, ROR #31                     SEP      rax1_m1 E3, C2, C4
	eor	x28, x28, x17, ROR #36                     SEP
	eor	x27, x27, x12, ROR #5                     SEP
	str	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]                   SEP
	eor	x30, x30, x5, ROR #25                     SEP      str vAgiq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                     SEP
	eor	x29, x29, x18, ROR #15                     SEP
	eor	x26, x26, x7, ROR #27                 SEP      rax1_m1 E0, C4, C1
	eor	x28, x28, x20, ROR #2                  SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP
	eor	x0, x30, x27, ROR #61                      SEP
	ror	x27, x27, 62                                  SEP      .unreq vvtmp
	eor	x27, x27, x29, ROR #57                      SEP
	ror	x29, x29, 58                                  SEP
	eor	x29, x29, x26, ROR #55                      SEP      vvtmp .req C1
	ror	x26, x26, 56
	eor	x26, x26, x28, ROR #63
	eor	x28, x28, x30, ROR #63
	eor	x30, x29, x1                          SEP
	eor	x1, x26, x11, ROR #50                   SEP
	eor	x11, x26, x13, ROR #46                   SEP      vvtmpq .req C1q
	eor	x13, x27, x25, ROR #63                   SEP
	eor	x25, x28, x24, ROR #28                   SEP
	eor	x24, x27, x20, ROR #2                    SEP
	eor	x20, x29, x4, ROR #54                   SEP      xar_m1 vBgi, vAka, E0, 61
	eor	x4, x0, x6, ROR #43                   SEP
	eor	x6, x27, x17, ROR #36                   SEP
	eor	x17, x0, x9, ROR #49                   SEP      xar_m1 vBga, vAbo, E3, 36
	eor	x9, x26, x12, ROR #3                    SEP
	eor	x12, x29, x3, ROR #39                   SEP
	eor	x3, x27, x16                            SEP
	eor	x16, x27, x19, ROR #37                   SEP      str vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
	eor	x19, x26, x14, ROR #8                    SEP
	eor	x14, x0, x8, ROR #56                   SEP
	eor	x8, x28, x22, ROR #44                   SEP      xar_m1 vBbo, vAmo, E3, 43
	eor	x22, x26, x15, ROR #62                   SEP
	eor	x15, x28, x23, ROR #58                   SEP
	eor	x23, x29, x5, ROR #25                   SEP
	eor	x5, x28, x21, ROR #20                   SEP      xar_m1 vBmo, vAmi, E2, 49
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]
	eor	x21, x28, x18, ROR #9                    SEP
	eor	x18, x0, x10, ROR #23                   SEP
	eor	x10, x29, x2, ROR #61                   SEP      str vAgeq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAge_offset)]
	eor	x28, x0, x7, ROR #19                   SEP
	SEP
	bic	x0, x12, x8, ROR #47             SEP
	bic	x29, x17, x12, ROR #42                 SEP      xar_m1 vBmi, vAke, E1, 54
	eor	x2, x0, x3, ROR #39                  SEP
	bic	x0, x22, x17, ROR #16                 SEP
	eor	x7, x29, x8, ROR #25                  SEP      xar_m1 vBge, vAgu, E4, 44
	bic	x29, x3, x22, ROR #31                 SEP
	eor	x12, x0, x12, ROR #58                  SEP
	bic	x0, x8, x3, ROR #56                 SEP      bcax_m1 vAga, vBga, vBgi, vBge
	eor	x17, x29, x17, ROR #47                  SEP
	bic	x29, x13, x9, ROR #19                 SEP
	eor	x22, x0, x22, ROR #23                  SEP
	bic	x0, x25, x13, ROR #47                 SEP      eor vBba.16b, vAba.16b, E0.16b
	eor	x3, x29, x4, ROR #24                  SEP
	bic	x29, x23, x25, ROR #10                 SEP
	eor	x8, x0, x9, ROR #2                   SEP      xar_m1 vBsa, vAbi, E2, 2
	bic	x0, x4, x23, ROR #47                 SEP
	eor	x13, x29, x13, ROR #57                  SEP
	bic	x29, x9, x4, ROR #5                  SEP
	eor	x25, x0, x25, ROR #57                  SEP      xar_m1 vBbi, vAki, E2, 21
	bic	x0, x14, x10, ROR #38                 SEP
	eor	x23, x29, x23, ROR #52                  SEP
	bic	x29, x19, x14, ROR #5                  SEP      xar_m1 vBki, vAko, E3, 39
	eor	x4, x0, x5, ROR #47                  SEP
	bic	x0, x24, x19, ROR #41                 SEP
	eor	x9, x29, x10, ROR #43                  SEP
	bic	x29, x5, x24, ROR #35                 SEP      xar_m1 vBko, vAmu, E4, 56
	eor	x14, x0, x14, ROR #46                  SEP
	bic	x0, x10, x5, ROR #9                  SEP
	SEP	xar_m1 vBmu, vAso, E3, 8
	SEP
	eor	x19, x29, x19, ROR #12                  SEP
	bic	x29, x15, x6, ROR #48                 SEP
	eor	x24, x0, x24, ROR #44                  SEP      xar_m1 vBso, vAma, E0, 23
	bic	x0, x20, x15, ROR #2                  SEP
	eor	x5, x29, x1, ROR #41                  SEP
	bic	x29, x18, x20, ROR #25                 SEP      xar_m1 vBka, vAbe, E1, 63
	eor	x10, x0, x6, ROR #50                  SEP
	bic	x0, x1, x18, ROR #60                 SEP
	eor	x15, x29, x15, ROR #27                  SEP      xar_m1 vBse, vAgo, E3, 9
	bic	x29, x6, x1, ROR #57                 SEP
	eor	x20, x0, x20, ROR #21                  SEP
	bic	x0, x11, x28, ROR #63                 SEP
	eor	x18, x29, x18, ROR #53                  SEP      xar_m1 vBgo, vAme, E1, 19
	str	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                      SEP
	ldr	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
	load_constant_ptr_stack
	ldr	x26, [x26, w27, UXTW #3]
	add	w27, w27, #1
	str	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
	bic	x29, x16, x11, ROR #42               SEP
	eor	x1, x30, x0, ROR #21                  SEP      bcax_m1 vAge, vBge, vBgo, vBgi
	bic	x0, x21, x16, ROR #57                 SEP
	eor	x6, x29, x28, ROR #41                  SEP
	bic	x29, x30, x21, ROR #50                 SEP
	eor	x11, x0, x11, ROR #35                 SEP      ldr vvtmpq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
	bic	x0, x28, x30, ROR #44                 SEP
	eor	x16, x29, x16, ROR #43                 SEP
	eor	x21, x0, x21, ROR #30                  SEP      xar_m1 vBke, vvtmp, E2, 58
	eor	x1, x1, x26                     SEP
	SEP
	eor	x27, x15, x11, ROR #52                    SEP
	eor	x30, x1, x2, ROR #61                    SEP      xar_m1 vBgu, vAsi, E2, 3
	eor	x29, x23, x22, ROR #50                    SEP
	eor	x26, x8, x9, ROR #57                    SEP
	eor	x28, x16, x25, ROR #63                    SEP      bcax_m1 vAgi, vBgi, vBgu, vBgo
	eor	x27, x27, x13, ROR #48                     SEP
	eor	x30, x30, x4, ROR #54                     SEP
	eor	x29, x29, x24, ROR #34                     SEP
	eor	x26, x26, x6, ROR #51                     SEP      xar_m1 vBsi, vAku, E4, 25
	eor	x28, x28, x19, ROR #37                     SEP
	eor	x27, x27, x14, ROR #10                     SEP
	eor	x30, x30, x3, ROR #39                     SEP      xar_m1 vBku, vAsa, E0, 46
	eor	x29, x29, x21, ROR #26                     SEP
	eor	x26, x26, x10, ROR #31                     SEP
	eor	x28, x28, x17, ROR #36                     SEP      xar_m1 vBma, vAbu, E4, 37
	eor	x27, x27, x12, ROR #5                     SEP
	str	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]                   SEP
	eor	x30, x30, x5, ROR #25                     SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                     SEP      xar_m1 vBbu, vAsu, E4, 50
	eor	x29, x29, x18, ROR #15                     SEP
	eor	x26, x26, x7, ROR #27                 SEP
	eor	x28, x28, x20, ROR #2                  SEP      xar_m1 vBsu, vAse, E1, 62
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP
	eor	x0, x30, x27, ROR #61                      SEP
	ror	x27, x27, 62                                  SEP
	eor	x27, x27, x29, ROR #57                      SEP      ldp vvtmpq, E3q, [sp, #(STACK_BASE_TMP_VREGS + 16*vAga_offset)]
	ror	x29, x29, 58                                  SEP
	eor	x29, x29, x26, ROR #55                      SEP
	ror	x26, x26, 56
	eor	x26, x26, x28, ROR #63
	eor	x28, x28, x30, ROR #63
	eor	x30, x29, x1                          SEP      xar_m1 vBme, vvtmp, E0, 28
	eor	x1, x26, x11, ROR #50                   SEP
	eor	x11, x26, x13, ROR #46                   SEP
	eor	x13, x27, x25, ROR #63                   SEP
	eor	x25, x28, x24, ROR #28                   SEP      xar_m1 vBbe, E3,  E1, 20
	eor	x24, x27, x20, ROR #2                    SEP
	eor	x20, x29, x4, ROR #54                   SEP
	eor	x4, x0, x6, ROR #43                   SEP      bcax_m1 vAgo, vBgo, vBga, vBgu
	eor	x6, x27, x17, ROR #36                   SEP
	eor	x17, x0, x9, ROR #49                   SEP
	eor	x9, x26, x12, ROR #3                    SEP
	eor	x12, x29, x3, ROR #39                   SEP      bcax_m1 vAgu, vBgu, vBge, vBga
	eor	x3, x27, x16                            SEP
	eor	x16, x27, x19, ROR #37                   SEP
	eor	x19, x26, x14, ROR #8                    SEP      bcax_m1 vAka, vBka, vBki, vBke
	eor	x14, x0, x8, ROR #56                   SEP
	eor	x8, x28, x22, ROR #44                   SEP
	eor	x22, x26, x15, ROR #62                   SEP      bcax_m1 vAke, vBke, vBko, vBki
	eor	x15, x28, x23, ROR #58                   SEP
	eor	x23, x29, x5, ROR #25                   SEP
	eor	x5, x28, x21, ROR #20                   SEP
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]
	eor	x21, x28, x18, ROR #9                    SEP      bcax_m1 vAki, vBki, vBku, vBko
	eor	x18, x0, x10, ROR #23                   SEP
	eor	x10, x29, x2, ROR #61                   SEP
	eor	x28, x0, x7, ROR #19                   SEP      bcax_m1 vAko, vBko, vBka, vBku
	SEP
	bic	x0, x12, x8, ROR #47                 SEP
	bic	x29, x17, x12, ROR #42                 SEP
	eor	x2, x0, x3, ROR #39                  SEP      bcax_m1 vAku, vBku, vBke, vBka
	bic	x0, x22, x17, ROR #16                 SEP
	eor	x7, x29, x8, ROR #25                  SEP
	bic	x29, x3, x22, ROR #31                 SEP      bcax_m1 vAma, vBma, vBmi, vBme
	eor	x12, x0, x12, ROR #58                  SEP
	bic	x0, x8, x3, ROR #56                 SEP
	eor	x17, x29, x17, ROR #47                  SEP
	bic	x29, x13, x9, ROR #19                 SEP      bcax_m1 vAme, vBme, vBmo, vBmi
	eor	x22, x0, x22, ROR #23                  SEP
	bic	x0, x25, x13, ROR #47                 SEP
	eor	x3, x29, x4, ROR #24                  SEP      bcax_m1 vAmi, vBmi, vBmu, vBmo
	bic	x29, x23, x25, ROR #10                 SEP
	eor	x8, x0, x9, ROR #2                   SEP
	bic	x0, x4, x23, ROR #47                 SEP
	eor	x13, x29, x13, ROR #57                  SEP      bcax_m1 vAmo, vBmo, vBma, vBmu
	bic	x29, x9, x4, ROR #5                  SEP
	eor	x25, x0, x25, ROR #57                  SEP
	bic	x0, x14, x10, ROR #38                 SEP      bcax_m1 vAmu, vBmu, vBme, vBma
	eor	x23, x29, x23, ROR #52                  SEP
	bic	x29, x19, x14, ROR #5                  SEP
	eor	x4, x0, x5, ROR #47                  SEP      bcax_m1 vAsa, vBsa, vBsi, vBse
	bic	x0, x24, x19, ROR #41                 SEP
	eor	x9, x29, x10, ROR #43                  SEP
	bic	x29, x5, x24, ROR #35                 SEP
	eor	x14, x0, x14, ROR #46                  SEP      bcax_m1 vAse, vBse, vBso, vBsi
	bic	x0, x10, x5, ROR #9                  SEP
	SEP
	SEP	bcax_m1 vAsi, vBsi, vBsu, vBso
	eor	x19, x29, x19, ROR #12                  SEP
	bic	x29, x15, x6, ROR #48                 SEP
	eor	x24, x0, x24, ROR #44                  SEP
	bic	x0, x20, x15, ROR #2                  SEP      bcax_m1 vAso, vBso, vBsa, vBsu
	eor	x5, x29, x1, ROR #41                  SEP
	bic	x29, x18, x20, ROR #25                 SEP
	eor	x10, x0, x6, ROR #50                  SEP      bcax_m1 vAsu, vBsu, vBse, vBsa
	bic	x0, x1, x18, ROR #60                 SEP
	eor	x15, x29, x15, ROR #27                  SEP
	bic	x29, x6, x1, ROR #57                 SEP
	eor	x20, x0, x20, ROR #21                  SEP      bcax_m1 vAba, vBba, vBbi, vBbe
	bic	x0, x11, x28, ROR #63                 SEP
	eor	x18, x29, x18, ROR #53                  SEP
	str	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                      SEP      bcax_m1 vAbe, vBbe, vBbo, vBbi
	ldr	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
	load_constant_ptr_stack
	ldr	x26, [x26, w27, UXTW #3]
	add	w27, w27, #1
	str	w27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
	bic	x29, x16, x11, ROR #42               SEP
	eor	x1, x30, x0, ROR #21                  SEP
	bic	x0, x21, x16, ROR #57                 SEP
	eor	x6, x29, x28, ROR #41                  SEP      bcax_m1 vAbi, vBbi, vBbu, vBbo
	bic	x29, x30, x21, ROR #50                 SEP
	eor	x11, x0, x11, ROR #35                 SEP
	bic	x0, x28, x30, ROR #44                 SEP      bcax_m1 vAbo, vBbo, vBba, vBbu
	eor	x16, x29, x16, ROR #43                 SEP
	eor	x21, x0, x21, ROR #30                  SEP
	eor	x1, x1, x26                     SEP      bcax_m1 vAbu, vBbu, vBbe, vBba
	ldr	x27, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)] // load A[2][3]
	ror	x2, x2, #(64-3)                           SEP
	ror	x21, x21, #(64-44)                          SEP
	ror	x3, x3, #(64-25)                          SEP
	ror	x8, x8, #(64-8)                           SEP      ldr x26, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]
	ror	x4, x4, #(64-10)                          SEP
	ror	x23, x23, #(64-6)                           SEP
	ror	x5, x5, #(64-39)                          SEP      ldr vvtmpq, [x26], #16
	ror	x10, x10, #(64-41)                          SEP
	ror	x6, x6, #(64-21)                          SEP
	ror	x7, x7, #(64-45)                          SEP
	ror	x12, x12, #(64-61)                          SEP      str x26, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]
	ror	x9, x9, #(64-15)                          SEP
	ror	x14, x14, #(64-56)                          SEP
	ror	x11, x11, #(64-14)                          SEP      eor vAba.16b, vAba.16b, vvtmp.16b
	ror	x13, x13, #(64-18)                          SEP
	ror	x25, x25, #(64-1)                           SEP
	ror	x15, x15, #(64-2)                           SEP
	ror	x20, x20, #(64-62)                          SEP      .unreq vvtmp
	ror	x17, x17, #(64-28)                          SEP
	ror	x22, x22, #(64-20)                          SEP
	ror	x19, x19, #(64-27)                          SEP      .unreq vvtmpq
	ror	x24, x24, #(64-36)                          SEP
	ror	x18, x18, #(64-55)                          SEP
.endm


#define KECCAK_F1600_ROUNDS 24

.globl	_keccak_f1600_x4_hybrid_asm_v5p_opt
.private_extern	_keccak_f1600_x4_hybrid_asm_v5p_opt
.globl	__keccak_f1600_x4_hybrid_asm_v5p_opt
.private_extern	__keccak_f1600_x4_hybrid_asm_v5p_opt
.text
.align	4

_keccak_f1600_x4_hybrid_asm_v5p_opt:
__keccak_f1600_x4_hybrid_asm_v5p_opt:
	alloc_stack
	save_gprs
	save_vregs
	str	input_addr, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_INPUT)]

	adr	const_addr, round_constants_vec
	str	const_addr, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]

	load_input_vector

	add	input_addr, input_addr, #16

	mov	out_count, #0
outer_loop:
	str	out_count, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT_OUT)]

	load_input_scalar
	str	input_addr, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CUR_INPUT)]

	sub	sp, sp, #8*6
	hybrid_round_initial
1:
	hybrid_round_noninitial
	cmp	count, #(KECCAK_F1600_ROUNDS-3)
	blt	1b
	hybrid_round_final

	add	sp, sp, #8*6

	ldr	input_addr, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_CUR_INPUT)]
	store_input_scalar
	add	input_addr, input_addr, #8

	ldr	out_count, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT_OUT)]
	add	out_count, out_count, #1
	cmp	out_count, #2
	blt	outer_loop

	ldr	input_addr, [sp, (STACK_BASE_TMP_GPRS + STACK_OFFSET_INPUT)]
	store_input_vector

	restore_vregs
	restore_gprs
	free_stack
	ret
.byte	75,101,99,99,97,107,45,49,54,48,48,32,97,98,115,111,114,98,32,97,110,100,32,115,113,117,101,101,122,101,32,102,111,114,32,65,82,77,118,56,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	2
#endif  // !OPENSSL_NO_ASM && defined(__AARCH64EL__) && defined(__APPLE__)
#if defined(__ELF__)
// See https://www.airs.com/blog/archives/518.
.section .note.GNU-stack,"",%progbits
#endif
