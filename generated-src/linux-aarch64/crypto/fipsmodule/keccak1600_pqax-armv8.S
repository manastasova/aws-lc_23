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
#include <openssl/arm_arch.h>
.text
.balign	64

.type	round_constants, %object
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
.size	round_constants, .-round_constants


 # Define the stack arrangement for the |SHA3_Absorb_lazy| function
#define OFFSET_RESERVED_BYTES (4*8)
#define STACK_OFFSET_BITSTATE_ADR (OFFSET_RESERVED_BYTES + 0*8)
#define STACK_OFFSET_INPUT_ADR (OFFSET_RESERVED_BYTES + 1*8)
#define STACK_OFFSET_LENGTH (OFFSET_RESERVED_BYTES + 2*8)
#define STACK_OFFSET_BLOCK_SIZE (OFFSET_RESERVED_BYTES + 3*8)

 # Define the stack arrangement for the |keccak_f1600_x1_scalar_asm_lazy_rotation| function
#define STACK_OFFSET_CONST (1*8)
#define STACK_OFFSET_COUNT (2*8)
#define STACK_OFFSET_x27_A44 (4*8)
#define STACK_OFFSET_x27_C2_E3 (5*8)

 # Define the macros
.macro	alloc_stack_save_GPRs_absorb
	stp	x29, x30, [sp, #-128]!
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	x25, x26, [sp, #64]
	stp	x27, x28, [sp, #80]
	sub	sp, sp, #64
.endm

.macro	free_stack_restore_GPRs_absorb
	ldp	x19, x20, [sp, #16+64]
	add	sp, sp, #64
	ldp	x21, x22, [sp, #32]
	ldp	x23, x24, [sp, #48]
	ldp	x25, x26, [sp, #64]
	ldp	x27, x28, [sp, #80]
	ldp	x29, x30, [sp], #128
.endm

.macro	offload_and_move_args
	stp	x0, x1, [sp, #STACK_OFFSET_BITSTATE_ADR]			// offload arguments
	stp	x2, x3, [sp, #STACK_OFFSET_LENGTH]
	mov	x29, x0			// uint64_t A[5][5]
	mov	x26, x1			// const void *inp
	mov	x0, x2			// size_t len
	mov	x28, x3			// size_t bsz
.endm

.macro	load_bitstate
	ldp	x1, x6, [x29, #16*0]
	ldp	x11, x16, [x29, #16*1]
	ldp	x21, x2, [x29, #16*2]
	ldp	x7, x12, [x29, #16*3]
	ldp	x17, x22, [x29, #16*4]
	ldp	x3, x8, [x29, #16*5]
	ldp	x13, x25, [x29, #16*6]
	ldp	x23, x4, [x29, #16*7]
	ldp	x9, x14, [x29, #16*8]
	ldp	x19, x24, [x29, #16*9]
	ldp	x5, x10, [x29, #16*10]
	ldp	x15, x20, [x29, #16*11]
	ldr	x27, [x29, #16*12]
.endm

.macro	load_constant_ptr
	adr	x26, round_constants
.endm

.macro	store_bitstate
	stp	x1, x6, [x29, #16*0]
	stp	x11, x16, [x29, #16*1]
	stp	x21, x2, [x29, #16*2]
	stp	x7, x12, [x29, #16*3]
	stp	x17, x22, [x29, #16*4]
	stp	x3, x8, [x29, #16*5]
	stp	x13, x25, [x29, #16*6]
	stp	x23, x4, [x29, #16*7]
	stp	x9, x14, [x29, #16*8]
	stp	x19, x24, [x29, #16*9]
	stp	x5, x10, [x29, #16*10]
	stp	x15, x20, [x29, #16*11]
	str	x27, [x29, #16*12]
.endm

.macro	alloc_stack_save_GPRs_KeccakF1600
	stp	x29, x30, [sp, #-128]!
	add	x29, sp, #0
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	x25, x26, [sp, #64]
	stp	x27, x28, [sp, #80]
	sub	sp, sp, #48+32
	stp	x19, x20, [sp, #48]
	stp	x21, x22, [sp, #64]
	str	x0, [sp, #32]
	ldp	x1, x6, [x0, #16*0]
	ldp	x11, x16, [x0, #16*1]
	ldp	x21, x2, [x0, #16*2]
	ldp	x7, x12, [x0, #16*3]
	ldp	x17, x22, [x0, #16*4]
	ldp	x3, x8, [x0, #16*5]
	ldp	x13, x25, [x0, #16*6]
	ldp	x23, x4, [x0, #16*7]
	ldp	x9, x14, [x0, #16*8]
	ldp	x19, x24, [x0, #16*9]
	ldp	x5, x10, [x0, #16*10]
	ldp	x15, x20, [x0, #16*11]
	ldr	x27, [x0, #16*12]
.endm

.macro	free_stack_restore_GPRs_KeccakF1600
	ldr	x0, [sp, #32]
	stp	x1, x6, [x0, #16*0]
	stp	x11, x16, [x0, #16*1]
	stp	x21, x2, [x0, #16*2]
	stp	x7, x12, [x0, #16*3]
	stp	x17, x22, [x0, #16*4]
	stp	x3, x8, [x0, #16*5]
	stp	x13, x25, [x0, #16*6]
	stp	x23, x4, [x0, #16*7]
	stp	x9, x14, [x0, #16*8]
	stp	x19, x24, [x0, #16*9]
	stp	x5, x10, [x0, #16*10]
	stp	x15, x20, [x0, #16*11]
	str	x27, [x0, #16*12]
	ldp	x19, x20, [x29, #16]
	ldp	x19, x20, [sp, #48]
	ldp	x21, x22, [sp, #64]
	add	sp, sp, #48+32
	ldp	x21, x22, [x29, #32]
	ldp	x23, x24, [x29, #48]
	ldp	x25, x26, [x29, #64]
	ldp	x27, x28, [x29, #80]
	ldp	x29, x30, [sp], #128
.endm


.macro	keccak_f1600_round_initial

	eor	x29, x24, x27

	str	x27, [sp, #STACK_OFFSET_x27_A44]  // store A[4][4] from bit state

	eor	x30, x4, x5
	eor	x26, x9, x10
	eor	x27, x14, x15
	eor	x28, x19, x20
	eor	x30, x3, x30
	eor	x26, x8, x26
	eor	x27, x13, x27
	eor	x28, x25, x28
	eor	x29, x23, x29
	eor	x30, x2, x30
	eor	x26, x7, x26
	eor	x27, x12, x27
	eor	x28, x17, x28
	eor	x29, x22, x29
	eor	x30, x1, x30
	eor	x26, x6, x26
	eor	x27, x11, x27
	eor	x28, x16, x28
	eor	x29, x21, x29

	eor	x0, x30, x27, ROR #63
	eor	x27, x27, x29, ROR #63
	eor	x29, x29, x26, ROR #63
	eor	x26, x26, x28, ROR #63
	eor	x28, x28, x30, ROR #63

	eor	x30, x1, x29
	eor	x1, x11, x26
	eor	x11, x13, x26
	eor	x13, x25, x27
	eor	x25, x24, x28
	eor	x24, x20, x27
	eor	x20, x4, x29
	eor	x4, x6, x0
	eor	x6, x17, x27
	eor	x17, x9, x0
	eor	x9, x12, x26
	eor	x12, x3, x29
	eor	x3, x16, x27
	eor	x16, x19, x27
	eor	x19, x14, x26
	eor	x14, x8, x0
	eor	x8, x22, x28
	eor	x22, x15, x26
	eor	x15, x23, x28
	eor	x23, x5, x29
	eor	x5, x21, x28

	ldr	x27, [sp, STACK_OFFSET_x27_A44]

	eor	x21, x27, x28
	eor	x27, x10, x0
	eor	x10, x2, x29
	eor	x28, x7, x0

	// Load address contants into x26
	load_constant_ptr

	bic	x0, x12, x8, ROR #47
	bic	x29, x17, x12, ROR #42
	eor	x2, x0, x3, ROR #39
	bic	x0, x22, x17, ROR #16
	eor	x7, x29, x8, ROR #25
	bic	x29, x3, x22, ROR #31
	eor	x12, x0, x12, ROR #58
	bic	x0, x8, x3, ROR #56
	eor	x17, x29, x17, ROR #47
	bic	x29, x13, x9, ROR #19
	eor	x22, x0, x22, ROR #23
	bic	x0, x25, x13, ROR #47
	eor	x3, x29, x4, ROR #24
	bic	x29, x23, x25, ROR #10
	eor	x8, x0, x9, ROR #2
	bic	x0, x4, x23, ROR #47
	eor	x13, x29, x13, ROR #57
	bic	x29, x9, x4, ROR #5
	eor	x25, x0, x25, ROR #57
	bic	x0, x14, x10, ROR #38
	eor	x23, x29, x23, ROR #52
	bic	x29, x19, x14, ROR #5
	eor	x4, x0, x5, ROR #47
	bic	x0, x24, x19, ROR #41
	eor	x9, x29, x10, ROR #43
	bic	x29, x5, x24, ROR #35
	eor	x14, x0, x14, ROR #46
	bic	x0, x10, x5, ROR #9

	str	x26, [sp, #(STACK_OFFSET_CONST)]
	ldr	x26, [x26]

	eor	x19, x29, x19, ROR #12
	bic	x29, x15, x6, ROR #48
	eor	x24, x0, x24, ROR #44
	bic	x0, x20, x15, ROR #2
	eor	x5, x29, x1, ROR #41
	bic	x29, x27, x20, ROR #25
	eor	x10, x0, x6, ROR #50
	bic	x0, x1, x27, ROR #60
	eor	x15, x29, x15, ROR #27
	bic	x29, x6, x1, ROR #57
	eor	x20, x0, x20, ROR #21
	bic	x0, x11, x28, ROR #63
	eor	x27, x29, x27, ROR #53

	str	x27, [sp, STACK_OFFSET_x27_A44]

	bic	x29, x16, x11, ROR #42
	eor	x1, x30, x0, ROR #21
	bic	x0, x21, x16, ROR #57
	eor	x6, x29, x28, ROR #41
	bic	x29, x30, x21, ROR #50
	eor	x11, x0, x11, ROR #35
	bic	x0, x28, x30, ROR #44
	eor	x16, x29, x16, ROR #43
	eor	x21, x0, x21, ROR #30

	mov	w27, #1

	eor	x1, x1, x26
	str	w27, [sp, #STACK_OFFSET_COUNT]

.endm

.macro	keccak_f1600_round_noninitial

	eor	x27, x15, x11, ROR #52
	eor	x30, x1, x2, ROR #61
	eor	x29, x23, x22, ROR #50
	eor	x26, x8, x9, ROR #57
	eor	x28, x16, x25, ROR #63
	eor	x27, x27, x13, ROR #48
	eor	x30, x30, x4, ROR #54
	eor	x29, x29, x24, ROR #34
	eor	x26, x26, x6, ROR #51
	eor	x28, x28, x19, ROR #37
	eor	x27, x27, x14, ROR #10
	eor	x30, x30, x3, ROR #39
	eor	x29, x29, x21, ROR #26
	eor	x26, x26, x10, ROR #31
	eor	x28, x28, x17, ROR #36
	eor	x27, x27, x12, ROR #5

	str	x27, [sp, STACK_OFFSET_x27_C2_E3]

	eor	x30, x30, x5, ROR #25

	ldr	x27, [sp, STACK_OFFSET_x27_A44]

	eor	x29, x29, x27, ROR #15
	eor	x26, x26, x7, ROR #27
	eor	x28, x28, x20, ROR #2

	ldr	x27, [sp, STACK_OFFSET_x27_C2_E3]

	eor	x0, x30, x27, ROR #61
	ror	x27, x27, 62
	eor	x27, x27, x29, ROR #57
	ror	x29, x29, 58
	eor	x29, x29, x26, ROR #55
	ror	x26, x26, 56
	eor	x26, x26, x28, ROR #63
	eor	x28, x28, x30, ROR #63

	eor	x30, x29, x1
	eor	x1, x26, x11, ROR #50
	eor	x11, x26, x13, ROR #46
	eor	x13, x27, x25, ROR #63
	eor	x25, x28, x24, ROR #28
	eor	x24, x27, x20, ROR #2
	eor	x20, x29, x4, ROR #54
	eor	x4, x0, x6, ROR #43
	eor	x6, x27, x17, ROR #36
	eor	x17, x0, x9, ROR #49
	eor	x9, x26, x12, ROR #3
	eor	x12, x29, x3, ROR #39
	eor	x3, x27, x16
	eor	x16, x27, x19, ROR #37
	eor	x19, x26, x14, ROR #8
	eor	x14, x0, x8, ROR #56
	eor	x8, x28, x22, ROR #44
	eor	x22, x26, x15, ROR #62
	eor	x15, x28, x23, ROR #58
	eor	x23, x29, x5, ROR #25
	eor	x5, x28, x21, ROR #20

	ldr	x27, [sp, #STACK_OFFSET_x27_A44]

	eor	x21, x28, x27, ROR #9
	eor	x27, x0, x10, ROR #23
	eor	x10, x29, x2, ROR #61
	eor	x28, x0, x7, ROR #19

	bic	x0, x12, x8, ROR #47
	bic	x29, x17, x12, ROR #42
	eor	x2, x0, x3, ROR #39
	bic	x0, x22, x17, ROR #16
	eor	x7, x29, x8, ROR #25
	bic	x29, x3, x22, ROR #31
	eor	x12, x0, x12, ROR #58
	bic	x0, x8, x3, ROR #56
	eor	x17, x29, x17, ROR #47
	bic	x29, x13, x9, ROR #19
	eor	x22, x0, x22, ROR #23
	bic	x0, x25, x13, ROR #47
	eor	x3, x29, x4, ROR #24
	bic	x29, x23, x25, ROR #10
	eor	x8, x0, x9, ROR #2
	bic	x0, x4, x23, ROR #47
	eor	x13, x29, x13, ROR #57
	bic	x29, x9, x4, ROR #5
	eor	x25, x0, x25, ROR #57
	bic	x0, x14, x10, ROR #38
	eor	x23, x29, x23, ROR #52
	bic	x29, x19, x14, ROR #5
	eor	x4, x0, x5, ROR #47
	bic	x0, x24, x19, ROR #41
	eor	x9, x29, x10, ROR #43
	bic	x29, x5, x24, ROR #35
	eor	x14, x0, x14, ROR #46
	bic	x0, x10, x5, ROR #9
	eor	x19, x29, x19, ROR #12
	bic	x29, x15, x6, ROR #48
	eor	x24, x0, x24, ROR #44
	bic	x0, x20, x15, ROR #2
	eor	x5, x29, x1, ROR #41
	bic	x29, x27, x20, ROR #25
	eor	x10, x0, x6, ROR #50
	bic	x0, x1, x27, ROR #60
	eor	x15, x29, x15, ROR #27
	bic	x29, x6, x1, ROR #57
	eor	x20, x0, x20, ROR #21
	bic	x0, x11, x28, ROR #63
	eor	x27, x29, x27, ROR #53

	str	x27, [sp, #STACK_OFFSET_x27_A44]

	ldr	w27, [sp, #STACK_OFFSET_COUNT]

	load_constant_ptr_stack
	ldr	x26, [x26, w27, UXTW #3]
	add	w27, w27, #1
	str	w27 , [sp , #STACK_OFFSET_COUNT]

	bic	x29, x16, x11, ROR #42
	eor	x1, x30, x0, ROR #21
	bic	x0, x21, x16, ROR #57
	eor	x6, x29, x28, ROR #41
	bic	x29, x30, x21, ROR #50
	eor	x11, x0, x11, ROR #35
	bic	x0, x28, x30, ROR #44
	eor	x16, x29, x16, ROR #43
	eor	x21, x0, x21, ROR #30

	eor	x1, x1, x26

.endm

.macro	final_rotate_store
	ldr	x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
	ror	x2, x2, #(64-3)
	ror	x21, x21, #(64-44)
	ror	x3, x3, #(64-25)
	ror	x8, x8, #(64-8)
	ror	x4, x4, #(64-10)
	ror	x23, x23, #(64-6)
	ror	x5, x5, #(64-39)
	ror	x10, x10, #(64-41)
	ror	x6, x6, #(64-21)
	ror	x7, x7, #(64-45)
	ror	x12, x12, #(64-61)
	ror	x9, x9, #(64-15)
	ror	x14, x14, #(64-56)
	ror	x11, x11, #(64-14)
	ror	x13, x13, #(64-18)
	ror	x25, x25, #(64-1)
	ror	x15, x15, #(64-2)
	ror	x20, x20, #(64-62)
	ror	x17, x17, #(64-28)
	ror	x22, x22, #(64-20)
	ror	x19, x19, #(64-27)
	ror	x24, x24, #(64-36)
	ror	x27, x27, #(64-55)
.endm

#define KECCAK_F1600_ROUNDS 24

.macro	load_constant_ptr_stack
	ldr	x26, [sp, #(STACK_OFFSET_CONST)]
.endm

.type	keccak_f1600_x1_scalar_asm_lazy_rotation, %function
.align	4
keccak_f1600_x1_scalar_asm_lazy_rotation:
	AARCH64_SIGN_LINK_REGISTER
	sub	sp, sp, #12*8
	stp	x30, x29, [sp, #6*8]

	keccak_f1600_round_initial

loop:
	keccak_f1600_round_noninitial
	cmp	w27, #(KECCAK_F1600_ROUNDS-1)
	ble	loop

	final_rotate_store

	ldp	x30, x29, [sp, #6*8]
	add	sp, sp, #12*8
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	keccak_f1600_x1_scalar_asm_lazy_rotation, .-keccak_f1600_x1_scalar_asm_lazy_rotation

.type	KeccakF1600, %function
.align	5
KeccakF1600:
	AARCH64_SIGN_LINK_REGISTER
	alloc_stack_save_GPRs_KeccakF1600

	bl	keccak_f1600_x1_scalar_asm_lazy_rotation

	free_stack_restore_GPRs_KeccakF1600
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	KeccakF1600, .-KeccakF1600

.globl	SHA3_Absorb_lazy
.hidden	SHA3_Absorb_lazy
.type	SHA3_Absorb_lazy, %function
.align	5
SHA3_Absorb_lazy:
	AARCH64_SIGN_LINK_REGISTER
	alloc_stack_save_GPRs_absorb
	offload_and_move_args
	load_bitstate
	b	.Loop_absorb
.align	4
.Loop_absorb:
	subs	x29, x0, x28		// rem = len - bsz
	blo	.Labsorbed
	str	x29, [sp, #STACK_OFFSET_LENGTH]			// save rem
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x1, x1, x29
	cmp	x28, #8*(0+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x6, x6, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x11, x11, x29
	cmp	x28, #8*(2+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x16, x16, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x21, x21, x29
	cmp	x28, #8*(4+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x2, x2, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x7, x7, x29
	cmp	x28, #8*(6+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x12, x12, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x17, x17, x29
	cmp	x28, #8*(8+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x22, x22, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x3, x3, x29
	cmp	x28, #8*(10+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x8, x8, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x13, x13, x29
	cmp	x28, #8*(12+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x25, x25, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x23, x23, x29
	cmp	x28, #8*(14+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x4, x4, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x9, x9, x29
	cmp	x28, #8*(16+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x14, x14, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x19, x19, x29
	cmp	x28, #8*(18+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x24, x24, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x5, x5, x29
	cmp	x28, #8*(20+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x10, x10, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x15, x15, x29
	cmp	x28, #8*(22+2)
	blo	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x20, x20, x29
	beq	.Lprocess_block
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x1, x1, x29
.Lprocess_block:
	str	x26, [sp, #STACK_OFFSET_INPUT_ADR]			// save input address

	bl	keccak_f1600_x1_scalar_asm_lazy_rotation

	ldr	x26, [sp, #STACK_OFFSET_INPUT_ADR]			// restore arguments
	ldp	x0, x28, [sp, #STACK_OFFSET_LENGTH]
	b	.Loop_absorb
.align	4
.Labsorbed:
	ldr	x29, [sp, #STACK_OFFSET_BITSTATE_ADR]
	store_bitstate
	free_stack_restore_GPRs_absorb
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	SHA3_Absorb_lazy, .-SHA3_Absorb_lazy
.globl	SHA3_Squeeze_lazy
.hidden	SHA3_Squeeze_lazy
.type	SHA3_Squeeze_lazy, %function
.align	5
SHA3_Squeeze_lazy:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	cmp	x2, #0
	beq	.Lsqueeze_abort
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	mov	x19, x0			// put x15de arguments
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3
.Loop_squeeze:
	ldr	x4, [x0], #8
	cmp	x21, #8
	blo	.Lsqueeze_tail
#ifdef	__AARCH64EB__
	rev	x4, x4
#endif
	str	x4, [x20], #8
	subs	x21, x21, #8
	beq	.Lsqueeze_done
	subs	x3, x3, #8
	bhi	.Loop_squeeze
	mov	x0, x19
	bl	KeccakF1600
	mov	x0, x19
	mov	x3, x22
	b	.Loop_squeeze
.align	4
.Lsqueeze_tail:
	strb	w4, [x20], #1
	lsr	x4, x4, #8
	subs	x21, x21, #1
	beq	.Lsqueeze_done
	strb	w4, [x20], #1
	lsr	x4, x4, #8
	subs	x21, x21, #1
	beq	.Lsqueeze_done
	strb	w4, [x20], #1
	lsr	x4, x4, #8
	subs	x21, x21, #1
	beq	.Lsqueeze_done
	strb	w4, [x20], #1
	lsr	x4, x4, #8
	subs	x21, x21, #1
	beq	.Lsqueeze_done
	strb	w4, [x20], #1
	lsr	x4, x4, #8
	subs	x21, x21, #1
	beq	.Lsqueeze_done
	strb	w4, [x20], #1
	lsr	x4, x4, #8
	subs	x21, x21, #1
	beq	.Lsqueeze_done
	strb	w4, [x20], #1
.Lsqueeze_done:
	ldp	x19, x20, [sp, #16]
	ldp	x21, x22, [sp, #32]
.Lsqueeze_abort:
	ldp	x29, x30, [sp], #48
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	SHA3_Squeeze_lazy, .-SHA3_Squeeze_lazy
.byte	75,101,99,99,97,107,45,49,54,48,48,32,97,98,115,111,114,98,32,97,110,100,32,115,113,117,101,101,122,101,32,102,111,114,32,65,82,77,118,56,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	2
#endif  // !OPENSSL_NO_ASM && defined(__AARCH64EL__) && defined(__ELF__)
#if defined(__ELF__)
// See https://www.airs.com/blog/archives/518.
.section .note.GNU-stack,"",%progbits
#endif
