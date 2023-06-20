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

 # Define the stack arrangement for the |SHA3_Absorb_lazy_absorb| function
#define OFFSET_RESERVED_BYTES (4*8)
#define STACK_OFFSET_BITSTATE_ADR (OFFSET_RESERVED_BYTES + 0*8)
#define STACK_OFFSET_INPUT_ADR (OFFSET_RESERVED_BYTES + 1*8)
#define STACK_OFFSET_LENGTH (OFFSET_RESERVED_BYTES + 2*8)
#define STACK_OFFSET_BLOCK_SIZE (OFFSET_RESERVED_BYTES + 3*8)

 # Define the stack arrangement for the |keccak_f1600_x1_scalar_asm_lazy_absorb| function
#define STACK_OFFSET_CONST (0*8)
#define STACK_OFFSET_COUNT (1*8)
#define STACK_OFFSET_x27_A44 (2*8)
#define STACK_OFFSET_x27_C2_E3 (3*8)

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

	str	x27, [sp, #STACK_OFFSET_x27_A44]  // store x27 from bit state

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

	eor	x30, x1, x29 //leftover 0
	eor	x1, x11, x26 //leftover 62
	eor	x11, x13, x26 //leftover 43
	eor	x13, x25, x27
	eor	x25, x24, x28 //leftover 8
	eor	x24, x20, x27
	eor	x20, x4, x29 //leftover 41
	eor	x4, x6, x0 //leftover 1
	eor	x6, x17, x27
	eor	x17, x9, x0 //leftover 45
	eor	x9, x12, x26 //leftover 6
	eor	x12, x3, x29 //leftover 3
	eor	x3, x16, x27
	eor	x16, x19, x27
	eor	x19, x14, x26 //leftover 15
	eor	x14, x8, x0 //leftover 10
	eor	x8, x22, x28 //leftover 20
	eor	x22, x15, x26 //leftover 61
	eor	x15, x23, x28 //leftover 39
	eor	x23, x5, x29 //leftover 18
	eor	x5, x21, x28 //leftover 27

	ldr	x27, [sp, STACK_OFFSET_x27_A44]

	eor	x21, x27, x28
	eor	x27, x10, x0
	eor	x10, x2, x29 //leftover 36
	eor	x28, x7, x0 //leftover 44

	// Load address contants into x26
	load_constant_ptr

	bic	x0, x12, x8, ROR #47  // A<<3, B<<20, C<<64-(20-3), leftover    3
	bic	x29, x17, x12, ROR #42  // A<<45, B<<3, C<<64-(-), leftover       45
	eor	x2, x0, x3, ROR #39   // A<<3, B<<28, C<<64-(28-3), leftover    3
	bic	x0, x22, x17, ROR #16  // A<<61, B<<45, C<<64-(-), leftover      61
	eor	x7, x29, x8, ROR #25  // A<<45, B<<20, C<<64-(-), leftover       45
	bic	x29, x3, x22, ROR #31  // A<<28, B<<61, C<<64-(-), leftover      28
	eor	x12, x0, x12, ROR #58  // A<<61, B<<3, C<<64-(-), leftover        61
	bic	x0, x8, x3, ROR #56  // A<<20, B<<28, C<<64-(-), leftover      20
	eor	x17, x29, x17, ROR #47  // A<<28, B<<45, C<<64-(-), leftover         28
	bic	x29, x13, x9, ROR #19  // A<<25, B<<6, C<<64-(6-25), leftover    25
	eor	x22, x0, x22, ROR #23  // A<<20, B<<61, C<<64-(-), leftover         20
	bic	x0, x25, x13, ROR #47  // A<<8, B<<25, C<<64-(-), leftover       8
	eor	x3, x29, x4, ROR #24  // A<<25, B<<1, C<<64-(-), leftover        25
	bic	x29, x23, x25, ROR #10  // A<<18, B<<8, C<<64-(8-18), leftover    18
	eor	x8, x0, x9, ROR #2  // A<<8, B<<6, C<<64-(-), leftover          8
	bic	x0, x4, x23, ROR #47  // A<<1, B<<18, C<<64-(-), leftover       1
	eor	x13, x29, x13, ROR #57  // A<<18, B<<25, C<<64-(25-54), leftover      18
	bic	x29, x9, x4, ROR #5  // A<<6, B<<1, C<<64-(-), leftover         6
	eor	x25, x0, x25, ROR #57  // A<<1, B<<8, C<<64-(-), leftover         1
	bic	x0, x14, x10, ROR #38  // A<<10, B<<36, C<<64-(-), leftover      10
	eor	x23, x29, x23, ROR #52  // A<<6, B<<18, C<<64-(-), leftover        6
	bic	x29, x19, x14, ROR #5  // A<<15, B<<10, C<<64-(-), leftover       15
	eor	x4, x0, x5, ROR #47  // A<<10, B<<27, C<<64-(-), leftover       10
	bic	x0, x24, x19, ROR #41  // A<<56, B<<15, C<<64-(-), leftover      56
	eor	x9, x29, x10, ROR #43  // A<<15, B<<36, C<<64-(-), leftover       15
	bic	x29, x5, x24, ROR #35  // A<<27, B<<56, C<<64-(-), leftover      27
	eor	x14, x0, x14, ROR #46  // A<<56, B<<10, C<<64-(-), leftover       56
	bic	x0, x10, x5, ROR #9  // A<<36, B<<27, C<<64-(-), leftover       36

	str	x26, [sp, #(STACK_OFFSET_CONST)]
	ldr	x26, [x26]

	eor	x19, x29, x19, ROR #12  // A<<27, B<<15, C<<64-(-), leftover       27
	bic	x29, x15, x6, ROR #48  // A<<39, B<<55, C<<64-(-), leftover      39
	eor	x24, x0, x24, ROR #44  // A<<36, B<<56, C<<64-(-), leftover       36
	bic	x0, x20, x15, ROR #2  // A<<41, B<<39, C<<64-(-), leftover       41
	eor	x5, x29, x1, ROR #41  // A<<39, B<<62, C<<64-(-), leftover       39
	bic	x29, x27, x20, ROR #25  // A<<2, B<<41, C<<64-(-), leftover       2
	eor	x10, x0, x6, ROR #50  // A<<41, B<<55, C<<64-(-), leftover       41
	bic	x0, x1, x27, ROR #60  // A<<62, B<<2, C<<64-(-), leftover       62
	eor	x15, x29, x15, ROR #27  // A<<2, B<<39, C<<64-(39-2), leftover     2
	bic	x29, x6, x1, ROR #57  // A<<55, B<<62, C<<64-(-), leftover      55
	eor	x20, x0, x20, ROR #21  // A<<62, B<<41, C<<64-(-), leftover       62
	bic	x0, x11, x28, ROR #63  // A<<43, B<<44, C<<64-(44-43), leftover  43
	eor	x27, x29, x27, ROR #53

	str	x27, [sp, STACK_OFFSET_x27_A44]

	bic	x29, x16, x11, ROR #42 // A<<21, B<<43, C<<64-(-), leftover       21
	eor	x1, x30, x0, ROR #21 // A<<0, B<<43, C<<64-(-), leftover         0
	bic	x0, x21, x16, ROR #57 // A<<14, B<<21, C<<64-(-), leftover       14
	eor	x6, x29, x28, ROR #41 // A<<21, B<<44, C<<64-(-), leftover        21
	bic	x29, x30, x21, ROR #50 // A<<0, B<<14, C<<64-(-), leftover        0
	eor	x11, x0, x11, ROR #35 // A<<14, B<<43, C<<64-(-), leftover        14
	bic	x0, x28, x30, ROR #44 // A<<44, B<<0, C<<64-(-), leftover        44
	eor	x16, x29, x16, ROR #43 // A<<0, B<<21, C<<64-(-), leftover         0
	eor	x21, x0, x21, ROR #30 // A<<44, B<<14, C<<64-(-), leftover        44

	mov	w27, #1

	eor	x1, x1, x26
	str	w27, [sp, #STACK_OFFSET_COUNT]
.endm

.macro	keccak_f1600_round_noninitial
	eor	x27, x15, x11, ROR #52 // A<<2, B<<14, C<<64-(14-2), leftover       2
	eor	x30, x1, x2, ROR #61 // A<<0, B<<3, C<<64-(3-0), leftover         0
	eor	x29, x23, x22, ROR #50 // A<<6, B<< 20, C<<64-(-), leftover         6
	eor	x26, x8, x9, ROR #57 // A<<8, B<<15, C<<64-(-), leftover          8
	eor	x28, x16, x25, ROR #63 // A<<0, B<<1, C<<64-(-), leftover           0
	eor	x27, x27, x13, ROR #48 // A<<2, B<<18, C<<64-(18-2), leftover          2
	eor	x30, x30, x4, ROR #54 // A<<0, B<<10, C<<64-(-), leftover             0
	eor	x29, x29, x24, ROR #34 // A<<6, B<<36, C<<64-(-), leftover             6
	eor	x26, x26, x6, ROR #51 // A<<, B<<21, C<<64-(-), leftover              8
	eor	x28, x28, x19, ROR #37 // A<<, B<<27, C<<64-(-), leftover              0
	eor	x27, x27, x14, ROR #10 // A<<2 , B<<56, C<<64-(-), leftover            2
	eor	x30, x30, x3, ROR #39 // A<<0, B<<20, C<<64-(-), leftover             0
	eor	x29, x29, x21, ROR #26 // A<<6, B<<44, C<<64-(-), leftover             6
	eor	x26, x26, x10, ROR #31 // A<<, B<<41, C<<64-(-), leftover              8
	eor	x28, x28, x17, ROR #36 // A<<, B<<28, C<<64-(-), leftover              0
	eor	x27, x27, x12, ROR #5 // A<<2 , B<<61, C<<64-(-), leftover             2

	str	x27, [sp, STACK_OFFSET_x27_C2_E3]

	eor	x30, x30, x5, ROR #25 // A<<, B<<, C<<64-(-), leftover     0

	ldr	x27, [sp, STACK_OFFSET_x27_A44]

	eor	x29, x29, x27, ROR #15 // A<<6, B<<, C<<64-(-), leftover      6
	eor	x26, x26, x7, ROR #27 // A<< 8, B<<, C<<64-(-), leftover     8
	eor	x28, x28, x20, ROR #2 // A<<, B<<, C<<64-(-), leftover          0

	ldr	x27, [sp, STACK_OFFSET_x27_C2_E3]

	eor	x0, x30, x27, ROR #61
	ror	x27, x27, 62
	eor	x27, x27, x29, ROR #57
	ror	x29, x29, 58
	eor	x29, x29, x26, ROR #55 // A<<0, B<<8, C<<64-(8-0)-1, leftover    0
	ror	x26, x26, 56
	eor	x26, x26, x28, ROR #63 // A<<0, B<<0, C<<64-(-)-1, leftover     0
	eor	x28, x28, x30, ROR #63 // A<<0, B<<0, C<<64-(-)-1, leftover     0


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

.macro	final_rotate_sha3_224
	ldr	x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
	ror	x19, x19, #(64-27)
	ror	x24, x24, #(64-36)
	ror	x5, x5, #(64-39)
	ror	x10, x10, #(64-41)
	ror	x15, x15, #(64-2)
	ror	x20, x20, #(64-62)
	ror	x27, x27, #(64-55)
.endm


.macro	final_rotate_sha3_256_shake256
	ldr	x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
	ror	x14, x14, #(64-56)
	ror	x19, x19, #(64-27)
	ror	x24, x24, #(64-36)
	ror	x5, x5, #(64-39)
	ror	x10, x10, #(64-41)
	ror	x15, x15, #(64-2)
	ror	x20, x20, #(64-62)
	ror	x27, x27, #(64-55)
.endm

.macro	final_rotate_sha3_384
	ldr	x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
	ror	x25, x25, #(64-1)
	ror	x23, x23, #(64-6)
	ror	x4, x4, #(64-10)
	ror	x9, x9, #(64-15)
	ror	x14, x14, #(64-56)
	ror	x19, x19, #(64-27)
	ror	x24, x24, #(64-36)
	ror	x5, x5, #(64-39)
	ror	x10, x10, #(64-41)
	ror	x15, x15, #(64-2)
	ror	x20, x20, #(64-62)
	ror	x27, x27, #(64-55)
.endm

.macro	final_rotate_sha3_512
	ldr	x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
	ror	x22, x22, #(64-20)
	ror	x3, x3, #(64-25)
	ror	x8, x8, #(64-8)
	ror	x13, x13, #(64-18)
	ror	x25, x25, #(64-1)
	ror	x23, x23, #(64-6)
	ror	x4, x4, #(64-10)
	ror	x9, x9, #(64-15)
	ror	x14, x14, #(64-56)
	ror	x19, x19, #(64-27)
	ror	x24, x24, #(64-36)
	ror	x5, x5, #(64-39)
	ror	x10, x10, #(64-41)
	ror	x15, x15, #(64-2)
	ror	x20, x20, #(64-62)
	ror	x27, x27, #(64-55)
.endm

.macro	final_rotate_shake128
	ldr	x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
	ror	x10, x10, #(64-41)
	ror	x15, x15, #(64-2)
	ror	x20, x20, #(64-62)
	ror	x27, x27, #(64-55)
.endm

.macro	final_rotate
	ldr	x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
	ror	x2, x2, #(64-3) //61
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

.type	keccak_f1600_x1_scalar_asm_lazy_absorb_first, %function
.align	4
keccak_f1600_x1_scalar_asm_lazy_absorb_first:
	AARCH64_SIGN_LINK_REGISTER
	stp	x30, x29, [sp, #4*8]

	keccak_f1600_round_initial

loop1:
	keccak_f1600_round_noninitial
	cmp	w27, #(KECCAK_F1600_ROUNDS-1)
	ble	loop1

	ldp	x30, x29, [sp, #4*8]
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	keccak_f1600_x1_scalar_asm_lazy_absorb_first, .-keccak_f1600_x1_scalar_asm_lazy_absorb_first


.type	keccak_f1600_x1_scalar_asm_lazy_absorb_non_first, %function
.align	4
keccak_f1600_x1_scalar_asm_lazy_absorb_non_first:
	AARCH64_SIGN_LINK_REGISTER
	stp	x30, x29, [sp, #4*8]
	keccak_f1600_round_initial

loop2:
	keccak_f1600_round_noninitial
	cmp	w27, #(KECCAK_F1600_ROUNDS-1)
	ble	loop2

	ldp	x30, x29, [sp, #4*8]
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	keccak_f1600_x1_scalar_asm_lazy_absorb_non_first, .-keccak_f1600_x1_scalar_asm_lazy_absorb_non_first

.type	keccak_f1600_x1_scalar_asm_lazy_squeeze, %function
.align	4
keccak_f1600_x1_scalar_asm_lazy_squeeze:
	AARCH64_SIGN_LINK_REGISTER
	stp	x30, x29, [sp, #4*8]

	keccak_f1600_round_initial

loop3:
	keccak_f1600_round_noninitial
	cmp	w27, #(KECCAK_F1600_ROUNDS-1)
	ble	loop3

	final_rotate

	ldp	x30, x29, [sp, #4*8]
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	keccak_f1600_x1_scalar_asm_lazy_squeeze, .-keccak_f1600_x1_scalar_asm_lazy_squeeze

.type	KeccakF1600, %function
.align	5
KeccakF1600:
	AARCH64_SIGN_LINK_REGISTER
	alloc_stack_save_GPRs_KeccakF1600

	sub	sp, sp, #6*8
	bl	keccak_f1600_x1_scalar_asm_lazy_squeeze
	add	sp, sp, #6*8

	free_stack_restore_GPRs_KeccakF1600
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	KeccakF1600, .-KeccakF1600


.globl	SHA3_Absorb_lazy_absorb
.hidden	SHA3_Absorb_lazy_absorb
.type	SHA3_Absorb_lazy_absorb, %function
.align	5
SHA3_Absorb_lazy_absorb:
	AARCH64_SIGN_LINK_REGISTER
	alloc_stack_save_GPRs_absorb
	offload_and_move_args
	load_bitstate
	b	.Loop_absorb_first
.align	4
.Loop_absorb_first:
	subs	x29, x0, x28		// rem = len - bsz
	blo	.Labsorbed
	str	x29, [sp, #STACK_OFFSET_LENGTH]			// save rem
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x1, x29, x1
	cmp	x28, #8*(0+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x6, x29, x6
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x11, x29, x11
	cmp	x28, #8*(2+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x16, x29, x16
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x21, x29, x21
	cmp	x28, #8*(4+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x2, x29, x2
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x7, x29, x7
	cmp	x28, #8*(6+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x12, x29, x12
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x17, x29, x17
	cmp	x28, #8*(8+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x22, x29, x22
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x3, x29, x3
	cmp	x28, #8*(10+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x8, x29, x8
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x13, x29, x13
	cmp	x28, #8*(12+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x25, x29, x25
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x23, x29, x23
	cmp	x28, #8*(14+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x4, x29, x4
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x9, x29, x9
	cmp	x28, #8*(16+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x14, x29, x14
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x19, x29, x19
	cmp	x28, #8*(18+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x24, x29, x24
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x5, x29, x5
	cmp	x28, #8*(20+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x10, x29, x10
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x15, x29, x15
	cmp	x28, #8*(22+2)
	blo	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x20, x29, x20
	beq	.Lprocess_block_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x1, x29, x1
.Lprocess_block_first:

	str	x26, [sp, #STACK_OFFSET_INPUT_ADR]			// save input address

	sub	sp, sp, #6*8
    // It will execute all keccak rounds without final rotate
	bl	keccak_f1600_x1_scalar_asm_lazy_absorb_first
	add	sp, sp, #6*8
	ldr	x26, [sp, #STACK_OFFSET_INPUT_ADR]			// restore arguments
	ldp	x0, x28, [sp, #STACK_OFFSET_LENGTH]
	b	.Loop_absorb_non_first

//END First Keccak
.align	4
.Loop_absorb_non_first:
	subs	x29, x0, x28		// rem = len - bsz
	blo	.Labsorbed
	str	x29, [sp, #STACK_OFFSET_LENGTH]			// save rem
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x1, x29, x1, ROR #0
	cmp	x28, #8*(0+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x6, x29, x6, ROR #64-21
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x11, x29, x11, ROR #64-14
	cmp	x28, #8*(2+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x16, x29, x16, ROR #0
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x21, x29, x21, ROR #64-44
	cmp	x28, #8*(4+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x2, x29, x2, ROR #64-3
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x7, x29, x7, ROR #64-45
	cmp	x28, #8*(6+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x12, x29, x12, ROR #64-61
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x17, x29, x17, ROR #64-28
	cmp	x28, #8*(8+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x22, x29, x22, ROR #64-20
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x3, x29, x3, ROR #64-25
	cmp	x28, #8*(10+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x8, x29, x8, ROR #64-8
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x13, x29, x13, ROR #64-18
	cmp	x28, #8*(12+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x25, x29, x25, ROR #64-1
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x23, x29, x23, ROR #64-6
	cmp	x28, #8*(14+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x4, x29, x4, ROR #64-10
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x9, x29, x9, ROR #64-15
	cmp	x28, #8*(16+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x14, x29, x14, ROR #64-56
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x19, x29, x19, ROR #64-27
	cmp	x28, #8*(18+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x24, x29, x24, ROR #64-36
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x5, x29, x5, ROR #64-39
	cmp	x28, #8*(20+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x10, x29, x10, ROR #64-41
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x15, x29, x15, ROR #64-2
	cmp	x28, #8*(22+2)
	blo	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x20, x29, x20, ROR #64-62
	beq	.Lprocess_block_non_first
	ldr	x29, [x26], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	x29, x29
#endif
	eor	x1, x29, x1, ROR #0
.Lprocess_block_non_first:

	str	x26, [sp, #STACK_OFFSET_INPUT_ADR]			// save input address
	sub	sp, sp, #6*8

//Check how many bit-state lanes are not adjusted on the absorb
	cmp	x28, #168
	bne	.not_shake128
	final_rotate_shake128
.not_shake128:
	cmp	x28, #144
	bne	.not_sha3_224
	final_rotate_sha3_224
.not_sha3_224:
	cmp	x28, #136
	bne	.not_sha3_256_shake256
	final_rotate_sha3_256_shake256
.not_sha3_256_shake256:
	cmp	x28, #104
	bne	.not_sha3_384
	final_rotate_sha3_384
.not_sha3_384:
	cmp	x28, #72
	bne	.not_sha3_512
	final_rotate_sha3_512
.not_sha3_512:

	bl	keccak_f1600_x1_scalar_asm_lazy_absorb_non_first
	add	sp, sp, #6*8

	ldr	x26, [sp, #STACK_OFFSET_INPUT_ADR]			// restore arguments
	ldp	x0, x28, [sp, #STACK_OFFSET_LENGTH]
	b	.Loop_absorb_non_first
.align	4
.Labsorbed:
	sub	sp, sp, #6*8
	final_rotate
	add	sp, sp, #6*8
	ldr	x29, [sp, #STACK_OFFSET_BITSTATE_ADR]
	store_bitstate
	free_stack_restore_GPRs_absorb
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	SHA3_Absorb_lazy_absorb, .-SHA3_Absorb_lazy_absorb
.globl	SHA3_Squeeze_lazy_absorb
.hidden	SHA3_Squeeze_lazy_absorb
.type	SHA3_Squeeze_lazy_absorb, %function
.align	5
SHA3_Squeeze_lazy_absorb:
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
.size	SHA3_Squeeze_lazy_absorb, .-SHA3_Squeeze_lazy_absorb
.byte	75,101,99,99,97,107,45,49,54,48,48,32,97,98,115,111,114,98,32,97,110,100,32,115,113,117,101,101,122,101,32,102,111,114,32,65,82,77,118,56,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	2
#endif  // !OPENSSL_NO_ASM && defined(__AARCH64EL__) && defined(__ELF__)
#if defined(__ELF__)
// See https://www.airs.com/blog/archives/518.
.section .note.GNU-stack,"",%progbits
#endif
