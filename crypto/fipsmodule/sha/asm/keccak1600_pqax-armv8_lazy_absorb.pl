#!/usr/bin/env perl
# Copyright (c) 2021-2022 Arm Limited
# Copyright (c) 2022 Matthias Kannwischer
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Author: Hanno Becker <hanno.becker@arm.com>
# Author: Matthias Kannwischer <matthias@kannwischer.eu>
#
# File keccak1600_pqax-armv8.pl is implemented based on previous AWS-LC Keccakf1600 design 
# adapting keccak_f1600_x1_scalar_asm_v5.s implementation into the library logic.
# keccak_f1600_x1_scalar_asm_v5.s could be found at:
# https://gitlab.com/arm-research/security/pqax

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
if ($#ARGV < 1) { die "Not enough arguments provided.
  Two arguments are necessary: the flavour and the output file path."; }

$flavour = shift;
$output = shift;

if ($flavour && $flavour ne "void") {
    $0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
    ( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
    ( $xlate="${dir}../../../perlasm/arm-xlate.pl" and -f $xlate) or
    die "can't locate arm-xlate.pl";

    open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\"";
    *STDOUT=*OUT;
} else {
    open OUT, ">$output";
    *STDOUT=*OUT;
}

$code.=<<___;
#include <openssl/arm_arch.h>
.text
.balign 64

.type	round_constants, %object
round_constants:
    .quad 0x0000000000000001
    .quad 0x0000000000008082
    .quad 0x800000000000808a
    .quad 0x8000000080008000
    .quad 0x000000000000808b
    .quad 0x0000000080000001
    .quad 0x8000000080008081
    .quad 0x8000000000008009
    .quad 0x000000000000008a
    .quad 0x0000000000000088
    .quad 0x0000000080008009
    .quad 0x000000008000000a
    .quad 0x000000008000808b
    .quad 0x800000000000008b
    .quad 0x8000000000008089
    .quad 0x8000000000008003
    .quad 0x8000000000008002
    .quad 0x8000000000000080
    .quad 0x000000000000800a
    .quad 0x800000008000000a
    .quad 0x8000000080008081
    .quad 0x8000000000008080
    .quad 0x0000000080000001
    .quad 0x8000000080008008
.size	round_constants, .-round_constants

___
								{{{
 # Alias symbol A (the bit-state matrix) with registers
$A[0][4] = "x21"; $A[1][4] =  "x22"; $A[2][4] = "x23"; $A[3][4] = "x24"; $A[4][4] = "x27";
$A[0][3] = "x16"; $A[1][3] =  "x17"; $A[2][3] = "x25"; $A[3][3] = "x19"; $A[4][3] = "x20";
$A[0][2] = "x11"; $A[1][2] =  "x12"; $A[2][2] = "x13"; $A[3][2] = "x14"; $A[4][2] = "x15";
$A[0][1] = "x6"; $A[1][1] =   "x7"; $A[2][1] =  "x8"; $A[3][1] =  "x9"; $A[4][1] =  "x10";
$A[0][0] = "x1"; $A[1][0] =   "x2"; $A[2][0] =  "x3"; $A[3][0] =  "x4"; $A[4][0] =  "x5";
 
 # Alias symbol A_ (the permuted bit-state matrix) with registers
 # A_[y, 2*x+3*y] = rot(A[x, y])
$A_[0][4] = "x21"; $A_[1][4] = "x22"; $A_[2][4] = "x23"; $A_[3][4] = "x24"; $A_[4][4] = "x27";
$A_[0][3] = "x16"; $A_[1][3] =  "x17"; $A_[2][3] = "x25"; $A_[3][3] = "x19"; $A_[4][3] = "x20";
$A_[0][2] = "x11"; $A_[1][2] =  "x12"; $A_[2][2] = "x13"; $A_[3][2] = "x14"; $A_[4][2] = "x15";
$A_[0][1] = "x28"; $A_[1][1] =  "x8"; $A_[2][1] = "x9"; $A_[3][1] = "x10"; $A_[4][1] = "x6";
$A_[0][0] = "x30"; $A_[1][0] =  "x3"; $A_[2][0] = "x4"; $A_[3][0] = "x5"; $A_[4][0] = "x1";

 # Alias symbol C and D with registers
 # C[x] = A[x, 0] xor A[x, 1] xor A[x, 2] xor A[x, 3] xor A[x, 4],   for x in 0..4
 # E[x] = C[x-1] xor rot(C[x+1], 1), for x in 0..4
my @C = map("x$_", (30, 26, 27, 28, 29));
my @E = map("x$_", (29, 0, 26, 27, 28));

$tmp0          =   "x0";
$tmp1          =  "x29";

$len           =   "x0";
$bsz           =  "x28";
$rem           =  "x29";

$inp           =  "x29";
$inp_adr       =  "x26";
$bitstate_adr  =  "x29";
$const_addr    =  "x26";
$cur_const     =  "x26";
$w27         =  "w27";

 # Alias final_rotates values
$final_rotates[0][0] =     "0"; $final_rotates[0][1] = "64-21"; $final_rotates[0][2] = "64-14"; $final_rotates[0][3] =     "0"; $final_rotates[0][4] = "64-44"; 
$final_rotates[1][0] =  "64-3"; $final_rotates[1][1] = "64-45"; $final_rotates[1][2] = "64-61"; $final_rotates[1][3] = "64-28"; $final_rotates[1][4] = "64-20"; 
$final_rotates[2][0] = "64-25"; $final_rotates[2][1] =  "64-8"; $final_rotates[2][2] = "64-18"; $final_rotates[2][3] =  "64-1"; $final_rotates[2][4] =  "64-6"; 
$final_rotates[3][0] = "64-10"; $final_rotates[3][1] = "64-15"; $final_rotates[3][2] = "64-56"; $final_rotates[3][3] = "64-27"; $final_rotates[3][4] = "64-36"; 
$final_rotates[4][0] = "64-39"; $final_rotates[4][1] = "64-41"; $final_rotates[4][2] =  "64-2"; $final_rotates[4][3] = "64-62"; $final_rotates[4][4] = "64-55"; 

$code.=<<___;
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
.macro alloc_stack_save_GPRs_absorb
	stp	x29, x30, [sp, #-128]!
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	x25, x26, [sp, #64]
	stp	x27, x28, [sp, #80]
	sub	sp, sp, #64
.endm

.macro free_stack_restore_GPRs_absorb
	ldp	x19, x20, [sp, #16+64]
	add	sp, sp, #64
	ldp	x21, x22, [sp, #32]
	ldp	x23, x24, [sp, #48]
	ldp	x25, x26, [sp, #64]
	ldp	x27, x28, [sp, #80]
	ldp	x29, x30, [sp], #128
.endm

.macro offload_and_move_args
	stp	x0, x1, [sp, #STACK_OFFSET_BITSTATE_ADR]			// offload arguments
	stp	x2, x3, [sp, #STACK_OFFSET_LENGTH]
	mov	$bitstate_adr, x0			// uint64_t A[5][5]
	mov	$inp_adr, x1			// const void *inp
	mov	$len, x2			// size_t len
	mov	$bsz, x3			// size_t bsz
.endm

.macro load_bitstate
	ldp	$A[0][0], $A[0][1], [$bitstate_adr, #16*0]
	ldp	$A[0][2], $A[0][3], [$bitstate_adr, #16*1]
	ldp	$A[0][4], $A[1][0], [$bitstate_adr, #16*2]
	ldp	$A[1][1], $A[1][2], [$bitstate_adr, #16*3]
	ldp	$A[1][3], $A[1][4], [$bitstate_adr, #16*4]
	ldp	$A[2][0], $A[2][1], [$bitstate_adr, #16*5]
	ldp	$A[2][2], $A[2][3], [$bitstate_adr, #16*6]
	ldp	$A[2][4], $A[3][0], [$bitstate_adr, #16*7]
	ldp	$A[3][1], $A[3][2], [$bitstate_adr, #16*8]
	ldp	$A[3][3], $A[3][4], [$bitstate_adr, #16*9]
	ldp	$A[4][0], $A[4][1], [$bitstate_adr, #16*10]
	ldp	$A[4][2], $A[4][3], [$bitstate_adr, #16*11]
	ldr	$A[4][4], [$bitstate_adr, #16*12]
.endm

.macro load_constant_ptr
	adr $const_addr, round_constants
.endm

.macro store_bitstate
	stp	$A[0][0], $A[0][1], [$bitstate_adr, #16*0]
	stp	$A[0][2], $A[0][3], [$bitstate_adr, #16*1]
	stp	$A[0][4], $A[1][0], [$bitstate_adr, #16*2]
	stp	$A[1][1], $A[1][2], [$bitstate_adr, #16*3]
	stp	$A[1][3], $A[1][4], [$bitstate_adr, #16*4]
	stp	$A[2][0], $A[2][1], [$bitstate_adr, #16*5]
	stp	$A[2][2], $A[2][3], [$bitstate_adr, #16*6]
	stp	$A[2][4], $A[3][0], [$bitstate_adr, #16*7]
	stp	$A[3][1], $A[3][2], [$bitstate_adr, #16*8]
	stp	$A[3][3], $A[3][4], [$bitstate_adr, #16*9]
	stp	$A[4][0], $A[4][1], [$bitstate_adr, #16*10]
	stp	$A[4][2], $A[4][3], [$bitstate_adr, #16*11]
	str	$A[4][4], [$bitstate_adr, #16*12]
.endm

.macro alloc_stack_save_GPRs_KeccakF1600
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
	ldp	$A[0][0], $A[0][1], [x0, #16*0]
	ldp	$A[0][2], $A[0][3], [x0, #16*1]
	ldp	$A[0][4], $A[1][0], [x0, #16*2]
	ldp	$A[1][1], $A[1][2], [x0, #16*3]
	ldp	$A[1][3], $A[1][4], [x0, #16*4]
	ldp	$A[2][0], $A[2][1], [x0, #16*5]
	ldp	$A[2][2], $A[2][3], [x0, #16*6]
	ldp	$A[2][4], $A[3][0], [x0, #16*7]
	ldp	$A[3][1], $A[3][2], [x0, #16*8]
	ldp	$A[3][3], $A[3][4], [x0, #16*9]
	ldp	$A[4][0], $A[4][1], [x0, #16*10]
	ldp	$A[4][2], $A[4][3], [x0, #16*11]
	ldr	$A[4][4], [x0, #16*12]
.endm

.macro free_stack_restore_GPRs_KeccakF1600
ldr	x0, [sp, #32]
	stp	$A[0][0], $A[0][1], [x0, #16*0]
	stp	$A[0][2], $A[0][3], [x0, #16*1]
	stp	$A[0][4], $A[1][0], [x0, #16*2]
	stp	$A[1][1], $A[1][2], [x0, #16*3]
	stp	$A[1][3], $A[1][4], [x0, #16*4]
	stp	$A[2][0], $A[2][1], [x0, #16*5]
	stp	$A[2][2], $A[2][3], [x0, #16*6]
	stp	$A[2][4], $A[3][0], [x0, #16*7]
	stp	$A[3][1], $A[3][2], [x0, #16*8]
	stp	$A[3][3], $A[3][4], [x0, #16*9]
	stp	$A[4][0], $A[4][1], [x0, #16*10]
	stp	$A[4][2], $A[4][3], [x0, #16*11]
	str	$A[4][4], [x0, #16*12]
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


.macro keccak_f1600_round_initial
    eor $C[4], $A[3][4], $A[4][4]

str x27, [sp, #STACK_OFFSET_x27_A44]  // store x27 from bit state

    eor $C[0], $A[3][0], $A[4][0]
    eor $C[1], $A[3][1], $A[4][1]
    eor $C[2], $A[3][2], $A[4][2]
    eor $C[3], $A[3][3], $A[4][3]
    eor $C[0], $A[2][0], $C[0]
    eor $C[1], $A[2][1], $C[1]
    eor $C[2], $A[2][2], $C[2]
    eor $C[3], $A[2][3], $C[3]
    eor $C[4], $A[2][4], $C[4]
    eor $C[0], $A[1][0], $C[0]
    eor $C[1], $A[1][1], $C[1]
    eor $C[2], $A[1][2], $C[2]
    eor $C[3], $A[1][3], $C[3]
    eor $C[4], $A[1][4], $C[4]
    eor $C[0], $A[0][0], $C[0]
    eor $C[1], $A[0][1], $C[1]
    eor $C[2], $A[0][2], $C[2]
    eor $C[3], $A[0][3], $C[3]
    eor $C[4], $A[0][4], $C[4]

 	eor $E[1], $C[0], $C[2], ROR #63
    eor $E[3], $C[2], $C[4], ROR #63
    eor $E[0], $C[4], $C[1], ROR #63
    eor $E[2], $C[1], $C[3], ROR #63
    eor $E[4], $C[3], $C[0], ROR #63

    eor $A_[0][0], $A[0][0], $E[0] //leftover 0
    eor $A_[4][0], $A[0][2], $E[2] //leftover 62
    eor $A_[0][2], $A[2][2], $E[2] //leftover 43
    eor $A_[2][2], $A[2][3], $E[3]
    eor $A_[2][3], $A[3][4], $E[4] //leftover 8
    eor $A_[3][4], $A[4][3], $E[3]
    eor $A_[4][3], $A[3][0], $E[0] //leftover 41
    eor $A_[2][0], $A[0][1], $E[1] //leftover 1
    eor $A_[4][1], $A[1][3], $E[3]
    eor $A_[1][3], $A[3][1], $E[1] //leftover 45
    eor $A_[2][1], $A[1][2], $E[2] //leftover 6
    eor $A_[1][2], $A[2][0], $E[0] //leftover 3
    eor $A_[1][0], $A[0][3], $E[3]
    eor $A_[0][3], $A[3][3], $E[3]
    eor $A_[3][3], $A[3][2], $E[2] //leftover 15
    eor $A_[3][2], $A[2][1], $E[1] //leftover 10
    eor $A_[1][1], $A[1][4], $E[4] //leftover 20
    eor $A_[1][4], $A[4][2], $E[2] //leftover 61
    eor $A_[4][2], $A[2][4], $E[4] //leftover 39
    eor $A_[2][4], $A[4][0], $E[0] //leftover 18
    eor $A_[3][0], $A[0][4], $E[4] //leftover 27

ldr x27, [sp, STACK_OFFSET_x27_A44]

    eor $A_[0][4], $A[4][4], $E[4]
    eor $A_[4][4], $A[4][1], $E[1]
    eor $A_[3][1], $A[1][0], $E[0] //leftover 36
    eor $A_[0][1], $A[1][1], $E[1] //leftover 44

	// Load address contants into x26
	load_constant_ptr

	bic $tmp0, $A_[1][2], $A_[1][1], ROR #47  // A<<3, B<<20, C<<64-(20-3), leftover    3
    bic $tmp1, $A_[1][3], $A_[1][2], ROR #42  // A<<45, B<<3, C<<64-(-), leftover       45
    eor $A[1][0], $tmp0, $A_[1][0], ROR #39   // A<<3, B<<28, C<<64-(28-3), leftover    3
    bic $tmp0, $A_[1][4], $A_[1][3], ROR #16  // A<<61, B<<45, C<<64-(-), leftover      61
    eor $A[1][1], $tmp1, $A_[1][1], ROR #25  // A<<45, B<<20, C<<64-(-), leftover       45
    bic $tmp1, $A_[1][0], $A_[1][4], ROR #31  // A<<28, B<<61, C<<64-(-), leftover      28
    eor $A[1][2], $tmp0, $A_[1][2], ROR #58  // A<<61, B<<3, C<<64-(-), leftover        61
    bic $tmp0, $A_[1][1], $A_[1][0], ROR #56  // A<<20, B<<28, C<<64-(-), leftover      20
    eor $A[1][3], $tmp1, $A_[1][3], ROR #47  // A<<28, B<<45, C<<64-(-), leftover         28
    bic $tmp1, $A_[2][2], $A_[2][1], ROR #19  // A<<25, B<<6, C<<64-(6-25), leftover    25
    eor $A[1][4], $tmp0, $A_[1][4], ROR #23  // A<<20, B<<61, C<<64-(-), leftover         20
    bic $tmp0, $A_[2][3], $A_[2][2], ROR #47  // A<<8, B<<25, C<<64-(-), leftover       8
    eor $A[2][0], $tmp1, $A_[2][0], ROR #24  // A<<25, B<<1, C<<64-(-), leftover        25
    bic $tmp1, $A_[2][4], $A_[2][3], ROR #10  // A<<18, B<<8, C<<64-(8-18), leftover    18
    eor $A[2][1], $tmp0, $A_[2][1], ROR #2  // A<<8, B<<6, C<<64-(-), leftover          8
    bic $tmp0, $A_[2][0], $A_[2][4], ROR #47  // A<<1, B<<18, C<<64-(-), leftover       1
    eor $A[2][2], $tmp1, $A_[2][2], ROR #57  // A<<18, B<<25, C<<64-(25-54), leftover      18
    bic $tmp1, $A_[2][1], $A_[2][0], ROR #5  // A<<6, B<<1, C<<64-(-), leftover         6
    eor $A[2][3], $tmp0, $A_[2][3], ROR #57  // A<<1, B<<8, C<<64-(-), leftover         1
    bic $tmp0, $A_[3][2], $A_[3][1], ROR #38  // A<<10, B<<36, C<<64-(-), leftover      10
    eor $A[2][4], $tmp1, $A_[2][4], ROR #52  // A<<6, B<<18, C<<64-(-), leftover        6
    bic $tmp1, $A_[3][3], $A_[3][2], ROR #5  // A<<15, B<<10, C<<64-(-), leftover       15
    eor $A[3][0], $tmp0, $A_[3][0], ROR #47  // A<<10, B<<27, C<<64-(-), leftover       10
    bic $tmp0, $A_[3][4], $A_[3][3], ROR #41  // A<<56, B<<15, C<<64-(-), leftover      56
    eor $A[3][1], $tmp1, $A_[3][1], ROR #43  // A<<15, B<<36, C<<64-(-), leftover       15
    bic $tmp1, $A_[3][0], $A_[3][4], ROR #35  // A<<27, B<<56, C<<64-(-), leftover      27
    eor $A[3][2], $tmp0, $A_[3][2], ROR #46  // A<<56, B<<10, C<<64-(-), leftover       56
    bic $tmp0, $A_[3][1], $A_[3][0], ROR #9  // A<<36, B<<27, C<<64-(-), leftover       36

	str $const_addr, [sp, #(STACK_OFFSET_CONST)]
    ldr $cur_const, [$const_addr]

	eor $A[3][3], $tmp1, $A_[3][3], ROR #12  // A<<27, B<<15, C<<64-(-), leftover       27
    bic $tmp1, $A_[4][2], $A_[4][1], ROR #48  // A<<39, B<<55, C<<64-(-), leftover      39
    eor $A[3][4], $tmp0, $A_[3][4], ROR #44  // A<<36, B<<56, C<<64-(-), leftover       36
    bic $tmp0, $A_[4][3], $A_[4][2], ROR #2  // A<<41, B<<39, C<<64-(-), leftover       41
    eor $A[4][0], $tmp1, $A_[4][0], ROR #41  // A<<39, B<<62, C<<64-(-), leftover       39
    bic $tmp1, $A_[4][4], $A_[4][3], ROR #25  // A<<2, B<<41, C<<64-(-), leftover       2
    eor $A[4][1], $tmp0, $A_[4][1], ROR #50  // A<<41, B<<55, C<<64-(-), leftover       41
    bic $tmp0, $A_[4][0], $A_[4][4], ROR #60  // A<<62, B<<2, C<<64-(-), leftover       62
    eor $A[4][2], $tmp1, $A_[4][2], ROR #27  // A<<2, B<<39, C<<64-(39-2), leftover     2
    bic $tmp1, $A_[4][1], $A_[4][0], ROR #57  // A<<55, B<<62, C<<64-(-), leftover      55
    eor $A[4][3], $tmp0, $A_[4][3], ROR #21  // A<<62, B<<41, C<<64-(-), leftover       62
    bic $tmp0, $A_[0][2], $A_[0][1], ROR #63  // A<<43, B<<44, C<<64-(44-43), leftover  43
    eor $A[4][4], $tmp1, $A_[4][4], ROR #53

str x27, [sp, STACK_OFFSET_x27_A44]

    bic $tmp1, $A_[0][3], $A_[0][2], ROR #42 // A<<21, B<<43, C<<64-(-), leftover       21
    eor $A[0][0], $A_[0][0], $tmp0, ROR #21 // A<<0, B<<43, C<<64-(-), leftover         0
    bic $tmp0, $A_[0][4], $A_[0][3], ROR #57 // A<<14, B<<21, C<<64-(-), leftover       14
    eor $A[0][1], $tmp1, $A_[0][1], ROR #41 // A<<21, B<<44, C<<64-(-), leftover        21
    bic $tmp1, $A_[0][0], $A_[0][4], ROR #50 // A<<0, B<<14, C<<64-(-), leftover        0
    eor $A[0][2], $tmp0, $A_[0][2], ROR #35 // A<<14, B<<43, C<<64-(-), leftover        14
    bic $tmp0, $A_[0][1], $A_[0][0], ROR #44 // A<<44, B<<0, C<<64-(-), leftover        44
    eor $A[0][3], $tmp1, $A_[0][3], ROR #43 // A<<0, B<<21, C<<64-(-), leftover         0
    eor $A[0][4], $tmp0, $A_[0][4], ROR #30 // A<<44, B<<14, C<<64-(-), leftover        44

    mov w27, #1

    eor $A[0][0], $A[0][0], $cur_const
	str w27, [sp, #STACK_OFFSET_COUNT]
.endm

.macro keccak_f1600_round_noninitial
    eor $C[2], $A[4][2], $A[0][2], ROR #52 // A<<2, B<<14, C<<64-(14-2), leftover       2      
    eor $C[0], $A[0][0], $A[1][0], ROR #61 // A<<0, B<<3, C<<64-(3-0), leftover         0
    eor $C[4], $A[2][4], $A[1][4], ROR #50 // A<<6, B<< 20, C<<64-(-), leftover         6   
    eor $C[1], $A[2][1], $A[3][1], ROR #57 // A<<8, B<<15, C<<64-(-), leftover          8
    eor $C[3], $A[0][3], $A[2][3], ROR #63 // A<<0, B<<1, C<<64-(-), leftover           0 
    eor $C[2], $C[2], $A[2][2], ROR #48 // A<<2, B<<18, C<<64-(18-2), leftover          2  
    eor $C[0], $C[0], $A[3][0], ROR #54 // A<<0, B<<10, C<<64-(-), leftover             0
    eor $C[4], $C[4], $A[3][4], ROR #34 // A<<6, B<<36, C<<64-(-), leftover             6
    eor $C[1], $C[1], $A[0][1], ROR #51 // A<<, B<<21, C<<64-(-), leftover              8
    eor $C[3], $C[3], $A[3][3], ROR #37 // A<<, B<<27, C<<64-(-), leftover              0
    eor $C[2], $C[2], $A[3][2], ROR #10 // A<<2 , B<<56, C<<64-(-), leftover            2 
    eor $C[0], $C[0], $A[2][0], ROR #39 // A<<0, B<<20, C<<64-(-), leftover             0
    eor $C[4], $C[4], $A[0][4], ROR #26 // A<<6, B<<44, C<<64-(-), leftover             6
    eor $C[1], $C[1], $A[4][1], ROR #31 // A<<, B<<41, C<<64-(-), leftover              8  
    eor $C[3], $C[3], $A[1][3], ROR #36 // A<<, B<<28, C<<64-(-), leftover              0
    eor $C[2], $C[2], $A[1][2], ROR #5 // A<<2 , B<<61, C<<64-(-), leftover             2 

str x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $C[0], $C[0], $A[4][0], ROR #25 // A<<, B<<, C<<64-(-), leftover     0     

ldr x27, [sp, STACK_OFFSET_x27_A44]

    eor $C[4], $C[4], $A[4][4], ROR #15 // A<<6, B<<, C<<64-(-), leftover      6     
    eor $C[1], $C[1], $A[1][1], ROR #27 // A<< 8, B<<, C<<64-(-), leftover     8     
    eor $C[3], $C[3], $A[4][3], ROR #2 // A<<, B<<, C<<64-(-), leftover          0

ldr x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $E[1], $C[0], $C[2], ROR #61
    ror $C[2], $C[2], 62
    eor $E[3], $C[2], $C[4], ROR #57 
    ror $C[4], $C[4], 58
    eor $E[0], $C[4], $C[1], ROR #55 // A<<0, B<<8, C<<64-(8-0)-1, leftover    0     
    ror $C[1], $C[1], 56
    eor $E[2], $C[1], $C[3], ROR #63 // A<<0, B<<0, C<<64-(-)-1, leftover     0     
    eor $E[4], $C[3], $C[0], ROR #63 // A<<0, B<<0, C<<64-(-)-1, leftover     0     


    eor $A_[0][0], $E[0], $A[0][0]
    eor $A_[4][0], $E[2], $A[0][2], ROR #50
    eor $A_[0][2], $E[2], $A[2][2], ROR #46
    eor $A_[2][2], $E[3], $A[2][3], ROR #63
    eor $A_[2][3], $E[4], $A[3][4], ROR #28
    eor $A_[3][4], $E[3], $A[4][3], ROR #2
    eor $A_[4][3], $E[0], $A[3][0], ROR #54
    eor $A_[2][0], $E[1], $A[0][1], ROR #43
    eor $A_[4][1], $E[3], $A[1][3], ROR #36
    eor $A_[1][3], $E[1], $A[3][1], ROR #49
    eor $A_[2][1], $E[2], $A[1][2], ROR #3
    eor $A_[1][2], $E[0], $A[2][0], ROR #39
    eor $A_[1][0], $E[3], $A[0][3]
    eor $A_[0][3], $E[3], $A[3][3], ROR #37
    eor $A_[3][3], $E[2], $A[3][2], ROR #8
    eor $A_[3][2], $E[1], $A[2][1], ROR #56
    eor $A_[1][1], $E[4], $A[1][4], ROR #44
    eor $A_[1][4], $E[2], $A[4][2], ROR #62
    eor $A_[4][2], $E[4], $A[2][4], ROR #58
    eor $A_[2][4], $E[0], $A[4][0], ROR #25
    eor $A_[3][0], $E[4], $A[0][4], ROR #20

ldr x27, [sp, #STACK_OFFSET_x27_A44]

    eor $A_[0][4], $E[4], $A[4][4], ROR #9
    eor $A_[4][4], $E[1], $A[4][1], ROR #23
    eor $A_[3][1], $E[0], $A[1][0], ROR #61
    eor $A_[0][1], $E[1], $A[1][1], ROR #19
	
    bic $tmp0, $A_[1][2], $A_[1][1], ROR #47
    bic $tmp1, $A_[1][3], $A_[1][2], ROR #42
    eor $A[1][0], $tmp0, $A_[1][0], ROR #39
    bic $tmp0, $A_[1][4], $A_[1][3], ROR #16
    eor $A[1][1], $tmp1, $A_[1][1], ROR #25
    bic $tmp1, $A_[1][0], $A_[1][4], ROR #31
    eor $A[1][2], $tmp0, $A_[1][2], ROR #58
    bic $tmp0, $A_[1][1], $A_[1][0], ROR #56
    eor $A[1][3], $tmp1, $A_[1][3], ROR #47
    bic $tmp1, $A_[2][2], $A_[2][1], ROR #19
    eor $A[1][4], $tmp0, $A_[1][4], ROR #23
    bic $tmp0, $A_[2][3], $A_[2][2], ROR #47
    eor $A[2][0], $tmp1, $A_[2][0], ROR #24
    bic $tmp1, $A_[2][4], $A_[2][3], ROR #10
    eor $A[2][1], $tmp0, $A_[2][1], ROR #2
    bic $tmp0, $A_[2][0], $A_[2][4], ROR #47
    eor $A[2][2], $tmp1, $A_[2][2], ROR #57
    bic $tmp1, $A_[2][1], $A_[2][0], ROR #5
    eor $A[2][3], $tmp0, $A_[2][3], ROR #57
    bic $tmp0, $A_[3][2], $A_[3][1], ROR #38
    eor $A[2][4], $tmp1, $A_[2][4], ROR #52
    bic $tmp1, $A_[3][3], $A_[3][2], ROR #5
    eor $A[3][0], $tmp0, $A_[3][0], ROR #47
    bic $tmp0, $A_[3][4], $A_[3][3], ROR #41
    eor $A[3][1], $tmp1, $A_[3][1], ROR #43
    bic $tmp1, $A_[3][0], $A_[3][4], ROR #35
    eor $A[3][2], $tmp0, $A_[3][2], ROR #46
    bic $tmp0, $A_[3][1], $A_[3][0], ROR #9
    eor $A[3][3], $tmp1, $A_[3][3], ROR #12
    bic $tmp1, $A_[4][2], $A_[4][1], ROR #48
    eor $A[3][4], $tmp0, $A_[3][4], ROR #44
    bic $tmp0, $A_[4][3], $A_[4][2], ROR #2
    eor $A[4][0], $tmp1, $A_[4][0], ROR #41
    bic $tmp1, $A_[4][4], $A_[4][3], ROR #25
    eor $A[4][1], $tmp0, $A_[4][1], ROR #50
    bic $tmp0, $A_[4][0], $A_[4][4], ROR #60
    eor $A[4][2], $tmp1, $A_[4][2], ROR #27
    bic $tmp1, $A_[4][1], $A_[4][0], ROR #57
    eor $A[4][3], $tmp0, $A_[4][3], ROR #21
    bic $tmp0, $A_[0][2], $A_[0][1], ROR #63
    eor $A[4][4], $tmp1, $A_[4][4], ROR #53

str x27, [sp, #STACK_OFFSET_x27_A44]

    ldr w27, [sp, #STACK_OFFSET_COUNT]

    load_constant_ptr_stack
    ldr $cur_const, [$const_addr, w27, UXTW #3]
    add w27, w27, #1
	str w27 , [sp , #STACK_OFFSET_COUNT]

    bic $tmp1, $A_[0][3], $A_[0][2], ROR #42
    eor $A[0][0], $A_[0][0], $tmp0, ROR #21
    bic $tmp0, $A_[0][4], $A_[0][3], ROR #57
    eor $A[0][1], $tmp1, $A_[0][1], ROR #41
    bic $tmp1, $A_[0][0], $A_[0][4], ROR #50
    eor $A[0][2], $tmp0, $A_[0][2], ROR #35
    bic $tmp0, $A_[0][1], $A_[0][0], ROR #44
    eor $A[0][3], $tmp1, $A_[0][3], ROR #43
    eor $A[0][4], $tmp0, $A_[0][4], ROR #30

    eor $A[0][0], $A[0][0], $cur_const

.endm

.macro final_rotate_sha3_224
ldr x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
    ror $A[3][3], $A[3][3], #(64-27)
    ror $A[3][4], $A[3][4], #(64-36)
    ror $A[4][0], $A[4][0], #(64-39)
    ror $A[4][1], $A[4][1], #(64-41)
    ror $A[4][2], $A[4][2], #(64-2)
    ror $A[4][3], $A[4][3], #(64-62)
    ror $A[4][4], $A[4][4], #(64-55)
.endm


.macro final_rotate_sha3_256_shake256
ldr x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
    ror $A[3][2], $A[3][2], #(64-56)
    ror $A[3][3], $A[3][3], #(64-27)
    ror $A[3][4], $A[3][4], #(64-36)
    ror $A[4][0], $A[4][0], #(64-39)
    ror $A[4][1], $A[4][1], #(64-41)
    ror $A[4][2], $A[4][2], #(64-2)
    ror $A[4][3], $A[4][3], #(64-62)
    ror $A[4][4], $A[4][4], #(64-55)
.endm

.macro final_rotate_sha3_384
ldr x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
    ror $A[2][3], $A[2][3], #(64-1)
    ror $A[2][4], $A[2][4], #(64-6)
    ror $A[3][0], $A[3][0], #(64-10)
    ror $A[3][1], $A[3][1], #(64-15)
    ror $A[3][2], $A[3][2], #(64-56)
    ror $A[3][3], $A[3][3], #(64-27)
    ror $A[3][4], $A[3][4], #(64-36)
    ror $A[4][0], $A[4][0], #(64-39)
    ror $A[4][1], $A[4][1], #(64-41)
    ror $A[4][2], $A[4][2], #(64-2)
    ror $A[4][3], $A[4][3], #(64-62)
    ror $A[4][4], $A[4][4], #(64-55)
.endm

.macro final_rotate_sha3_512
ldr x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
    ror $A[1][4], $A[1][4], #(64-20)
    ror $A[2][0], $A[2][0], #(64-25)
    ror $A[2][1], $A[2][1], #(64-8)
    ror $A[2][2], $A[2][2], #(64-18)
    ror $A[2][3], $A[2][3], #(64-1)
    ror $A[2][4], $A[2][4], #(64-6)
    ror $A[3][0], $A[3][0], #(64-10)
    ror $A[3][1], $A[3][1], #(64-15)
    ror $A[3][2], $A[3][2], #(64-56)
    ror $A[3][3], $A[3][3], #(64-27)
    ror $A[3][4], $A[3][4], #(64-36)
    ror $A[4][0], $A[4][0], #(64-39)
    ror $A[4][1], $A[4][1], #(64-41)
    ror $A[4][2], $A[4][2], #(64-2)
    ror $A[4][3], $A[4][3], #(64-62)
    ror $A[4][4], $A[4][4], #(64-55)
.endm

.macro  final_rotate_shake128
ldr x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
    ror $A[4][1], $A[4][1], #(64-41)
    ror $A[4][2], $A[4][2], #(64-2)
    ror $A[4][3], $A[4][3], #(64-62)
    ror $A[4][4], $A[4][4], #(64-55)
.endm

.macro final_rotate
ldr x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
    ror $A[1][0], $A[1][0], #(64-3) //61
    ror $A[0][4], $A[0][4], #(64-44)
    ror $A[2][0], $A[2][0], #(64-25)
    ror $A[2][1], $A[2][1], #(64-8)
    ror $A[3][0], $A[3][0], #(64-10)
    ror $A[2][4], $A[2][4], #(64-6)
    ror $A[4][0], $A[4][0], #(64-39)
    ror $A[4][1], $A[4][1], #(64-41)
    ror $A[0][1], $A[0][1], #(64-21)
    ror $A[1][1], $A[1][1], #(64-45)
    ror $A[1][2], $A[1][2], #(64-61)
    ror $A[3][1], $A[3][1], #(64-15)
    ror $A[3][2], $A[3][2], #(64-56)
    ror $A[0][2], $A[0][2], #(64-14)
    ror $A[2][2], $A[2][2], #(64-18)
    ror $A[2][3], $A[2][3], #(64-1)
    ror $A[4][2], $A[4][2], #(64-2)
    ror $A[4][3], $A[4][3], #(64-62)
    ror $A[1][3], $A[1][3], #(64-28)
    ror $A[1][4], $A[1][4], #(64-20)
    ror $A[3][3], $A[3][3], #(64-27)
    ror $A[3][4], $A[3][4], #(64-36)
    ror $A[4][4], $A[4][4], #(64-55)
.endm

#define KECCAK_F1600_ROUNDS 24

.macro load_constant_ptr_stack
    ldr $const_addr, [sp, #(STACK_OFFSET_CONST)]
.endm

.type	keccak_f1600_x1_scalar_asm_lazy_absorb_first, %function
.align	4
keccak_f1600_x1_scalar_asm_lazy_absorb_first:
	AARCH64_SIGN_LINK_REGISTER
	stp $C[0], $C[4], [sp, #4*8]

	keccak_f1600_round_initial
    
 loop1:
  	keccak_f1600_round_noninitial
    cmp w27, #(KECCAK_F1600_ROUNDS-1)
    ble loop1

	ldp $C[0], $C[4], [sp, #4*8]
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	keccak_f1600_x1_scalar_asm_lazy_absorb_first, .-keccak_f1600_x1_scalar_asm_lazy_absorb_first


.type	keccak_f1600_x1_scalar_asm_lazy_absorb_non_first, %function
.align	4
keccak_f1600_x1_scalar_asm_lazy_absorb_non_first:
	AARCH64_SIGN_LINK_REGISTER
	stp $C[0], $C[4], [sp, #4*8]
    keccak_f1600_round_initial
    
 loop2:
  	keccak_f1600_round_noninitial
    cmp w27, #(KECCAK_F1600_ROUNDS-1)
    ble loop2

	ldp $C[0], $C[4], [sp, #4*8]
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	keccak_f1600_x1_scalar_asm_lazy_absorb_non_first, .-keccak_f1600_x1_scalar_asm_lazy_absorb_non_first

.type	keccak_f1600_x1_scalar_asm_lazy_squeeze, %function
.align	4
keccak_f1600_x1_scalar_asm_lazy_squeeze:
	AARCH64_SIGN_LINK_REGISTER
	stp $C[0], $C[4], [sp, #4*8]

    keccak_f1600_round_initial
    
 loop3:
  	keccak_f1600_round_noninitial
    cmp w27, #(KECCAK_F1600_ROUNDS-1)
    ble loop3

    final_rotate

	ldp $C[0], $C[4], [sp, #4*8]
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	keccak_f1600_x1_scalar_asm_lazy_squeeze, .-keccak_f1600_x1_scalar_asm_lazy_squeeze

.type	KeccakF1600, %function
.align	5
KeccakF1600:
	AARCH64_SIGN_LINK_REGISTER
	alloc_stack_save_GPRs_KeccakF1600
	
    sub sp, sp, #6*8
	bl keccak_f1600_x1_scalar_asm_lazy_squeeze
	add sp, sp, #6*8

	free_stack_restore_GPRs_KeccakF1600
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	KeccakF1600, .-KeccakF1600


.globl	SHA3_Absorb_lazy_absorb
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
	subs	$rem, $len, $bsz		// rem = len - bsz
	blo	.Labsorbed
	str	$rem, [sp, #STACK_OFFSET_LENGTH]			// save rem
___
for (my $i=0; $i<24; $i+=2) {
my $j = $i+1;
$code.=<<___;
	ldr	$inp, [$inp_adr], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	$inp, $inp
#endif
	eor	$A[$i/5][$i%5], $inp, $A[$i/5][$i%5]
	cmp	$bsz, #8*($i+2)
	blo	.Lprocess_block_first
	ldr	$inp, [$inp_adr], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	$inp, $inp
#endif
	eor	$A[$j/5][$j%5], $inp, $A[$j/5][$j%5]
	beq	.Lprocess_block_first
___
}
$code.=<<___;
	ldr	$inp, [$inp_adr], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	$inp, $inp
#endif
	eor	$A[$j/5][$j%5], $inp, $A[$j/5][$j%5]
.Lprocess_block_first:

	str	$inp_adr, [sp, #STACK_OFFSET_INPUT_ADR]			// save input address

    sub sp, sp, #6*8
    // It will execute all keccak rounds without final rotate
    bl keccak_f1600_x1_scalar_asm_lazy_absorb_first
    add sp, sp, #6*8
	ldr	$inp_adr, [sp, #STACK_OFFSET_INPUT_ADR]			// restore arguments
	ldp	$len, $bsz, [sp, #STACK_OFFSET_LENGTH]
    b	.Loop_absorb_non_first

//END First Keccak
.align	4
.Loop_absorb_non_first:
subs	$rem, $len, $bsz		// rem = len - bsz
	blo	.Labsorbed
	str	$rem, [sp, #STACK_OFFSET_LENGTH]			// save rem
___
for (my $i=0; $i<24; $i+=2) {
my $j = $i+1;
$code.=<<___;
	ldr	$inp, [$inp_adr], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	$inp, $inp
#endif
	eor	$A[$i/5][$i%5], $inp, $A[$i/5][$i%5], ROR #$final_rotates[$i/5][$i%5]
	cmp	$bsz, #8*($i+2)
	blo	.Lprocess_block_non_first
	ldr	$inp, [$inp_adr], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	$inp, $inp
#endif
	eor	$A[$j/5][$j%5], $inp, $A[$j/5][$j%5], ROR #$final_rotates[$j/5][$j%5]
	beq	.Lprocess_block_non_first
___
}
$code.=<<___;
	ldr	$inp, [$inp_adr], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	$inp, $inp
#endif
    eor	$A[$j/5][$j%5], $inp, $A[$j/5][$j%5], ROR #$final_rotates[$j/5][$j%5]
.Lprocess_block_non_first:

	str	$inp_adr, [sp, #STACK_OFFSET_INPUT_ADR]			// save input address
    sub sp, sp, #6*8

//Check how many bit-state lanes are not adjusted on the absorb
cmp	$bsz, #168
    bne .not_shake128
    final_rotate_shake128
.not_shake128:
    cmp	$bsz, #144
    bne .not_sha3_224
    final_rotate_sha3_224
.not_sha3_224:
    cmp	$bsz, #136
    bne .not_sha3_256_shake256
    final_rotate_sha3_256_shake256
.not_sha3_256_shake256:
    cmp	$bsz, #104
    bne .not_sha3_384
    final_rotate_sha3_384
.not_sha3_384:
    cmp	$bsz, #72
    bne .not_sha3_512
    final_rotate_sha3_512
.not_sha3_512:

	bl keccak_f1600_x1_scalar_asm_lazy_absorb_non_first
    add sp, sp, #6*8

	ldr	$inp_adr, [sp, #STACK_OFFSET_INPUT_ADR]			// restore arguments
	ldp	$len, $bsz, [sp, #STACK_OFFSET_LENGTH]
	b	.Loop_absorb_non_first
.align	4
.Labsorbed:
    sub sp, sp, #6*8
    final_rotate
    add sp, sp, #6*8
	ldr	$bitstate_adr, [sp, #STACK_OFFSET_BITSTATE_ADR]
	store_bitstate
	free_stack_restore_GPRs_absorb
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	SHA3_Absorb_lazy_absorb, .-SHA3_Absorb_lazy_absorb
___
                                    }}}			
$code.=<<___;
.asciz	"Keccak-1600 absorb and squeeze for ARMv8, CRYPTOGAMS by <appro\@openssl.org>"
___

foreach(split("\n", $code)) {
	s/\`([^\`]*)\`/eval($1)/ge;
	m/\bld1r\b/ and s/\.16b/.2d/g;
	print $_, "\n";
}

close STDOUT or die "error closing STDOUT: $!";