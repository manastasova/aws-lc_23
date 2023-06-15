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

.type	round_constants_vec, %object
round_constants_vec:
    .quad 0x0000000000000001
    .quad 0x0000000000000001
    .quad 0x0000000000008082
    .quad 0x0000000000008082
    .quad 0x800000000000808a
    .quad 0x800000000000808a
    .quad 0x8000000080008000
    .quad 0x8000000080008000
    .quad 0x000000000000808b
    .quad 0x000000000000808b
    .quad 0x0000000080000001
    .quad 0x0000000080000001
    .quad 0x8000000080008081
    .quad 0x8000000080008081
    .quad 0x8000000000008009
    .quad 0x8000000000008009
    .quad 0x000000000000008a
    .quad 0x000000000000008a
    .quad 0x0000000000000088
    .quad 0x0000000000000088
    .quad 0x0000000080008009
    .quad 0x0000000080008009
    .quad 0x000000008000000a
    .quad 0x000000008000000a
    .quad 0x000000008000808b
    .quad 0x000000008000808b
    .quad 0x800000000000008b
    .quad 0x800000000000008b
    .quad 0x8000000000008089
    .quad 0x8000000000008089
    .quad 0x8000000000008003
    .quad 0x8000000000008003
    .quad 0x8000000000008002
    .quad 0x8000000000008002
    .quad 0x8000000000000080
    .quad 0x8000000000000080
    .quad 0x000000000000800a
    .quad 0x000000000000800a
    .quad 0x800000008000000a
    .quad 0x800000008000000a
    .quad 0x8000000080008081
    .quad 0x8000000080008081
    .quad 0x8000000000008080
    .quad 0x8000000000008080
    .quad 0x0000000080000001
    .quad 0x0000000080000001
    .quad 0x8000000080008008
    .quad 0x8000000080008008
.size	round_constants_vec, .-round_constants_vec
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
$count         =  "w27";

$code.=<<___;
// Mapping of Kecck-f1600 state to vector registers at the beginning and end of each round.
    vAba     .req v0
    vAbe     .req v1
    vAbi     .req v2
    vAbo     .req v3
    vAbu     .req v4
    vAga     .req v5
    vAge     .req v6
    vAgi     .req v7
    vAgo     .req v8
    vAgu     .req v9
    vAka     .req v10
    vAke     .req v11
    vAki     .req v12
    vAko     .req v13
    vAku     .req v14
    vAma     .req v15
    vAme     .req v16
    vAmi     .req v17
    vAmo     .req v18
    vAmu     .req v19
    vAsa     .req v20
    vAse     .req v21
    vAsi     .req v22
    vAso     .req v23
    vAsu     .req v24

    /* q-form of the above mapping */
    vAbaq    .req q0
    vAbeq    .req q1
    vAbiq    .req q2
    vAboq    .req q3
    vAbuq    .req q4
    vAgaq    .req q5
    vAgeq    .req q6
    vAgiq    .req q7
    vAgoq    .req q8
    vAguq    .req q9
    vAkaq    .req q10
    vAkeq    .req q11
    vAkiq    .req q12
    vAkoq    .req q13
    vAkuq    .req q14
    vAmaq    .req q15
    vAmeq    .req q16
    vAmiq    .req q17
    vAmoq    .req q18
    vAmuq    .req q19
    vAsaq    .req q20
    vAseq    .req q21
    vAsiq    .req q22
    vAsoq    .req q23
    vAsuq    .req q24

    /* C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0..4 */
    C0 .req v27
    C1 .req v28
    C2 .req v29
    C3 .req v30
    C4 .req v31

    C0q .req q27
    C1q .req q28
    C2q .req q29
    C3q .req q30
    C4q .req q31

    /* A_[y,2*x+3*y] = rot(A[x,y]) */
    vBba .req v25 // fresh
    vBbe .req v26 // fresh
    vBbi .req vAbi
    vBbo .req vAbo
    vBbu .req vAbu
    vBga .req vAka
    vBge .req vAke
    vBgi .req vAgi
    vBgo .req vAgo
    vBgu .req vAgu
    vBka .req vAma
    vBke .req vAme
    vBki .req vAki
    vBko .req vAko
    vBku .req vAku
    vBma .req vAsa
    vBme .req vAse
    vBmi .req vAmi
    vBmo .req vAmo
    vBmu .req vAmu
    vBsa .req vAba
    vBse .req vAbe
    vBsi .req vAsi
    vBso .req vAso
    vBsu .req vAsu

    vBbaq .req q25 // fresh
    vBbeq .req q26 // fresh
    vBbiq .req vAbiq
    vBboq .req vAboq
    vBbuq .req vAbuq
    vBgaq .req vAkaq
    vBgeq .req vAkeq
    vBgiq .req vAgiq
    vBgoq .req vAgoq
    vBguq .req vAguq
    vBkaq .req vAmaq
    vBkeq .req vAmeq
    vBkiq .req vAkiq
    vBkoq .req vAkoq
    vBkuq .req vAkuq
    vBmaq .req vAsaq
    vBmeq .req vAseq
    vBmiq .req vAmiq
    vBmoq .req vAmoq
    vBmuq .req vAmuq
    vBsaq .req vAbaq
    vBseq .req vAbeq
    vBsiq .req vAsiq
    vBsoq .req vAsoq
    vBsuq .req vAsuq

    /* E[x] = C[x-1] xor rot(C[x+1],1), for x in 0..4 */
    E0 .req C4
    E1 .req C0
    E2 .req vBbe // fresh
    E3 .req C2
    E4 .req C3

    E0q .req C4q
    E1q .req C0q
    E2q .req vBbeq // fresh
    E3q .req C2q
    E4q .req C3q


/************************ MACROS ****************************/

/* Macros using v8.4-A SHA-3 instructions */


.macro eor3_m1_0, d, s0, s1, s2
    eor \\d\\().16b , \\s0\\().16b , \\s1\\().16b
.endm

.macro eor2 d, s0, s1
    eor \\d\\().16b, \\s0\\().16b, \\s1\\().16b
.endm

.macro eor3_m1_1 d s0 s1 s2
    eor \\d\\().16b, \\d\\().16b,  \\s2\\().16b
.endm


.macro eor3_m1 d s0 s1 s2
    eor3_m1_0 \\d, \\s0, \\s1, \\s2
    eor3_m1_1 \\d, \\s0, \\s1, \\s2
.endm

.macro rax1_m1 d s0 s1
   // Use add instead of SHL #1
   add vvtmp.2d, \\s1\\().2d, \\s1\\().2d
   sri vvtmp.2d, \\s1\\().2d, #63
   eor \\d\\().16b, vvtmp.16b, \\s0\\().16b
.endm

 .macro xar_m1 d s0 s1 imm
   // Special cases where we can replace SHLs by ADDs
   .if \\imm == 63
     eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
     add \\d\\().2d, \\s0\\().2d, \\s0\\().2d
     sri \\d\\().2d, \\s0\\().2d, #(63)
   .elseif \\imm == 62
     eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
     add \\d\\().2d, \\s0\\().2d, \\s0\\().2d
     add \\d\\().2d, \\d\\().2d,  \\d\\().2d
     sri \\d\\().2d, \\s0\\().2d, #(62)
   .else
     eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
     shl \\d\\().2d, \\s0\\().2d, #(64-\\imm)
     sri \\d\\().2d, \\s0\\().2d, #(\\imm)
   .endif
.endm

 .macro xar_m1_0 d s0 s1 imm
   // Special cases where we can replace SHLs by ADDs
   .if \\imm == 63
     eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
   .elseif \\imm == 62
     eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
   .else
     eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
   .endif
.endm

 .macro xar_m1_1 d s0 s1 imm
   // Special cases where we can replace SHLs by ADDs
   .if \\imm == 63
     add \\d\\().2d, \\s0\\().2d, \\s0\\().2d
     sri \\d\\().2d, \\s0\\().2d, #(63)
   .elseif \\imm == 62
     add \\d\\().2d, \\s0\\().2d, \\s0\\().2d
     add \\d\\().2d, \\d\\().2d,  \\d\\().2d
     sri \\d\\().2d, \\s0\\().2d, #(62)
   .else
     shl \\d\\().2d, \\s0\\().2d, #(64-\\imm)
     sri \\d\\().2d, \\s0\\().2d, #(\\imm)
   .endif
.endm

.macro bcax_m1 d s0 s1 s2
    bic vvtmp.16b, \\s1\\().16b, \\s2\\().16b
    eor \\d\\().16b, vvtmp.16b, \\s0\\().16b
.endm

.macro load_input_vector
    ldr vAbaq, [input_addr, #(32*0)]
    ldr vAbeq, [input_addr, #(32*0+32)]
    ldr vAbiq, [input_addr, #(32*2)]
    ldr vAboq, [input_addr, #(32*2+32)]
    ldr vAbuq, [input_addr, #(32*4)]
    ldr vAgaq, [input_addr, #(32*4+32)]
    ldr vAgeq, [input_addr, #(32*6)]
    ldr vAgiq, [input_addr, #(32*6+32)]
    ldr vAgoq, [input_addr, #(32*8)]
    ldr vAguq, [input_addr, #(32*8+32)]
    ldr vAkaq, [input_addr, #(32*10)]
    ldr vAkeq, [input_addr, #(32*10+32)]
    ldr vAkiq, [input_addr, #(32*12)]
    ldr vAkoq, [input_addr, #(32*12+32)]
    ldr vAkuq, [input_addr, #(32*14)]
    ldr vAmaq, [input_addr, #(32*14+32)]
    ldr vAmeq, [input_addr, #(32*16)]
    ldr vAmiq, [input_addr, #(32*16+32)]
    ldr vAmoq, [input_addr, #(32*18)]
    ldr vAmuq, [input_addr, #(32*18+32)]
    ldr vAsaq, [input_addr, #(32*20)]
    ldr vAseq, [input_addr, #(32*20+32)]
    ldr vAsiq, [input_addr, #(32*22)]
    ldr vAsoq, [input_addr, #(32*22+32)]
    ldr vAsuq, [input_addr, #(32*24)]
.endm

.macro store_input_vector
    str vAbaq, [input_addr, #(32*0)]
    str vAbeq, [input_addr, #(32*0+32)]
    str vAbiq, [input_addr, #(32*2)]
    str vAboq, [input_addr, #(32*2+32)]
    str vAbuq, [input_addr, #(32*4)]
    str vAgaq, [input_addr, #(32*4+32)]
    str vAgeq, [input_addr, #(32*6)]
    str vAgiq, [input_addr, #(32*6+32)]
    str vAgoq, [input_addr, #(32*8)]
    str vAguq, [input_addr, #(32*8+32)]
    str vAkaq, [input_addr, #(32*10)]
    str vAkeq, [input_addr, #(32*10+32)]
    str vAkiq, [input_addr, #(32*12)]
    str vAkoq, [input_addr, #(32*12+32)]
    str vAkuq, [input_addr, #(32*14)]
    str vAmaq, [input_addr, #(32*14+32)]
    str vAmeq, [input_addr, #(32*16)]
    str vAmiq, [input_addr, #(32*16+32)]
    str vAmoq, [input_addr, #(32*18)]
    str vAmuq, [input_addr, #(32*18+32)]
    str vAsaq, [input_addr, #(32*20)]
    str vAseq, [input_addr, #(32*20+32)]
    str vAsiq, [input_addr, #(32*22)]
    str vAsoq, [input_addr, #(32*22+32)]
    str vAsuq, [input_addr, #(32*24)]
.endm

 # Define the stack arrangement for the |SHA3_Absorb_x4_neon_scalar| function
#define OFFSET_RESERVED_BYTES (4*8)
#define STACK_OFFSET_BITSTATE_ADR (OFFSET_RESERVED_BYTES + 0*8)
#define STACK_OFFSET_INPUT_ADR (OFFSET_RESERVED_BYTES + 1*8)
#define STACK_OFFSET_LENGTH (OFFSET_RESERVED_BYTES + 2*8)
#define STACK_OFFSET_BLOCK_SIZE (OFFSET_RESERVED_BYTES + 3*8)

 # Define the stack arrangement for the |keccak_f1600_x4_neon_scalar_asm| function
#define STACK_SIZE             (4*16 + 12*8 + 6*8 + 3*16 + 16) // 2 words for the stack storage of the A44, etc
#define STACK_BASE_VREGS       (0)
#define STACK_BASE_GPRS        (4*16)
#define STACK_BASE_TMP_GPRS    (4*16 + 12*8)
#define STACK_BASE_TMP_VREGS   (4*16 + 12*8 + 6*8)
#define STACK_OFFSET_INPUT     (0*8)
#define STACK_OFFSET_CONST     (1*8)
#define STACK_OFFSET_COUNT     (2*8)
#define STACK_OFFSET_COUNT_OUT (3*8)
#define STACK_OFFSET_CUR_INPUT (4*8)

#define STACK_OFFSET_x27_A44 (STACK_SIZE - 2*8)
#define STACK_OFFSET_x27_C2_E3 (STACK_SIZE - 1*8)

#define vAgi_offset 0
#define vAga_offset 1
#define vAge_offset 2

.macro save reg, offset
    str \\reg, [sp, #(STACK_BASE_TMP_GPRS + \\{offset})]
.endm

.macro restore reg, offset
    ldr \\reg, [sp, #(STACK_BASE_TMP_GPRS + \\{offset})]
.endm


.macro save_gprs
    stp x19, x20, [sp, #(STACK_BASE_GPRS + 16*0)]
    stp x21, x22, [sp, #(STACK_BASE_GPRS + 16*1)]
    stp x23, x24, [sp, #(STACK_BASE_GPRS + 16*2)]
    stp x25, x26, [sp, #(STACK_BASE_GPRS + 16*3)]
    stp x27, x28, [sp, #(STACK_BASE_GPRS + 16*4)]
    stp x29, x30, [sp, #(STACK_BASE_GPRS + 16*5)]
.endm

.macro restore_gprs
    ldp x19, x20, [sp, #(STACK_BASE_GPRS + 16*0)]
    ldp x21, x22, [sp, #(STACK_BASE_GPRS + 16*1)]
    ldp x23, x24, [sp, #(STACK_BASE_GPRS + 16*2)]
    ldp x25, x26, [sp, #(STACK_BASE_GPRS + 16*3)]
    ldp x27, x28, [sp, #(STACK_BASE_GPRS + 16*4)]
    ldp x29, x30, [sp, #(STACK_BASE_GPRS + 16*5)]
.endm

.macro save_vregs
    stp d8,  d9,  [sp,#(STACK_BASE_VREGS+0*16)]
    stp d10, d11, [sp,#(STACK_BASE_VREGS+1*16)]
    stp d12, d13, [sp,#(STACK_BASE_VREGS+2*16)]
    stp d14, d15, [sp,#(STACK_BASE_VREGS+3*16)]
.endm

.macro restore_vregs
    ldp d14, d15, [sp,#(STACK_BASE_VREGS+3*16)]
    ldp d12, d13, [sp,#(STACK_BASE_VREGS+2*16)]
    ldp d10, d11, [sp,#(STACK_BASE_VREGS+1*16)]
    ldp d8,  d9,  [sp,#(STACK_BASE_VREGS+0*16)]
.endm

.macro alloc_stack
    sub sp, sp, #(STACK_SIZE)
.endm

.macro free_stack
    add sp, sp, #(STACK_SIZE)
.endm

.macro eor5 dst, src0, src1, src2, src3, src4
    eor \\dst, \\src0, \\src1
    eor \\dst, \\dst,  \\src2
    eor \\dst, \\dst,  \\src3
    eor \\dst, \\dst,  \\src4
.endm

.macro xor_rol dst, src1, src0, imm
    eor \\dst, \\src0, \\src1, ROR  #(64-\\imm)
.endm

.macro bic_rol dst, src1, src0, imm
    bic \\dst, \\src0, \\src1, ROR  #(64-\\imm)
.endm

.macro rotate dst, src, imm
    ror \\dst, \\src, #(64-\\imm)
.endm

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

#define SEP ;

.macro hybrid_round_initial

    eor $C[4], $A[3][4], $A[4][4]
str x27, [sp, #STACK_OFFSET_x27_A44]  // store A[4][4] from bit state
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

    eor $A_[0][0], $A[0][0], $E[0]
    eor $A_[4][0], $A[0][2], $E[2]
    eor $A_[0][2], $A[2][2], $E[2]
    eor $A_[2][2], $A[2][3], $E[3]
    eor $A_[2][3], $A[3][4], $E[4]
    eor $A_[3][4], $A[4][3], $E[3]
    eor $A_[4][3], $A[3][0], $E[0]
    eor $A_[2][0], $A[0][1], $E[1]
    eor $A_[4][1], $A[1][3], $E[3]
    eor $A_[1][3], $A[3][1], $E[1]
    eor $A_[2][1], $A[1][2], $E[2]
    eor $A_[1][2], $A[2][0], $E[0]
    eor $A_[1][0], $A[0][3], $E[3]
    eor $A_[0][3], $A[3][3], $E[3]
    eor $A_[3][3], $A[3][2], $E[2]
    eor $A_[3][2], $A[2][1], $E[1]
    eor $A_[1][1], $A[1][4], $E[4]
    eor $A_[1][4], $A[4][2], $E[2]
    eor $A_[4][2], $A[2][4], $E[4]
    eor $A_[2][4], $A[4][0], $E[0]
    eor $A_[3][0], $A[0][4], $E[4]

ldr x27, [sp, STACK_OFFSET_x27_A44]

    eor $A_[0][4], $A[4][4], $E[4]
    eor $A_[4][4], $A[4][1], $E[1]
    eor $A_[3][1], $A[1][0], $E[0]
    eor $A_[0][1], $A[1][1], $E[1]

	// Load address contants into x26
	load_constant_ptr

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

	str $const_addr, [sp, #(STACK_OFFSET_CONST)]
    ldr $cur_const, [$const_addr]

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

str x27, [sp, STACK_OFFSET_x27_A44]

    bic $tmp1, $A_[0][3], $A_[0][2], ROR #42
    eor $A[0][0], $A_[0][0], $tmp0, ROR #21
    bic $tmp0, $A_[0][4], $A_[0][3], ROR #57
    eor $A[0][1], $tmp1, $A_[0][1], ROR #41
    bic $tmp1, $A_[0][0], $A_[0][4], ROR #50
    eor $A[0][2], $tmp0, $A_[0][2], ROR #35
    bic $tmp0, $A_[0][1], $A_[0][0], ROR #44
    eor $A[0][3], $tmp1, $A_[0][3], ROR #43
    eor $A[0][4], $tmp0, $A_[0][4], ROR #30

    mov $count, #1

    eor $A[0][0], $A[0][0], $cur_const
	str $count, [sp, #STACK_OFFSET_COUNT]

// Second iteration (noninitial)
    eor $C[2], $A[4][2], $A[0][2], ROR #52
    eor $C[0], $A[0][0], $A[1][0], ROR #61
    eor $C[4], $A[2][4], $A[1][4], ROR #50
    eor $C[1], $A[2][1], $A[3][1], ROR #57
    eor $C[3], $A[0][3], $A[2][3], ROR #63
    eor $C[2], $C[2], $A[2][2], ROR #48
    eor $C[0], $C[0], $A[3][0], ROR #54
    eor $C[4], $C[4], $A[3][4], ROR #34
    eor $C[1], $C[1], $A[0][1], ROR #51
    eor $C[3], $C[3], $A[3][3], ROR #37
    eor $C[2], $C[2], $A[3][2], ROR #10
    eor $C[0], $C[0], $A[2][0], ROR #39
    eor $C[4], $C[4], $A[0][4], ROR #26
    eor $C[1], $C[1], $A[4][1], ROR #31
    eor $C[3], $C[3], $A[1][3], ROR #36
    eor $C[2], $C[2], $A[1][2], ROR #5

str x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $C[0], $C[0], $A[4][0], ROR #25

ldr x27, [sp, STACK_OFFSET_x27_A44]

    eor $C[4], $C[4], $A[4][4], ROR #15
    eor $C[1], $C[1], $A[1][1], ROR #27
    eor $C[3], $C[3], $A[4][3], ROR #2

ldr x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $E[1], $C[0], $C[2], ROR #61
    ror $C[2], $C[2], 62
    eor $E[3], $C[2], $C[4], ROR #57
    ror $C[4], $C[4], 58
    eor $E[0], $C[4], $C[1], ROR #55
    ror $C[1], $C[1], 56
    eor $E[2], $C[1], $C[3], ROR #63
    eor $E[4], $C[3], $C[0], ROR #63

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

    ldr $count, [sp, #STACK_OFFSET_COUNT]

    load_constant_ptr_stack
    ldr $cur_const, [$const_addr, $count, UXTW #3]
    add $count, $count, #1
	str $count , [sp , #STACK_OFFSET_COUNT]

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

.macro keccak_f1600_round_noninitial
// First iteration
    eor $C[2], $A[4][2], $A[0][2], ROR #52
    eor $C[0], $A[0][0], $A[1][0], ROR #61
    eor $C[4], $A[2][4], $A[1][4], ROR #50
    eor $C[1], $A[2][1], $A[3][1], ROR #57
    eor $C[3], $A[0][3], $A[2][3], ROR #63
    eor $C[2], $C[2], $A[2][2], ROR #48
    eor $C[0], $C[0], $A[3][0], ROR #54
    eor $C[4], $C[4], $A[3][4], ROR #34
    eor $C[1], $C[1], $A[0][1], ROR #51
    eor $C[3], $C[3], $A[3][3], ROR #37
    eor $C[2], $C[2], $A[3][2], ROR #10
    eor $C[0], $C[0], $A[2][0], ROR #39
    eor $C[4], $C[4], $A[0][4], ROR #26
    eor $C[1], $C[1], $A[4][1], ROR #31
    eor $C[3], $C[3], $A[1][3], ROR #36
    eor $C[2], $C[2], $A[1][2], ROR #5

str x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $C[0], $C[0], $A[4][0], ROR #25

ldr x27, [sp, STACK_OFFSET_x27_A44]

    eor $C[4], $C[4], $A[4][4], ROR #15
    eor $C[1], $C[1], $A[1][1], ROR #27
    eor $C[3], $C[3], $A[4][3], ROR #2

ldr x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $E[1], $C[0], $C[2], ROR #61
    ror $C[2], $C[2], 62
    eor $E[3], $C[2], $C[4], ROR #57
    ror $C[4], $C[4], 58
    eor $E[0], $C[4], $C[1], ROR #55
    ror $C[1], $C[1], 56
    eor $E[2], $C[1], $C[3], ROR #63
    eor $E[4], $C[3], $C[0], ROR #63

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

    ldr $count, [sp, #STACK_OFFSET_COUNT]

    load_constant_ptr_stack
    ldr $cur_const, [$const_addr, $count, UXTW #3]
    add $count, $count, #1
	str $count , [sp , #STACK_OFFSET_COUNT]

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

// Second iteration
    eor $C[2], $A[4][2], $A[0][2], ROR #52
    eor $C[0], $A[0][0], $A[1][0], ROR #61
    eor $C[4], $A[2][4], $A[1][4], ROR #50
    eor $C[1], $A[2][1], $A[3][1], ROR #57
    eor $C[3], $A[0][3], $A[2][3], ROR #63
    eor $C[2], $C[2], $A[2][2], ROR #48
    eor $C[0], $C[0], $A[3][0], ROR #54
    eor $C[4], $C[4], $A[3][4], ROR #34
    eor $C[1], $C[1], $A[0][1], ROR #51
    eor $C[3], $C[3], $A[3][3], ROR #37
    eor $C[2], $C[2], $A[3][2], ROR #10
    eor $C[0], $C[0], $A[2][0], ROR #39
    eor $C[4], $C[4], $A[0][4], ROR #26
    eor $C[1], $C[1], $A[4][1], ROR #31
    eor $C[3], $C[3], $A[1][3], ROR #36
    eor $C[2], $C[2], $A[1][2], ROR #5

str x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $C[0], $C[0], $A[4][0], ROR #25

ldr x27, [sp, STACK_OFFSET_x27_A44]

    eor $C[4], $C[4], $A[4][4], ROR #15
    eor $C[1], $C[1], $A[1][1], ROR #27
    eor $C[3], $C[3], $A[4][3], ROR #2

ldr x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $E[1], $C[0], $C[2], ROR #61
    ror $C[2], $C[2], 62
    eor $E[3], $C[2], $C[4], ROR #57
    ror $C[4], $C[4], 58
    eor $E[0], $C[4], $C[1], ROR #55
    ror $C[1], $C[1], 56
    eor $E[2], $C[1], $C[3], ROR #63
    eor $E[4], $C[3], $C[0], ROR #63

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

    ldr $count, [sp, #STACK_OFFSET_COUNT]

    load_constant_ptr_stack
    ldr $cur_const, [$const_addr, $count, UXTW #3]
    add $count, $count, #1
	str $count , [sp , #STACK_OFFSET_COUNT]

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

.macro final_rotate_store
// First iteration
    eor $C[2], $A[4][2], $A[0][2], ROR #52
    eor $C[0], $A[0][0], $A[1][0], ROR #61
    eor $C[4], $A[2][4], $A[1][4], ROR #50
    eor $C[1], $A[2][1], $A[3][1], ROR #57
    eor $C[3], $A[0][3], $A[2][3], ROR #63
    eor $C[2], $C[2], $A[2][2], ROR #48
    eor $C[0], $C[0], $A[3][0], ROR #54
    eor $C[4], $C[4], $A[3][4], ROR #34
    eor $C[1], $C[1], $A[0][1], ROR #51
    eor $C[3], $C[3], $A[3][3], ROR #37
    eor $C[2], $C[2], $A[3][2], ROR #10
    eor $C[0], $C[0], $A[2][0], ROR #39
    eor $C[4], $C[4], $A[0][4], ROR #26
    eor $C[1], $C[1], $A[4][1], ROR #31
    eor $C[3], $C[3], $A[1][3], ROR #36
    eor $C[2], $C[2], $A[1][2], ROR #5

str x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $C[0], $C[0], $A[4][0], ROR #25

ldr x27, [sp, STACK_OFFSET_x27_A44]

    eor $C[4], $C[4], $A[4][4], ROR #15
    eor $C[1], $C[1], $A[1][1], ROR #27
    eor $C[3], $C[3], $A[4][3], ROR #2

ldr x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $E[1], $C[0], $C[2], ROR #61
    ror $C[2], $C[2], 62
    eor $E[3], $C[2], $C[4], ROR #57
    ror $C[4], $C[4], 58
    eor $E[0], $C[4], $C[1], ROR #55
    ror $C[1], $C[1], 56
    eor $E[2], $C[1], $C[3], ROR #63
    eor $E[4], $C[3], $C[0], ROR #63

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

    ldr $count, [sp, #STACK_OFFSET_COUNT]

    load_constant_ptr_stack
    ldr $cur_const, [$const_addr, $count, UXTW #3]
    add $count, $count, #1
	str $count , [sp , #STACK_OFFSET_COUNT]

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

// Second iteration 
    eor $C[2], $A[4][2], $A[0][2], ROR #52
    eor $C[0], $A[0][0], $A[1][0], ROR #61
    eor $C[4], $A[2][4], $A[1][4], ROR #50
    eor $C[1], $A[2][1], $A[3][1], ROR #57
    eor $C[3], $A[0][3], $A[2][3], ROR #63
    eor $C[2], $C[2], $A[2][2], ROR #48
    eor $C[0], $C[0], $A[3][0], ROR #54
    eor $C[4], $C[4], $A[3][4], ROR #34
    eor $C[1], $C[1], $A[0][1], ROR #51
    eor $C[3], $C[3], $A[3][3], ROR #37
    eor $C[2], $C[2], $A[3][2], ROR #10
    eor $C[0], $C[0], $A[2][0], ROR #39
    eor $C[4], $C[4], $A[0][4], ROR #26
    eor $C[1], $C[1], $A[4][1], ROR #31
    eor $C[3], $C[3], $A[1][3], ROR #36
    eor $C[2], $C[2], $A[1][2], ROR #5

str x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $C[0], $C[0], $A[4][0], ROR #25

ldr x27, [sp, STACK_OFFSET_x27_A44]

    eor $C[4], $C[4], $A[4][4], ROR #15
    eor $C[1], $C[1], $A[1][1], ROR #27
    eor $C[3], $C[3], $A[4][3], ROR #2

ldr x27, [sp, STACK_OFFSET_x27_C2_E3]

    eor $E[1], $C[0], $C[2], ROR #61
    ror $C[2], $C[2], 62
    eor $E[3], $C[2], $C[4], ROR #57
    ror $C[4], $C[4], 58
    eor $E[0], $C[4], $C[1], ROR #55
    ror $C[1], $C[1], 56
    eor $E[2], $C[1], $C[3], ROR #63
    eor $E[4], $C[3], $C[0], ROR #63

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

    ldr $count, [sp, #STACK_OFFSET_COUNT]

    load_constant_ptr_stack
    ldr $cur_const, [$const_addr, $count, UXTW #3]
    add $count, $count, #1
	str $count , [sp , #STACK_OFFSET_COUNT]

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

// Final rotate
ldr x27, [sp, #STACK_OFFSET_x27_A44] // load A[2][3]
    ror $A[1][0], $A[1][0], #(64-3)
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

.type	keccak_f1600_x4_neon_scalar_asm, %function
.align	4
keccak_f1600_x4_neon_scalar_asm:
	AARCH64_SIGN_LINK_REGISTER
	sub sp, sp, #12*8
	stp $C[0], $C[4], [sp, #6*8]

	hybrid_round_initial
    
 loop:
  	keccak_f1600_round_noninitial
    cmp $count, #(KECCAK_F1600_ROUNDS-3)
    ble loop

    final_rotate_store 

	ldp $C[0], $C[4], [sp, #6*8]
	add sp, sp, #12*8
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	keccak_f1600_x4_neon_scalar_asm, .-keccak_f1600_x4_neon_scalar_asm

.type	KeccakF1600, %function
.align	5
KeccakF1600:
	AARCH64_SIGN_LINK_REGISTER
	alloc_stack_save_GPRs_KeccakF1600
	
	bl keccak_f1600_x4_neon_scalar_asm
	
	free_stack_restore_GPRs_KeccakF1600
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	KeccakF1600, .-KeccakF1600

.globl	SHA3_Absorb_x4_neon_scalar
.type	SHA3_Absorb_x4_neon_scalar, %function
.align	5
SHA3_Absorb_x4_neon_scalar:
	AARCH64_SIGN_LINK_REGISTER
	alloc_stack_save_GPRs_absorb
	offload_and_move_args
	load_bitstate
	b	.Loop_absorb
.align	4
.Loop_absorb:
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
	eor	$A[$i/5][$i%5], $A[$i/5][$i%5], $inp
	cmp	$bsz, #8*($i+2)
	blo	.Lprocess_block
	ldr	$inp, [$inp_adr], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	$inp, $inp
#endif
	eor	$A[$j/5][$j%5], $A[$j/5][$j%5], $inp
	beq	.Lprocess_block
___
}
$code.=<<___;
	ldr	$inp, [$inp_adr], #8		// *inp++
#ifdef	__AARCH64EB__
	rev	$inp, $inp
#endif
	eor	$A[$j/5][$j%5], $A[$j/5][$j%5], $inp
.Lprocess_block:
	str	$inp_adr, [sp, #STACK_OFFSET_INPUT_ADR]			// save input address

	bl keccak_f1600_x4_neon_scalar_asm

	ldr	$inp_adr, [sp, #STACK_OFFSET_INPUT_ADR]			// restore arguments
	ldp	$len, $bsz, [sp, #STACK_OFFSET_LENGTH]
	b	.Loop_absorb
.align	4
.Labsorbed:
	ldr	$bitstate_adr, [sp, #STACK_OFFSET_BITSTATE_ADR]
	store_bitstate
	free_stack_restore_GPRs_absorb
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	SHA3_Absorb_x4_neon_scalar, .-SHA3_Absorb_x4_neon_scalar
___
{
my ($A_flat, $out, $len, $bsz) = map("x$_", (19..22));
$code.=<<___;
.globl	SHA3_Squeeze_x4_neon_scalar
.type	SHA3_Squeeze_x4_neon_scalar, %function
.align	5
SHA3_Squeeze_x4_neon_scalar:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	cmp	x2, #0
    beq	.Lsqueeze_abort
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	mov	$A_flat, x0			// put $A[4][2]de arguments
	mov	$out, x1
	mov	$len, x2
	mov	$bsz, x3
.Loop_squeeze:
	ldr	x4, [x0], #8
	cmp	$len, #8
	blo	.Lsqueeze_tail
#ifdef	__AARCH64EB__
	rev	x4, x4
#endif
	str	x4, [$out], #8
	subs	$len, $len, #8
	beq	.Lsqueeze_done
	subs	x3, x3, #8
	bhi	.Loop_squeeze
	mov	x0, $A_flat
	bl	KeccakF1600
	mov	x0, $A_flat
	mov	x3, $bsz
	b	.Loop_squeeze
.align	4
.Lsqueeze_tail:
	strb	w4, [$out], #1
	lsr	x4, x4, #8
	subs	$len, $len, #1
	beq	.Lsqueeze_done
	strb	w4, [$out], #1
	lsr	x4, x4, #8
	subs	$len, $len, #1
	beq	.Lsqueeze_done
	strb	w4, [$out], #1
	lsr	x4, x4, #8
	subs	$len, $len, #1
	beq	.Lsqueeze_done
	strb	w4, [$out], #1
	lsr	x4, x4, #8
	subs	$len, $len, #1
	beq	.Lsqueeze_done
	strb	w4, [$out], #1
	lsr	x4, x4, #8
	subs	$len, $len, #1
	beq	.Lsqueeze_done
	strb	w4, [$out], #1
	lsr	x4, x4, #8
	subs	$len, $len, #1
	beq	.Lsqueeze_done
	strb	w4, [$out], #1
.Lsqueeze_done:
	ldp	x19, x20, [sp, #16]
	ldp	x21, x22, [sp, #32]
.Lsqueeze_abort:
	ldp	x29, x30, [sp], #48
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	SHA3_Squeeze_x4_neon_scalar, .-SHA3_Squeeze_x4_neon_scalar
___
}								}}}
								
$code.=<<___;
.asciz	"Keccak-1600 absorb and squeeze for ARMv8, CRYPTOGAMS by <appro\@openssl.org>"
___

foreach(split("\n", $code)) {
	s/\`([^\`]*)\`/eval($1)/ge;
	m/\bld1r\b/ and s/\.16b/.2d/g;
	print $_, "\n";
}

close STDOUT or die "error closing STDOUT: $!";