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
#define SEP  ;
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

$input_addr         =  "x0";
$const_addr         =  "x26";
$count              =  "w27";
$out_count          =  "w27";
$cur_const          =  "x26";

$code.=<<___;


/****************** REGISTER ALLOCATIONS *******************/


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
#define STACK_OFFSET_CONST_VEC (5*8)
#define STACK_OFFSET_x27_A44   (6*8)
#define STACK_OFFSET_x27_C2_E3 (7*8)

#define vAgi_offset 0
#define vAga_offset 1
#define vAge_offset 2

    

    /* Mapping of Kecck-f1600 SIMD state to vector registers
     * at the beginning and end of each round. */

   /* Mapping of Kecck-f1600 state to vector registers
     * at the beginning and end of each round. */
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

    tmp .req x30

/************************ MACROS ****************************/

/* Macros using v8.4-A SHA-3 instructions */

.macro load_constant_ptr_stack
    ldr $const_addr, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]
.endm

.macro load_constant_ptr
	adr $const_addr, round_constants
.endm
.macro eor3_m1_0 d s0 s1 s2
    eor \\d\\().16b, \\s0\\().16b, \\s1\\().16b
.endm

.macro eor2 d s0 s1
    eor \\d\\().16b, \\s0\\().16b, \\s1\\().16b
.endm

.macro eor3_m1_1 d s0 s1 s2
    eor \\d\\().16b, \\d\\().16b,  \\s2\\().16b
.endm


.macro eor3_m1 d s0 s1 s2
    eor3_m1_0 \\d\\(), \\s0\\(), \\s1\\(), \\s2\\()
    eor3_m1_1 \\d\\(), \\s0\\(), \\s1\\(), \\s2\\()
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
    ldr vAbaq, [ $input_addr, #(32*0)]
    ldr vAbeq, [ $input_addr, #(32*0+32)]
    ldr vAbiq, [ $input_addr, #(32*2)]
    ldr vAboq, [ $input_addr, #(32*2+32)]
    ldr vAbuq, [ $input_addr, #(32*4)]
    ldr vAgaq, [ $input_addr, #(32*4+32)]
    ldr vAgeq, [ $input_addr, #(32*6)]
    ldr vAgiq, [ $input_addr, #(32*6+32)]
    ldr vAgoq, [ $input_addr, #(32*8)]
    ldr vAguq, [ $input_addr, #(32*8+32)]
    ldr vAkaq, [ $input_addr, #(32*10)]
    ldr vAkeq, [ $input_addr, #(32*10+32)]
    ldr vAkiq, [ $input_addr, #(32*12)]
    ldr vAkoq, [ $input_addr, #(32*12+32)]
    ldr vAkuq, [ $input_addr, #(32*14)]
    ldr vAmaq, [ $input_addr, #(32*14+32)]
    ldr vAmeq, [ $input_addr, #(32*16)]
    ldr vAmiq, [ $input_addr, #(32*16+32)]
    ldr vAmoq, [ $input_addr, #(32*18)]
    ldr vAmuq, [ $input_addr, #(32*18+32)]
    ldr vAsaq, [ $input_addr, #(32*20)]
    ldr vAseq, [ $input_addr, #(32*20+32)]
    ldr vAsiq, [ $input_addr, #(32*22)]
    ldr vAsoq, [ $input_addr, #(32*22+32)]
    ldr vAsuq, [ $input_addr, #(32*24)]
.endm

.macro store_input_vector
    str vAbaq, [ $input_addr, #(32*0)]
    str vAbeq, [ $input_addr, #(32*0+32)]
    str vAbiq, [ $input_addr, #(32*2)]
    str vAboq, [ $input_addr, #(32*2+32)]
    str vAbuq, [ $input_addr, #(32*4)]
    str vAgaq, [ $input_addr, #(32*4+32)]
    str vAgeq, [ $input_addr, #(32*6)]
    str vAgiq, [ $input_addr, #(32*6+32)]
    str vAgoq, [ $input_addr, #(32*8)]
    str vAguq, [ $input_addr, #(32*8+32)]
    str vAkaq, [ $input_addr, #(32*10)]
    str vAkeq, [ $input_addr, #(32*10+32)]
    str vAkiq, [ $input_addr, #(32*12)]
    str vAkoq, [ $input_addr, #(32*12+32)]
    str vAkuq, [ $input_addr, #(32*14)]
    str vAmaq, [ $input_addr, #(32*14+32)]
    str vAmeq, [ $input_addr, #(32*16)]
    str vAmiq, [ $input_addr, #(32*16+32)]
    str vAmoq, [ $input_addr, #(32*18)]
    str vAmuq, [ $input_addr, #(32*18+32)]
    str vAsaq, [ $input_addr, #(32*20)]
    str vAseq, [ $input_addr, #(32*20+32)]
    str vAsiq, [ $input_addr, #(32*22)]
    str vAsoq, [ $input_addr, #(32*22+32)]
    str vAsuq, [ $input_addr, #(32*24)]
.endm

.macro store_input_scalar
    str $A[0][0],[ $input_addr, 32*0 ]
    str $A[0][1], [ $input_addr, 32*1 ]
    str $A[0][2], [ $input_addr, 32*2 ]
    str $A[0][3], [ $input_addr, 32*3 ]
    str $A[0][4], [ $input_addr, 32*4 ]
    str $A[1][0], [ $input_addr, 32*5 ]
    str $A[1][1], [ $input_addr, 32*6 ]
    str $A[1][2], [ $input_addr, 32*7 ]
    str $A[1][3], [ $input_addr, 32*8 ]
    str $A[1][4], [ $input_addr, 32*9 ]
    str $A[2][0], [ $input_addr, 32*10]
    str $A[2][1], [ $input_addr, 32*11]
    str $A[2][2], [ $input_addr, 32*12]
    str $A[2][3], [ $input_addr, 32*13]
    str $A[2][4], [ $input_addr, 32*14]
    str $A[3][0], [ $input_addr, 32*15]
    str $A[3][1], [ $input_addr, 32*16]
    str $A[3][2], [ $input_addr, 32*17]
    str $A[3][3], [ $input_addr, 32*18]
    str $A[3][4], [ $input_addr, 32*19]
    str $A[4][0], [ $input_addr, 32*20]
    str $A[4][1], [ $input_addr, 32*21]
    str $A[4][2], [ $input_addr, 32*22]
    str $A[4][3], [ $input_addr, 32*23]
    str $A[4][4], [ $input_addr, 32*24]
.endm

.macro load_input_scalar
    ldr $A[0][0],[ $input_addr, 32*0 ]
    ldr $A[0][1], [ $input_addr, 32*1 ]
    ldr $A[0][2], [ $input_addr, 32*2 ]
    ldr $A[0][3], [ $input_addr, 32*3 ]
    ldr $A[0][4], [ $input_addr, 32*4 ]
    ldr $A[1][0], [ $input_addr, 32*5 ]
    ldr $A[1][1], [ $input_addr, 32*6 ]
    ldr $A[1][2], [ $input_addr, 32*7 ]
    ldr $A[1][3], [ $input_addr, 32*8 ]
    ldr $A[1][4], [ $input_addr, 32*9 ]
    ldr $A[2][0], [ $input_addr, 32*10]
    ldr $A[2][1], [ $input_addr, 32*11]
    ldr $A[2][2], [ $input_addr, 32*12]
    ldr $A[2][3], [ $input_addr, 32*13]
    ldr $A[2][4], [ $input_addr, 32*14]
    ldr $A[3][0], [ $input_addr, 32*15]
    ldr $A[3][1], [ $input_addr, 32*16]
    ldr $A[3][2], [ $input_addr, 32*17]
    ldr $A[3][3], [ $input_addr, 32*18]
    ldr $A[3][4], [ $input_addr, 32*19]
    ldr $A[4][0], [ $input_addr, 32*20]
    ldr $A[4][1], [ $input_addr, 32*21]
    ldr $A[4][2], [ $input_addr, 32*22]
    ldr $A[4][3], [ $input_addr, 32*23]
    ldr $A[4][4], [ $input_addr, 32*24]
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
    eor \\d\\()st, \\src0, \\src1
    eor \\d\\()st, \\d\\()st,  \\src2
    eor \\d\\()st, \\d\\()st,  \\src3
    eor \\d\\()st, \\d\\()st,  \\src4
.endm

.macro xor_rol dst, src1, src0, imm
    eor \\d\\()st, \\src0, \\src1, ROR  #(64-\\imm)
.endm

.macro bic_rol dst, src1, src0, imm
    bic \\d\\()st, \\src0, \\src1, ROR  #(64-\\imm)
.endm

.macro rotate dst, src, imm
    ror \\d\\()st, \\src, #(64-\\imm)
.endm

.macro hybrid_round_initial
eor $C[4], $A[3][4], $A[4][4]
str x27, [sp, #STACK_OFFSET_x27_A44]
eor $C[0], $A[3][0], $A[4][0]                                               SEP      eor3_m1_0 C1,vAbe,vAge,vAke
eor $C[1], $A[3][1], $A[4][1]                                               SEP
eor $C[2], $A[3][2], $A[4][2]                                               SEP      eor3_m1_0 C3,vAbo,vAgo,vAko
eor $C[3], $A[3][3], $A[4][3]                                               SEP
                                                                            SEP      eor3_m1_0 C0,vAba,vAga,vAka
eor $C[0], $A[2][0], $C[0]                                                  SEP
eor $C[1], $A[2][1], $C[1]                                                  SEP      eor3_m1_0 C2,vAbi,vAgi,vAki
eor $C[2], $A[2][2], $C[2]                                                  SEP
eor $C[3], $A[2][3], $C[3]                                                  SEP      eor3_m1_0 C4,vAbu,vAgu,vAku
eor $C[4], $A[2][4], $C[4]                                                  SEP
eor $C[0], $A[1][0], $C[0]                                                  SEP      eor3_m1_1 C1,vAbe,vAge,vAke
eor $C[1], $A[1][1], $C[1]                                                  SEP      eor3_m1_1 C3,vAbo,vAgo,vAko
eor $C[2], $A[1][2], $C[2]                                                  SEP
eor $C[3], $A[1][3], $C[3]                                                  SEP      eor3_m1_1 C0,vAba,vAga,vAka
eor $C[4], $A[1][4], $C[4]                                                  SEP
eor $C[0], $A[0][0], $C[0]                                                  SEP      eor3_m1_1 C2,vAbi,vAgi,vAki
eor $C[1], $A[0][1], $C[1]                                                  SEP
eor $C[2], $A[0][2], $C[2]                                                  SEP      eor3_m1_1 C4,vAbu,vAgu,vAku
eor $C[3], $A[0][3], $C[3]                                                  SEP
eor $C[4], $A[0][4], $C[4]                                                  SEP      eor3_m1_0 C1, C1,vAme, vAse
eor $E[1], $C[0], $C[2], ROR #63                                            SEP      eor3_m1_0 C3, C3,vAmo, vAso
eor $E[3], $C[2], $C[4], ROR #63                                            SEP
eor $E[0], $C[4], $C[1], ROR #63                                            SEP      eor3_m1_0 C0, C0,vAma, vAsa
eor $E[2], $C[1], $C[3], ROR #63                                            SEP
eor $E[4], $C[3], $C[0], ROR #63                                            SEP      eor3_m1_0 C2, C2,vAmi, vAsi
eor $A_[0][0], $A[0][0], $E[0]                                              SEP
eor $A_[4][0], $A[0][2], $E[2]                                              SEP      eor3_m1_0 C4, C4,vAmu, vAsu
eor $A_[0][2], $A[2][2], $E[2]                                              SEP
eor $A_[2][2], $A[2][3], $E[3]                                              SEP      eor3_m1_1 C1, C1,vAme, vAse
eor $A_[2][3], $A[3][4], $E[4]                                              SEP      eor3_m1_1 C3, C3,vAmo, vAso
eor $A_[3][4], $A[4][3], $E[3]                                              SEP
eor $A_[4][3], $A[3][0], $E[0]                                              SEP      eor3_m1_1 C0, C0,vAma, vAsa
eor $A_[2][0], $A[0][1], $E[1]                                              SEP
eor $A_[4][1], $A[1][3], $E[3]                                              SEP      eor3_m1_1 C2, C2,vAmi, vAsi
eor $A_[1][3], $A[3][1], $E[1]                                              SEP
eor $A_[2][1], $A[1][2], $E[2]                                              SEP      eor3_m1_1 C4, C4,vAmu, vAsu
eor $A_[1][2], $A[2][0], $E[0]                                              SEP
eor $A_[1][0], $A[0][3], $E[3]                                              SEP      vvtmp .req vBba
eor $A_[0][3], $A[3][3], $E[3]                                              SEP      rax1_m1 E2, C1, C3
eor $A_[3][3], $A[3][2], $E[2]                                              SEP
eor $A_[3][2], $A[2][1], $E[1]                                              SEP      rax1_m1 E4, C3, C0
eor $A_[1][1], $A[1][4], $E[4]                                              SEP
eor $A_[1][4], $A[4][2], $E[2]                                              SEP      rax1_m1 E1, C0, C2
eor $A_[4][2], $A[2][4], $E[4]                                              SEP
eor $A_[2][4], $A[4][0], $E[0]                                              SEP      rax1_m1 E3, C2, C4
eor $A_[3][0], $A[0][4], $E[4]                                              SEP
ldr x27, [sp, STACK_OFFSET_x27_A44]
eor $A_[0][4], $A[4][4], $E[4]                                              SEP      str vAgiq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
eor $A_[4][4], $A[4][1], $E[1]                                              SEP      rax1_m1 E0, C4, C1
eor $A_[3][1], $A[1][0], $E[0]                                              SEP
eor $A_[0][1], $A[1][1], $E[1]                                              SEP      /* 25x XAR, 75 in total */
load_constant_ptr      //into x26                                                     SEP
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                                    SEP      .unreq vvtmp
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                                    SEP
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                                     SEP      vvtmp .req C1
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                                    SEP
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                                     SEP      vvtmpq .req C1q
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                                    SEP      xar_m1 vBgi, vAka, E0, 61
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                                     SEP
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                                    SEP      xar_m1 vBga, vAbo, E3, 36
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                                     SEP
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                                    SEP      str vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                                     SEP
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                                    SEP      xar_m1 vBbo, vAmo, E3, 43
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                                     SEP
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                                    SEP      xar_m1 vBmo, vAmi, E2, 49
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                                      SEP      str vAgeq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAge_offset)]
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                                    SEP
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                                     SEP      xar_m1 vBmi, vAke, E1, 54
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                                     SEP
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                                     SEP      xar_m1 vBge, vAgu, E4, 44
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                                    SEP
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                                     SEP      bcax_m1 vAga, vBga, vBgi, vBge
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                                     SEP
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                                     SEP      eor vBba.16b, vAba.16b, E0.16b
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                                    SEP
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                                     SEP      xar_m1 vBsa, vAbi, E2, 2
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                                    SEP      xar_m1 vBbi, vAki, E2, 21
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                                     SEP
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                                     SEP      xar_m1 vBki, vAko, E3, 39
str $const_addr, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST)]          SEP
ldr $cur_const, [$const_addr]                                               SEP      xar_m1 vBko, vAmu, E4, 56
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                                     SEP
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                                    SEP      xar_m1 vBmu, vAso, E3, 8
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                                     SEP
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                                     SEP      xar_m1 vBso, vAma, E0, 23
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                                     SEP      xar_m1 vBka, vAbe, E1, 63
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                                    SEP
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                                     SEP      xar_m1 vBse, vAgo, E3, 9
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                                    SEP
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                                     SEP      xar_m1 vBgo, vAme, E1, 19
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                                    SEP
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                                     SEP      bcax_m1 vAge, vBge, vBgo, vBgi
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                                    SEP
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                                     SEP      ldr vvtmpq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
str x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                SEP      xar_m1 vBke, vvtmp, E2, 58
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                                    SEP
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                                     SEP      xar_m1 vBgu, vAsi, E2, 3
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                                    SEP
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                                     SEP      bcax_m1 vAgi, vBgi, vBgu, vBgo
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                                    SEP
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                                     SEP      xar_m1 vBsi, vAku, E4, 25
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                                    SEP
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                                     SEP      xar_m1 vBku, vAsa, E0, 46
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                                     SEP      xar_m1 vBma, vAbu, E4, 37
mov $count, #1                                                              SEP
eor $A[0][0], $A[0][0], $cur_const                                          SEP
str $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]               SEP              
eor $C[2], $A[4][2], $A[0][2], ROR #52                                      SEP      xar_m1 vBbu, vAsu, E4, 50
eor $C[0], $A[0][0], $A[1][0], ROR #61                                      SEP
eor $C[4], $A[2][4], $A[1][4], ROR #50                                      SEP      xar_m1 vBsu, vAse, E1, 62
eor $C[1], $A[2][1], $A[3][1], ROR #57                                      SEP
eor $C[3], $A[0][3], $A[2][3], ROR #63                                      SEP      ldp vvtmpq, E3q, [sp, #(STACK_BASE_TMP_VREGS + 16*vAga_offset)]
eor $C[2], $C[2], $A[2][2], ROR #48                                         SEP
eor $C[0], $C[0], $A[3][0], ROR #54                                         SEP      xar_m1 vBme, vvtmp, E0, 28
eor $C[4], $C[4], $A[3][4], ROR #34                                         SEP      xar_m1 vBbe, E3,  E1, 20
eor $C[1], $C[1], $A[0][1], ROR #51                                         SEP
eor $C[3], $C[3], $A[3][3], ROR #37                                         SEP      /* 25x BCAX, 50 in total */
eor $C[2], $C[2], $A[3][2], ROR #10                                         SEP
eor $C[0], $C[0], $A[2][0], ROR #39                                         SEP      bcax_m1 vAgo, vBgo, vBga, vBgu
eor $C[4], $C[4], $A[0][4], ROR #26                                         SEP
eor $C[1], $C[1], $A[4][1], ROR #31                                         SEP      bcax_m1 vAgu, vBgu, vBge, vBga
eor $C[3], $C[3], $A[1][3], ROR #36                                         SEP
eor $C[2], $C[2], $A[1][2], ROR #5                                          SEP      bcax_m1 vAka, vBka, vBki, vBke
str x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]              SEP      bcax_m1 vAke, vBke, vBko, vBki
eor $C[0], $C[0], $A[4][0], ROR #25                                         SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                SEP      .unreq vvtmp
eor $C[4], $C[4], $A[4][4], ROR #15                                         SEP
eor $C[1], $C[1], $A[1][1], ROR #27                                         SEP      .unreq vvtmpq
eor $C[3], $C[3], $A[4][3], ROR #2                                          SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]              SEP      eor2    C0,  vAka, vAga
eor $E[1], $C[0], $C[2], ROR #61                                            SEP
ror $C[2], $C[2], 62                                                        SEP      str vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
eor $E[3], $C[2], $C[4], ROR #57                                            SEP      vvtmp .req vAga
ror $C[4], $C[4], 58                                                        SEP
eor $E[0], $C[4], $C[1], ROR #55                                            SEP      vvtmpq .req vAgaq
ror $C[1], $C[1], 56                                                        SEP
eor $E[2], $C[1], $C[3], ROR #63                                            SEP
eor $E[4], $C[3], $C[0], ROR #63                                            SEP
eor $A_[0][0], $E[0], $A[0][0]                                              SEP
eor $A_[4][0], $E[2], $A[0][2], ROR #50                                     SEP      bcax_m1 vAki, vBki, vBku, vBko
eor $A_[0][2], $E[2], $A[2][2], ROR #46                                     SEP
eor $A_[2][2], $E[3], $A[2][3], ROR #63                                     SEP      bcax_m1 vAko, vBko, vBka, vBku
eor $A_[2][3], $E[4], $A[3][4], ROR #28                                     SEP
eor $A_[3][4], $E[3], $A[4][3], ROR #2                                      SEP      eor2    C1,  vAke, vAge
eor $A_[4][3], $E[0], $A[3][0], ROR #54                                     SEP      bcax_m1 vAku, vBku, vBke, vBka
eor $A_[2][0], $E[1], $A[0][1], ROR #43                                     SEP
eor $A_[4][1], $E[3], $A[1][3], ROR #36                                     SEP      eor2    C2,  vAki, vAgi
eor $A_[1][3], $E[1], $A[3][1], ROR #49                                     SEP
eor $A_[2][1], $E[2], $A[1][2], ROR #3                                      SEP      bcax_m1 vAma, vBma, vBmi, vBme
eor $A_[1][2], $E[0], $A[2][0], ROR #39                                     SEP
eor $A_[1][0], $E[3], $A[0][3]                                              SEP      eor2    C3,  vAko, vAgo
eor $A_[0][3], $E[3], $A[3][3], ROR #37                                     SEP
eor $A_[3][3], $E[2], $A[3][2], ROR #8                                      SEP      bcax_m1 vAme, vBme, vBmo, vBmi
eor $A_[3][2], $E[1], $A[2][1], ROR #56                                     SEP
eor $A_[1][1], $E[4], $A[1][4], ROR #44                                     SEP      eor2    C4,  vAku, vAgu
eor $A_[1][4], $E[2], $A[4][2], ROR #62                                     SEP      bcax_m1 vAmi, vBmi, vBmu, vBmo
eor $A_[4][2], $E[4], $A[2][4], ROR #58                                     SEP
eor $A_[2][4], $E[0], $A[4][0], ROR #25                                     SEP      eor2    C0,  C0,  vAma
eor $A_[3][0], $E[4], $A[0][4], ROR #20                                     SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]
eor $A_[0][4], $E[4], $A[4][4], ROR #9                                      SEP      bcax_m1 vAmo, vBmo, vBma, vBmu
eor $A_[4][4], $E[1], $A[4][1], ROR #23                                     SEP
eor $A_[3][1], $E[0], $A[1][0], ROR #61                                     SEP      eor2    C1,  C1,  vAme
eor $A_[0][1], $E[1], $A[1][1], ROR #19                                     SEP
                                                                            SEP      bcax_m1 vAmu, vBmu, vBme, vBma
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                                    SEP      eor2    C2,  C2,  vAmi
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                                    SEP
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                                     SEP      bcax_m1 vAsa, vBsa, vBsi, vBse
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                                    SEP
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                                     SEP      eor2    C3,  C3,  vAmo
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                                    SEP
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                                     SEP      bcax_m1 vAse, vBse, vBso, vBsi
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                                    SEP
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                                     SEP      eor2    C4,  C4,  vAmu
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                                    SEP      bcax_m1 vAsi, vBsi, vBsu, vBso
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                                     SEP
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                                    SEP      eor2    C0,  C0,  vAsa
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                                     SEP
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                                    SEP      bcax_m1 vAso, vBso, vBsa, vBsu
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                                      SEP
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                                    SEP      eor2    C1,  C1,  vAse
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                                     SEP
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                                     SEP      bcax_m1 vAsu, vBsu, vBse, vBsa
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                                     SEP      eor2    C2,  C2,  vAsi
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                                    SEP
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                                     SEP      eor2    C3,  C3,  vAso
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                                     SEP
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                                     SEP      bcax_m1 vAba, vBba, vBbi, vBbe
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                                    SEP
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                                     SEP      bcax_m1 vAbe, vBbe, vBbo, vBbi
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                                    SEP
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                                     SEP      eor2    C1,  C1,  vAbe
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                                     SEP      ldr x26, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST_VEC)] 
                                                                            SEP      ldr vvtmpq, [x26], #16
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                                     SEP      str x26, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST_VEC)]
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                                    SEP
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                                     SEP
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                                     SEP      eor vAba.16b, vAba.16b, vvtmp.16b
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                                     SEP
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                                    SEP      eor2    C4,  C4,  vAsu
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                                     SEP      bcax_m1 vAbi, vBbi, vBbu, vBbo
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                                    SEP
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                                     SEP      bcax_m1 vAbo, vBbo, vBba, vBbu
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                                    SEP
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                                     SEP      eor2    C3,  C3,  vAbo
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                                    SEP
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                                     SEP      eor2    C2,  C2,  vAbi
str x27, [sp,(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                  SEP
ldr $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
load_constant_ptr_stack
ldr $cur_const, [$const_addr, $count, UXTW #3]
add $count, $count, #1
str $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                                    SEP      eor2    C0,  C0,  vAba
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                                     SEP      bcax_m1 vAbu, vBbu, vBbe, vBba
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                                    SEP
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                                     SEP      eor2    C4,  C4,  vAbu
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                                    SEP
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                                     SEP      ldr vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                                    SEP
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                                     SEP      .unreq vvtmp
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                                     SEP
eor $A[0][0], $A[0][0], $cur_const                                          SEP      .unreq vvtmpq
  
.endm


.macro  hybrid_round_noninitial
                                                                             SEP
eor $C[2], $A[4][2], $A[0][2], ROR #52                                       SEP      vvtmp .req vBba
eor $C[0], $A[0][0], $A[1][0], ROR #61                                       SEP      rax1_m1 E2, C1, C3
eor $C[4], $A[2][4], $A[1][4], ROR #50                                       SEP      rax1_m1 E4, C3, C0
eor $C[1], $A[2][1], $A[3][1], ROR #57                                       SEP
eor $C[3], $A[0][3], $A[2][3], ROR #63                                       SEP
eor $C[2], $C[2], $A[2][2], ROR #48                                          SEP
eor $C[0], $C[0], $A[3][0], ROR #54                                          SEP      rax1_m1 E1, C0, C2
eor $C[4], $C[4], $A[3][4], ROR #34                                          SEP
eor $C[1], $C[1], $A[0][1], ROR #51                                          SEP
eor $C[3], $C[3], $A[3][3], ROR #37                                          SEP      rax1_m1 E3, C2, C4
eor $C[2], $C[2], $A[3][2], ROR #10                                          SEP
eor $C[0], $C[0], $A[2][0], ROR #39                                          SEP      str vAgiq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
eor $C[4], $C[4], $A[0][4], ROR #26                                          SEP
eor $C[1], $C[1], $A[4][1], ROR #31                                          SEP      rax1_m1 E0, C4, C1
eor $C[3], $C[3], $A[1][3], ROR #36                                          SEP
eor $C[2], $C[2], $A[1][2], ROR #5                                           SEP      .unreq vvtmp
str x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP
eor $C[0], $C[0], $A[4][0], ROR #25                                          SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                 SEP      vvtmp .req C1
eor $C[4], $C[4], $A[4][4], ROR #15                                          SEP
eor $C[1], $C[1], $A[1][1], ROR #27                                          SEP      vvtmpq .req C1q
eor $C[3], $C[3], $A[4][3], ROR #2                                           SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP      xar_m1 vBgi, vAka, E0, 61
eor $E[1], $C[0], $C[2], ROR #61                                             SEP
ror $C[2], $C[2], 62                                                         SEP      xar_m1 vBga, vAbo, E3, 36
eor $E[3], $C[2], $C[4], ROR #57                                             SEP
ror $C[4], $C[4], 58                                                         SEP
eor $E[0], $C[4], $C[1], ROR #55                                             SEP      str vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
ror $C[1], $C[1], 56                               
eor $E[2], $C[1], $C[3], ROR #63                       
eor $E[4], $C[3], $C[0], ROR #63                
eor $A_[0][0], $E[0], $A[0][0]                                               SEP
eor $A_[4][0], $E[2], $A[0][2], ROR #50                                      SEP      xar_m1 vBbo, vAmo, E3, 43
eor $A_[0][2], $E[2], $A[2][2], ROR #46                                      SEP
eor $A_[2][2], $E[3], $A[2][3], ROR #63                                      SEP      xar_m1 vBmo, vAmi, E2, 49
eor $A_[2][3], $E[4], $A[3][4], ROR #28                                      SEP
eor $A_[3][4], $E[3], $A[4][3], ROR #2                                       SEP
eor $A_[4][3], $E[0], $A[3][0], ROR #54                                      SEP      str vAgeq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAge_offset)]
eor $A_[2][0], $E[1], $A[0][1], ROR #43                                      SEP
eor $A_[4][1], $E[3], $A[1][3], ROR #36                                      SEP      xar_m1 vBmi, vAke, E1, 54
eor $A_[1][3], $E[1], $A[3][1], ROR #49                                      SEP
eor $A_[2][1], $E[2], $A[1][2], ROR #3                                       SEP      xar_m1 vBge, vAgu, E4, 44
eor $A_[1][2], $E[0], $A[2][0], ROR #39                                      SEP
eor $A_[1][0], $E[3], $A[0][3]                                               SEP      bcax_m1 vAga, vBga, vBgi, vBge
eor $A_[0][3], $E[3], $A[3][3], ROR #37                                      SEP
eor $A_[3][3], $E[2], $A[3][2], ROR #8                                       SEP
eor $A_[3][2], $E[1], $A[2][1], ROR #56                                      SEP      eor vBba.16b, vAba.16b, E0.16b
eor $A_[1][1], $E[4], $A[1][4], ROR #44                                      SEP
eor $A_[1][4], $E[2], $A[4][2], ROR #62                                      SEP      xar_m1 vBsa, vAbi, E2, 2
eor $A_[4][2], $E[4], $A[2][4], ROR #58                                      SEP
eor $A_[2][4], $E[0], $A[4][0], ROR #25                                      SEP      xar_m1 vBbi, vAki, E2, 21
eor $A_[3][0], $E[4], $A[0][4], ROR #20                                      SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]
eor $A_[0][4], $E[4], $A[4][4], ROR #9                                       SEP      xar_m1 vBki, vAko, E3, 39
eor $A_[4][4], $E[1], $A[4][1], ROR #23                                      SEP
eor $A_[3][1], $E[0], $A[1][0], ROR #61                                      SEP
eor $A_[0][1], $E[1], $A[1][1], ROR #19                                      SEP      xar_m1 vBko, vAmu, E4, 56
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                                     SEP      xar_m1 vBmu, vAso, E3, 8
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                                     SEP
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                                      SEP      xar_m1 vBso, vAma, E0, 23
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                                     SEP
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                                      SEP
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                                     SEP      xar_m1 vBka, vAbe, E1, 63
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                                      SEP
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                                     SEP      xar_m1 vBse, vAgo, E3, 9
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                                      SEP
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                                     SEP      xar_m1 vBgo, vAme, E1, 19
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                                      SEP
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                                     SEP      bcax_m1 vAge, vBge, vBgo, vBgi
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                                      SEP
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                                     SEP
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                                       SEP      ldr vvtmpq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                                     SEP
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                                      SEP      xar_m1 vBke, vvtmp, E2, 58
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                                      SEP
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                                      SEP      xar_m1 vBgu, vAsi, E2, 3
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                                     SEP
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                                      SEP      bcax_m1 vAgi, vBgi, vBgu, vBgo
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                                      SEP
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                                      SEP
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                                     SEP      xar_m1 vBsi, vAku, E4, 25
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                                      SEP
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                                     SEP      xar_m1 vBku, vAsa, E0, 46
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                                      SEP
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                                      SEP      xar_m1 vBma, vAbu, E4, 37
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                                      SEP      xar_m1 vBbu, vAsu, E4, 50
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                                     SEP
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                                      SEP      xar_m1 vBsu, vAse, E1, 62
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                                      SEP
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                                      SEP      ldp vvtmpq, E3q, [sp, #(STACK_BASE_TMP_VREGS + 16*vAga_offset)]
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                                     SEP
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                                      SEP      xar_m1 vBme, vvtmp, E0, 28
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                                     SEP
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                                      SEP
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                                     SEP      xar_m1 vBbe, E3,  E1, 20
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                                      SEP
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                                     SEP      bcax_m1 vAgo, vBgo, vBga, vBgu
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                                      SEP
str x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                 SEP      bcax_m1 vAgu, vBgu, vBge, vBga
ldr $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
load_constant_ptr_stack
ldr $cur_const, [$const_addr, $count, UXTW #3]
add $count, $count, #1
str $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                                     SEP
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                                      SEP      bcax_m1 vAka, vBka, vBki, vBke
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                                     SEP
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                                      SEP
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                                     SEP      bcax_m1 vAke, vBke, vBko, vBki
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                                      SEP
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                                     SEP      .unreq vvtmp
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                                      SEP
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                                      SEP      .unreq vvtmpq
eor $A[0][0], $A[0][0], $cur_const                                           SEP
eor $C[2], $A[4][2], $A[0][2], ROR #52                                       SEP      eor2    C0,  vAka, vAga
eor $C[0], $A[0][0], $A[1][0], ROR #61                                       SEP
eor $C[4], $A[2][4], $A[1][4], ROR #50                                       SEP      str vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
eor $C[1], $A[2][1], $A[3][1], ROR #57                                       SEP
eor $C[3], $A[0][3], $A[2][3], ROR #63                                       SEP      vvtmp .req vAga
eor $C[2], $C[2], $A[2][2], ROR #48                                          SEP
eor $C[0], $C[0], $A[3][0], ROR #54                                          SEP      vvtmpq .req vAgaq
eor $C[4], $C[4], $A[3][4], ROR #34                                          SEP
eor $C[1], $C[1], $A[0][1], ROR #51                                          SEP
eor $C[3], $C[3], $A[3][3], ROR #37                                          SEP      bcax_m1 vAki, vBki, vBku, vBko
eor $C[2], $C[2], $A[3][2], ROR #10                                          SEP
eor $C[0], $C[0], $A[2][0], ROR #39                                          SEP      bcax_m1 vAko, vBko, vBka, vBku
eor $C[4], $C[4], $A[0][4], ROR #26                                          SEP
eor $C[1], $C[1], $A[4][1], ROR #31                                          SEP      eor2    C1,  vAke, vAge
eor $C[3], $C[3], $A[1][3], ROR #36                                          SEP
eor $C[2], $C[2], $A[1][2], ROR #5                                           SEP      bcax_m1 vAku, vBku, vBke, vBka
str x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP
eor $C[0], $C[0], $A[4][0], ROR #25                                          SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                 SEP      eor2    C2,  vAki, vAgi
eor $C[4], $C[4], $A[4][4], ROR #15                                          SEP
eor $C[1], $C[1], $A[1][1], ROR #27                                          SEP      bcax_m1 vAma, vBma, vBmi, vBme
eor $C[3], $C[3], $A[4][3], ROR #2                                           SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP      eor2    C3,  vAko, vAgo
eor $E[1], $C[0], $C[2], ROR #61                                             SEP
ror $C[2], $C[2], 62                                                         SEP      bcax_m1 vAme, vBme, vBmo, vBmi
eor $E[3], $C[2], $C[4], ROR #57                                             SEP
ror $C[4], $C[4], 58                                                         SEP
eor $E[0], $C[4], $C[1], ROR #55                                             SEP      eor2    C4,  vAku, vAgu
ror $C[1], $C[1], 56                           
eor $E[2], $C[1], $C[3], ROR #63                 
eor $E[4], $C[3], $C[0], ROR #63                
eor $A_[0][0], $E[0], $A[0][0]                                               SEP
eor $A_[4][0], $E[2], $A[0][2], ROR #50                                      SEP      bcax_m1 vAmi, vBmi, vBmu, vBmo
eor $A_[0][2], $E[2], $A[2][2], ROR #46                                      SEP
eor $A_[2][2], $E[3], $A[2][3], ROR #63                                      SEP      eor2    C0,  C0,  vAma
eor $A_[2][3], $E[4], $A[3][4], ROR #28                                      SEP
eor $A_[3][4], $E[3], $A[4][3], ROR #2                                       SEP
eor $A_[4][3], $E[0], $A[3][0], ROR #54                                      SEP      bcax_m1 vAmo, vBmo, vBma, vBmu
eor $A_[2][0], $E[1], $A[0][1], ROR #43                                      SEP
eor $A_[4][1], $E[3], $A[1][3], ROR #36                                      SEP      eor2    C1,  C1,  vAme
eor $A_[1][3], $E[1], $A[3][1], ROR #49                                      SEP
eor $A_[2][1], $E[2], $A[1][2], ROR #3                                       SEP      bcax_m1 vAmu, vBmu, vBme, vBma
eor $A_[1][2], $E[0], $A[2][0], ROR #39                                      SEP
eor $A_[1][0], $E[3], $A[0][3]                                               SEP      eor2    C2,  C2,  vAmi
eor $A_[0][3], $E[3], $A[3][3], ROR #37                                      SEP
eor $A_[3][3], $E[2], $A[3][2], ROR #8                                       SEP
eor $A_[3][2], $E[1], $A[2][1], ROR #56                                      SEP      bcax_m1 vAsa, vBsa, vBsi, vBse
eor $A_[1][1], $E[4], $A[1][4], ROR #44                                      SEP
eor $A_[1][4], $E[2], $A[4][2], ROR #62                                      SEP      eor2    C3,  C3,  vAmo
eor $A_[4][2], $E[4], $A[2][4], ROR #58                                      SEP
eor $A_[2][4], $E[0], $A[4][0], ROR #25                                      SEP      bcax_m1 vAse, vBse, vBso, vBsi
eor $A_[3][0], $E[4], $A[0][4], ROR #20                                      SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]
eor $A_[0][4], $E[4], $A[4][4], ROR #9                                       SEP      eor2    C4,  C4,  vAmu
eor $A_[4][4], $E[1], $A[4][1], ROR #23                                      SEP
eor $A_[3][1], $E[0], $A[1][0], ROR #61                                      SEP
eor $A_[0][1], $E[1], $A[1][1], ROR #19                                      SEP      bcax_m1 vAsi, vBsi, vBsu, vBso
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                                     SEP      eor2    C0,  C0,  vAsa
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                                     SEP
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                                      SEP      bcax_m1 vAso, vBso, vBsa, vBsu
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                                     SEP
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                                      SEP
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                                     SEP      eor2    C1,  C1,  vAse
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                                      SEP
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                                     SEP      bcax_m1 vAsu, vBsu, vBse, vBsa
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                                      SEP
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                                     SEP      eor2    C2,  C2,  vAsi
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                                      SEP
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                                     SEP      eor2    C3,  C3,  vAso
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                                      SEP
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                                     SEP
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                                       SEP      bcax_m1 vAba, vBba, vBbi, vBbe
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                                     SEP
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                                      SEP      bcax_m1 vAbe, vBbe, vBbo, vBbi
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                                      SEP
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                                      SEP      eor2    C1,  C1,  vAbe
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                                     SEP
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                                      SEP      ldr x26, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST_VEC)]
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                                      SEP
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                                      SEP
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                                     SEP      ldr vvtmpq, [x26], #16
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                                      SEP
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                                     SEP      str x26, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST_VEC)]
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                                      SEP
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                                      SEP      eor vAba.16b, vAba.16b, vvtmp.16b
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                                      SEP      eor2    C4,  C4,  vAsu
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                                     SEP
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                                      SEP      bcax_m1 vAbi, vBbi, vBbu, vBbo
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                                      SEP
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                                      SEP      bcax_m1 vAbo, vBbo, vBba, vBbu
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                                     SEP
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                                      SEP      eor2    C3,  C3,  vAbo
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                                     SEP
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                                      SEP
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                                     SEP      eor2    C2,  C2,  vAbi
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                                      SEP
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                                     SEP      eor2    C0,  C0,  vAba
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                                      SEP
str x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                 SEP      bcax_m1 vAbu, vBbu, vBbe, vBba
ldr $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
load_constant_ptr_stack
ldr $cur_const, [$const_addr, $count, UXTW #3]
add $count, $count, #1
str $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                                     SEP
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                                      SEP      eor2    C4,  C4,  vAbu
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                                     SEP
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                                      SEP
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                                     SEP      ldr vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                                      SEP
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                                     SEP      .unreq vvtmp
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                                      SEP
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                                      SEP      .unreq vvtmpq
eor $A[0][0], $A[0][0], $cur_const                                           SEP
.endm

.macro  hybrid_round_final
                                                                             SEP      vvtmp .req vBba
                                                                             SEP      rax1_m1 E2, C1, C3
eor $C[2], $A[4][2], $A[0][2], ROR #52                                       SEP
eor $C[0], $A[0][0], $A[1][0], ROR #61                                       SEP      rax1_m1 E4, C3, C0
eor $C[4], $A[2][4], $A[1][4], ROR #50                                       SEP
eor $C[1], $A[2][1], $A[3][1], ROR #57                                       SEP      rax1_m1 E1, C0, C2
eor $C[3], $A[0][3], $A[2][3], ROR #63                                       SEP
eor $C[2], $C[2], $A[2][2], ROR #48                                          SEP
eor $C[0], $C[0], $A[3][0], ROR #54                                          SEP
eor $C[4], $C[4], $A[3][4], ROR #34                                          SEP
eor $C[1], $C[1], $A[0][1], ROR #51                                          SEP
eor $C[3], $C[3], $A[3][3], ROR #37                                          SEP
eor $C[2], $C[2], $A[3][2], ROR #10                                          SEP
eor $C[0], $C[0], $A[2][0], ROR #39                                          SEP
eor $C[4], $C[4], $A[0][4], ROR #26                                          SEP
eor $C[1], $C[1], $A[4][1], ROR #31                                          SEP      rax1_m1 E3, C2, C4
eor $C[3], $C[3], $A[1][3], ROR #36                                          SEP
eor $C[2], $C[2], $A[1][2], ROR #5                                           SEP
str x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP
eor $C[0], $C[0], $A[4][0], ROR #25                                          SEP      str vAgiq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                 SEP
eor $C[4], $C[4], $A[4][4], ROR #15                                          SEP
eor $C[1], $C[1], $A[1][1], ROR #27                                          SEP      rax1_m1 E0, C4, C1
eor $C[3], $C[3], $A[4][3], ROR #2                                           SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP
eor $E[1], $C[0], $C[2], ROR #61                                             SEP
ror $C[2], $C[2], 62                                                         SEP      .unreq vvtmp
eor $E[3], $C[2], $C[4], ROR #57                                             SEP
ror $C[4], $C[4], 58                                                         SEP
eor $E[0], $C[4], $C[1], ROR #55                                             SEP      vvtmp .req C1
ror $C[1], $C[1], 56                             
eor $E[2], $C[1], $C[3], ROR #63                    
eor $E[4], $C[3], $C[0], ROR #63                 
eor $A_[0][0], $E[0], $A[0][0]                                               SEP
eor $A_[4][0], $E[2], $A[0][2], ROR #50                                      SEP
eor $A_[0][2], $E[2], $A[2][2], ROR #46                                      SEP      vvtmpq .req C1q
eor $A_[2][2], $E[3], $A[2][3], ROR #63                                      SEP
eor $A_[2][3], $E[4], $A[3][4], ROR #28                                      SEP
eor $A_[3][4], $E[3], $A[4][3], ROR #2                                       SEP
eor $A_[4][3], $E[0], $A[3][0], ROR #54                                      SEP      xar_m1 vBgi, vAka, E0, 61
eor $A_[2][0], $E[1], $A[0][1], ROR #43                                      SEP
eor $A_[4][1], $E[3], $A[1][3], ROR #36                                      SEP
eor $A_[1][3], $E[1], $A[3][1], ROR #49                                      SEP      xar_m1 vBga, vAbo, E3, 36
eor $A_[2][1], $E[2], $A[1][2], ROR #3                                       SEP
eor $A_[1][2], $E[0], $A[2][0], ROR #39                                      SEP
eor $A_[1][0], $E[3], $A[0][3]                                               SEP
eor $A_[0][3], $E[3], $A[3][3], ROR #37                                      SEP      str vAgaq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAga_offset)]
eor $A_[3][3], $E[2], $A[3][2], ROR #8                                       SEP
eor $A_[3][2], $E[1], $A[2][1], ROR #56                                      SEP
eor $A_[1][1], $E[4], $A[1][4], ROR #44                                      SEP      xar_m1 vBbo, vAmo, E3, 43
eor $A_[1][4], $E[2], $A[4][2], ROR #62                                      SEP
eor $A_[4][2], $E[4], $A[2][4], ROR #58                                      SEP
eor $A_[2][4], $E[0], $A[4][0], ROR #25                                      SEP
eor $A_[3][0], $E[4], $A[0][4], ROR #20                                      SEP      xar_m1 vBmo, vAmi, E2, 49
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]
eor $A_[0][4], $E[4], $A[4][4], ROR #9                                       SEP
eor $A_[4][4], $E[1], $A[4][1], ROR #23                                      SEP
eor $A_[3][1], $E[0], $A[1][0], ROR #61                                      SEP      str vAgeq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAge_offset)]
eor $A_[0][1], $E[1], $A[1][1], ROR #19                                      SEP
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                                     SEP
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                                     SEP      xar_m1 vBmi, vAke, E1, 54
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                                      SEP
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                                     SEP
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                                      SEP      xar_m1 vBge, vAgu, E4, 44
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                                     SEP
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                                      SEP
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                                     SEP      bcax_m1 vAga, vBga, vBgi, vBge
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                                      SEP
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                                     SEP
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                                      SEP
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                                     SEP      eor vBba.16b, vAba.16b, E0.16b
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                                      SEP
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                                     SEP
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                                       SEP      xar_m1 vBsa, vAbi, E2, 2
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                                     SEP
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                                      SEP
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                                      SEP
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                                      SEP      xar_m1 vBbi, vAki, E2, 21
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                                     SEP
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                                      SEP
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                                      SEP      xar_m1 vBki, vAko, E3, 39
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                                      SEP
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                                     SEP
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                                      SEP
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                                     SEP      xar_m1 vBko, vAmu, E4, 56
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                                      SEP
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                                      SEP
                                                                             SEP      xar_m1 vBmu, vAso, E3, 8
                                                                             SEP
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                                      SEP
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                                     SEP
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                                      SEP      xar_m1 vBso, vAma, E0, 23
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                                      SEP
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                                      SEP
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                                     SEP      xar_m1 vBka, vAbe, E1, 63
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                                      SEP
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                                     SEP
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                                      SEP      xar_m1 vBse, vAgo, E3, 9
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                                     SEP
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                                      SEP
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                                     SEP
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                                      SEP      xar_m1 vBgo, vAme, E1, 19
str x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                 SEP
ldr $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
load_constant_ptr_stack
ldr $cur_const, [$const_addr, $count, UXTW #3]
add $count, $count, #1
str $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                                     SEP
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                                      SEP      bcax_m1 vAge, vBge, vBgo, vBgi
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                                     SEP
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                                      SEP
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                                     SEP
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                                      SEP      ldr vvtmpq, [sp, #(STACK_BASE_TMP_VREGS + 16 * vAgi_offset)]
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                                     SEP
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                                      SEP
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                                      SEP      xar_m1 vBke, vvtmp, E2, 58
eor $A[0][0], $A[0][0], $cur_const                                           SEP
eor $C[2], $A[4][2], $A[0][2], ROR #52                                       SEP
eor $C[0], $A[0][0], $A[1][0], ROR #61                                       SEP      xar_m1 vBgu, vAsi, E2, 3
eor $C[4], $A[2][4], $A[1][4], ROR #50                                       SEP
eor $C[1], $A[2][1], $A[3][1], ROR #57                                       SEP
eor $C[3], $A[0][3], $A[2][3], ROR #63                                       SEP      bcax_m1 vAgi, vBgi, vBgu, vBgo
eor $C[2], $C[2], $A[2][2], ROR #48                                          SEP
eor $C[0], $C[0], $A[3][0], ROR #54                                          SEP
eor $C[4], $C[4], $A[3][4], ROR #34                                          SEP
eor $C[1], $C[1], $A[0][1], ROR #51                                          SEP      xar_m1 vBsi, vAku, E4, 25
eor $C[3], $C[3], $A[3][3], ROR #37                                          SEP
eor $C[2], $C[2], $A[3][2], ROR #10                                          SEP
eor $C[0], $C[0], $A[2][0], ROR #39                                          SEP      xar_m1 vBku, vAsa, E0, 46
eor $C[4], $C[4], $A[0][4], ROR #26                                          SEP
eor $C[1], $C[1], $A[4][1], ROR #31                                          SEP
eor $C[3], $C[3], $A[1][3], ROR #36                                          SEP      xar_m1 vBma, vAbu, E4, 37
eor $C[2], $C[2], $A[1][2], ROR #5                                           SEP
str x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP
eor $C[0], $C[0], $A[4][0], ROR #25                                          SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                 SEP      xar_m1 vBbu, vAsu, E4, 50
eor $C[4], $C[4], $A[4][4], ROR #15                                          SEP
eor $C[1], $C[1], $A[1][1], ROR #27                                          SEP
eor $C[3], $C[3], $A[4][3], ROR #2                                           SEP      xar_m1 vBsu, vAse, E1, 62
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_C2_E3)]               SEP
eor $E[1], $C[0], $C[2], ROR #61                                             SEP
ror $C[2], $C[2], 62                                                         SEP
eor $E[3], $C[2], $C[4], ROR #57                                             SEP      ldp vvtmpq, E3q, [sp, #(STACK_BASE_TMP_VREGS + 16*vAga_offset)]
ror $C[4], $C[4], 58                                                         SEP
eor $E[0], $C[4], $C[1], ROR #55                                             SEP
ror $C[1], $C[1], 56                                     
eor $E[2], $C[1], $C[3], ROR #63                           
eor $E[4], $C[3], $C[0], ROR #63                             
eor $A_[0][0], $E[0], $A[0][0]                                               SEP      xar_m1 vBme, vvtmp, E0, 28
eor $A_[4][0], $E[2], $A[0][2], ROR #50                                      SEP
eor $A_[0][2], $E[2], $A[2][2], ROR #46                                      SEP
eor $A_[2][2], $E[3], $A[2][3], ROR #63                                      SEP
eor $A_[2][3], $E[4], $A[3][4], ROR #28                                      SEP      xar_m1 vBbe, E3,  E1, 20
eor $A_[3][4], $E[3], $A[4][3], ROR #2                                       SEP
eor $A_[4][3], $E[0], $A[3][0], ROR #54                                      SEP
eor $A_[2][0], $E[1], $A[0][1], ROR #43                                      SEP      bcax_m1 vAgo, vBgo, vBga, vBgu
eor $A_[4][1], $E[3], $A[1][3], ROR #36                                      SEP
eor $A_[1][3], $E[1], $A[3][1], ROR #49                                      SEP
eor $A_[2][1], $E[2], $A[1][2], ROR #3                                       SEP
eor $A_[1][2], $E[0], $A[2][0], ROR #39                                      SEP      bcax_m1 vAgu, vBgu, vBge, vBga
eor $A_[1][0], $E[3], $A[0][3]                                               SEP
eor $A_[0][3], $E[3], $A[3][3], ROR #37                                      SEP
eor $A_[3][3], $E[2], $A[3][2], ROR #8                                       SEP      bcax_m1 vAka, vBka, vBki, vBke
eor $A_[3][2], $E[1], $A[2][1], ROR #56                                      SEP
eor $A_[1][1], $E[4], $A[1][4], ROR #44                                      SEP
eor $A_[1][4], $E[2], $A[4][2], ROR #62                                      SEP      bcax_m1 vAke, vBke, vBko, vBki
eor $A_[4][2], $E[4], $A[2][4], ROR #58                                      SEP
eor $A_[2][4], $E[0], $A[4][0], ROR #25                                      SEP
eor $A_[3][0], $E[4], $A[0][4], ROR #20                                      SEP
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]
eor $A_[0][4], $E[4], $A[4][4], ROR #9                                       SEP      bcax_m1 vAki, vBki, vBku, vBko
eor $A_[4][4], $E[1], $A[4][1], ROR #23                                      SEP
eor $A_[3][1], $E[0], $A[1][0], ROR #61                                      SEP
eor $A_[0][1], $E[1], $A[1][1], ROR #19                                      SEP      bcax_m1 vAko, vBko, vBka, vBku
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                                     SEP
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                                     SEP
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                                      SEP      bcax_m1 vAku, vBku, vBke, vBka
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                                     SEP
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                                      SEP
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                                     SEP      bcax_m1 vAma, vBma, vBmi, vBme
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                                      SEP
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                                     SEP
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                                      SEP
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                                     SEP      bcax_m1 vAme, vBme, vBmo, vBmi
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                                      SEP
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                                     SEP
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                                      SEP      bcax_m1 vAmi, vBmi, vBmu, vBmo
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                                     SEP
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                                       SEP
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                                     SEP
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                                      SEP      bcax_m1 vAmo, vBmo, vBma, vBmu
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                                      SEP
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                                      SEP
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                                     SEP      bcax_m1 vAmu, vBmu, vBme, vBma
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                                      SEP
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                                      SEP
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                                      SEP      bcax_m1 vAsa, vBsa, vBsi, vBse
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                                     SEP
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                                      SEP
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                                     SEP
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                                      SEP      bcax_m1 vAse, vBse, vBso, vBsi
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                                      SEP
                                                                             SEP      bcax_m1 vAsi, vBsi, vBsu, vBso
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                                      SEP
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                                     SEP
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                                      SEP
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                                      SEP      bcax_m1 vAso, vBso, vBsa, vBsu
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                                      SEP
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                                     SEP
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                                      SEP      bcax_m1 vAsu, vBsu, vBse, vBsa
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                                     SEP
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                                      SEP
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                                     SEP
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                                      SEP      bcax_m1 vAba, vBba, vBbi, vBbe
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                                     SEP
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                                      SEP
str x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)]                 SEP      bcax_m1 vAbe, vBbe, vBbo, vBbi
ldr $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
load_constant_ptr_stack
ldr $cur_const, [$const_addr, $count, UXTW #3]
add $count, $count, #1
str $count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT)]
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                                     SEP
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                                      SEP
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                                     SEP
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                                      SEP      bcax_m1 vAbi, vBbi, vBbu, vBbo
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                                     SEP
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                                      SEP
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                                     SEP      bcax_m1 vAbo, vBbo, vBba, vBbu
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                                      SEP
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                                      SEP
eor $A[0][0], $A[0][0], $cur_const                                           SEP      bcax_m1 vAbu, vBbu, vBbe, vBba
ldr x27, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_x27_A44)] // load A[2][3]
ror $A[1][0], $A[1][0], #(64-3)                                              SEP
ror $A[0][4], $A[0][4], #(64-44)                                             SEP
ror $A[2][0], $A[2][0], #(64-25)                                             SEP
ror $A[2][1], $A[2][1], #(64-8)                                              SEP      ldr x26, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST_VEC)]
ror $A[3][0], $A[3][0], #(64-10)                                             SEP
ror $A[2][4], $A[2][4], #(64-6)                                              SEP
ror $A[4][0], $A[4][0], #(64-39)                                             SEP      ldr vvtmpq, [x26], #16
ror $A[4][1], $A[4][1], #(64-41)                                             SEP
ror $A[0][1], $A[0][1], #(64-21)                                             SEP
ror $A[1][1], $A[1][1], #(64-45)                                             SEP
ror $A[1][2], $A[1][2], #(64-61)                                             SEP      str x26, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST_VEC)]
ror $A[3][1], $A[3][1], #(64-15)                                             SEP
ror $A[3][2], $A[3][2], #(64-56)                                             SEP
ror $A[0][2], $A[0][2], #(64-14)                                             SEP      eor vAba.16b, vAba.16b, vvtmp.16b
ror $A[2][2], $A[2][2], #(64-18)                                             SEP
ror $A[2][3], $A[2][3], #(64-1)                                              SEP
ror $A[4][2], $A[4][2], #(64-2)                                              SEP
ror $A[4][3], $A[4][3], #(64-62)                                             SEP      .unreq vvtmp
ror $A[1][3], $A[1][3], #(64-28)                                             SEP
ror $A[1][4], $A[1][4], #(64-20)                                             SEP
ror $A[3][3], $A[3][3], #(64-27)                                             SEP      .unreq vvtmpq
ror $A[3][4], $A[3][4], #(64-36)                                             SEP
ror $A[4][4], $A[4][4], #(64-55)                                             SEP
.endm


#define KECCAK_F1600_ROUNDS 24

.global keccak_f1600_x4_hybrid_asm_v5p_opt
.global _keccak_f1600_x4_hybrid_asm_v5p_opt
.text
.align 4

keccak_f1600_x4_hybrid_asm_v5p_opt:
_keccak_f1600_x4_hybrid_asm_v5p_opt:
    alloc_stack
    save_gprs
    save_vregs
    str  $input_addr, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_INPUT)]

    adr $const_addr, round_constants_vec
    str $const_addr, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CONST_VEC)]

    load_input_vector

    add  $input_addr,  $input_addr, #16

    mov $out_count, #0
outer_loop:
    str $out_count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT_OUT)]

    load_input_scalar
    str  $input_addr, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CUR_INPUT)]

    hybrid_round_initial
1:
    hybrid_round_noninitial
    cmp $count, #(KECCAK_F1600_ROUNDS-3)
    blt 1b
    hybrid_round_final


    ldr  $input_addr, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_CUR_INPUT)]
    store_input_scalar
    add  $input_addr,  $input_addr, #8

    ldr $out_count, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_COUNT_OUT)]
    add $out_count, $out_count, #1
    cmp $out_count, #2
    blt outer_loop

    ldr  $input_addr, [sp, #(STACK_BASE_TMP_GPRS + STACK_OFFSET_INPUT)]
    store_input_vector

    restore_vregs
    restore_gprs
    free_stack
    ret
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