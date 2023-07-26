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

#define SEP ;
#define KECCAK_F1600_ROUNDS 24

.align(8)
.type	round_constants, %object
round_constants:
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
.size	round_constants, .-round_constants
___

 # Alias symbol vA (the bit-state matrix) with vector registers
$vA[0][4] = "v4"; $vA[1][4] = "v9"; $vA[2][4] = "v14"; $vA[3][4] = "v19"; $vA[4][4] = "v24"; 
$vA[0][3] = "v3"; $vA[1][3] = "v8"; $vA[2][3] = "v13"; $vA[3][3] = "v18"; $vA[4][3] = "v23";
$vA[0][2] = "v2"; $vA[1][2] = "v7"; $vA[2][2] = "v12"; $vA[3][2] = "v17"; $vA[4][2] = "v22";
$vA[0][1] = "v1"; $vA[1][1] = "v6"; $vA[2][1] = "v11"; $vA[3][1] = "v16"; $vA[4][1] = "v21";
$vA[0][0] = "v0"; $vA[1][0] = "v5"; $vA[2][0] = "v10"; $vA[3][0] = "v15"; $vA[4][0] = "v20";

 # Alias symbol vA_ (the permuted bit-state matrix) with vector registers
 # vA_[y, 2*x+3*y] = rot(vA[x, y])
$vA_[0][4] = "v4";  $vA_[1][4] = "v9";  $vA_[2][4] = "v14"; $vA_[3][4] = "v19"; $vA_[4][4] = "v24";
$vA_[0][3] = "v3";  $vA_[1][3] = "v8";  $vA_[2][3] = "v13"; $vA_[3][3] = "v18"; $vA_[4][3] = "v23";
$vA_[0][2] = "v2";  $vA_[1][2] = "v7";  $vA_[2][2] = "v12"; $vA_[3][2] = "v17"; $vA_[4][2] = "v22";
$vA_[0][1] = "v26"; $vA_[1][1] = "v11"; $vA_[2][1] = "v16"; $vA_[3][1] = "v21"; $vA_[4][1] = "v1";
$vA_[0][0] = "v25"; $vA_[1][0] = "v10"; $vA_[2][0] = "v15"; $vA_[3][0] = "v20"; $vA_[4][0] = "v0";  

 # Alias symbol vC and vE with vector registers
 # vC[x] = vA[x, 0] xor vA[x, 1] xor vA[x, 2] xor vA[x, 3] xor A[x, 4],   for x in 0..4
 # vE[x] = vC[x-1] xor rot(vC[x+1], 1), for x in 0..4
my @vC = map("v$_", (27, 28, 29, 30, 31));
my @vE = map("v$_", (31, 27, 26, 29, 30));

 # Alias symbol vAq (the bit-state matrix) with vector registers
$vAq[0][4] = "q4"; $vAq[1][4] = "q9"; $vAq[2][4] = "q14"; $vAq[3][4] = "q19"; $vAq[4][4] = "q24";
$vAq[0][3] = "q3"; $vAq[1][3] = "q8"; $vAq[2][3] = "q13"; $vAq[3][3] = "q18"; $vAq[4][3] = "q23";
$vAq[0][2] = "q2"; $vAq[1][2] = "q7"; $vAq[2][2] = "q12"; $vAq[3][2] = "q17"; $vAq[4][2] = "q22";
$vAq[0][1] = "q1"; $vAq[1][1] = "q6"; $vAq[2][1] = "q11"; $vAq[3][1] = "q16"; $vAq[4][1] = "q21";
$vAq[0][0] = "q0"; $vAq[1][0] = "q5"; $vAq[2][0] = "q10"; $vAq[3][0] = "q15"; $vAq[4][0] = "q20";
    
 # Alias symbol vAq_ (the permuted bit-state matrix) with vector registers
 # vAq_[y, 2*x+3*y] = rot(vAq[x, y])
$vAq_[0][4] = "q4";  $vAq_[1][4] = "q9";  $vAq_[2][4] = "q14"; $vAq_[3][4] = "q19"; $vAq_[4][4] = "q24";
$vAq_[0][3] = "q3";  $vAq_[1][3] = "q8";  $vAq_[2][3] = "q13"; $vAq_[3][3] = "q18"; $vAq_[4][3] = "q23";
$vAq_[0][2] = "q2";  $vAq_[1][2] = "q7";  $vAq_[2][2] = "q12"; $vAq_[3][2] = "q17"; $vAq_[4][2] = "q22";
$vAq_[0][1] = "q26"; $vAq_[1][1] = "q11"; $vAq_[2][1] = "q16"; $vAq_[3][1] = "q21"; $vAq_[4][1] = "q1";
$vAq_[0][0] = "q25"; $vAq_[1][0] = "q10"; $vAq_[2][0] = "q15"; $vAq_[3][0] = "q20"; $vAq_[4][0] = "q0";

 # Alias symbol vCq and vEq with vector registers
 # vCq[x] = vAq[x, 0] xor vAq[x, 1] xor vAq[x, 2] xor vAq[x, 3] xor vAq[x, 4],   for x in 0..4
 # vEq[x] = vCq[x-1] xor rot(vCq[x+1], 1), for x in 0..4
my @vCq = map("q$_", (27, 28, 29, 30, 31));
my @vEq = map("q$_", (31, 27, 26, 29, 30));

$input_addr  = "x0";
$const_addr  = "x1";
$count       = "x2";
$cur_const   = "x3";

$code.=<<___;

/****************** STACK ALLOCATIONS *******************/
#define STACK_SIZE (16*4 + 16*34)
#define STACK_BASE_VREGS 0
#define STACK_BASE_TMP   16*4
#define vAq_offset 0

/****************** MEMORY ACCESSING MACROS *******************/
.macro load_input
    ldp $vAq[0][0], $vAq[0][1], [$input_addr, #(2*8*0)]
    ldp $vAq[0][2], $vAq[0][3], [$input_addr, #(2*8*2)]
    ldp $vAq[0][4], $vAq[1][0], [$input_addr, #(2*8*4)]
    ldp $vAq[1][1], $vAq[1][2], [$input_addr, #(2*8*6)]
    ldp $vAq[1][3], $vAq[1][4], [$input_addr, #(2*8*8)]
    ldp $vAq[2][0], $vAq[2][1], [$input_addr, #(2*8*10)]
    ldp $vAq[2][2], $vAq[2][3], [$input_addr, #(2*8*12)]
    ldp $vAq[2][4], $vAq[3][0], [$input_addr, #(2*8*14)]
    ldp $vAq[3][1], $vAq[3][2], [$input_addr, #(2*8*16)]
    ldp $vAq[3][3], $vAq[3][4], [$input_addr, #(2*8*18)]
    ldp $vAq[4][0], $vAq[4][1], [$input_addr, #(2*8*20)]
    ldp $vAq[4][2], $vAq[4][3], [$input_addr, #(2*8*22)]
    ldr $vAq[4][4], [$input_addr, #(2*8*24)]
.endm

.macro store_input
    str $vAq[0][0], [$input_addr, #(2*8*0)]
    str $vAq[0][1], [$input_addr, #(2*8*1)]
    str $vAq[0][2], [$input_addr, #(2*8*2)]
    str $vAq[0][3], [$input_addr, #(2*8*3)]
    str $vAq[0][4], [$input_addr, #(2*8*4)]
    str $vAq[1][0], [$input_addr, #(2*8*5)]
    str $vAq[1][1], [$input_addr, #(2*8*6)]
    str $vAq[1][2], [$input_addr, #(2*8*7)]
    str $vAq[1][3], [$input_addr, #(2*8*8)]
    str $vAq[1][4], [$input_addr, #(2*8*9)]
    str $vAq[2][0], [$input_addr, #(2*8*10)]
    str $vAq[2][1], [$input_addr, #(2*8*11)]
    str $vAq[2][2], [$input_addr, #(2*8*12)]
    str $vAq[2][3], [$input_addr, #(2*8*13)]
    str $vAq[2][4], [$input_addr, #(2*8*14)]
    str $vAq[3][0], [$input_addr, #(2*8*15)]
    str $vAq[3][1], [$input_addr, #(2*8*16)]
    str $vAq[3][2], [$input_addr, #(2*8*17)]
    str $vAq[3][3], [$input_addr, #(2*8*18)]
    str $vAq[3][4], [$input_addr, #(2*8*19)]
    str $vAq[4][0], [$input_addr, #(2*8*20)]
    str $vAq[4][1], [$input_addr, #(2*8*21)]
    str $vAq[4][2], [$input_addr, #(2*8*22)]
    str $vAq[4][3], [$input_addr, #(2*8*23)]
    str $vAq[4][4], [$input_addr, #(2*8*24)]
.endm

.macro save_vregs
    stp  d8,  d9, [sp, #(STACK_BASE_VREGS + 16*0)]
    stp d10, d11, [sp, #(STACK_BASE_VREGS + 16*1)]
    stp d12, d13, [sp, #(STACK_BASE_VREGS + 16*2)]
    stp d14, d15, [sp, #(STACK_BASE_VREGS + 16*3)]
.endm

.macro restore_vregs
    ldp  d8,  d9, [sp, #(STACK_BASE_VREGS + 16*0)]
    ldp d10, d11, [sp, #(STACK_BASE_VREGS + 16*1)]
    ldp d12, d13, [sp, #(STACK_BASE_VREGS + 16*2)]
    ldp d14, d15, [sp, #(STACK_BASE_VREGS + 16*3)]
.endm

.macro alloc_stack
   sub sp, sp, #(STACK_SIZE)
.endm

.macro free_stack
    add sp, sp, #(STACK_SIZE)
.endm

.macro load_constant_ptr
	adr $const_addr, round_constants
.endm

/****************** SHA3 Feat_SHA3 MACROS *******************/
.macro eor3_m0 d s0 s1 s2
    eor3 \\d\\().16b, \\s0\\().16b, \\s1\\().16b, \\s2\\().16b
.endm

.macro rax1_m0 d s0 s1
    rax1 \\d\\().2d, \\s0\\().2d, \\s1\\().2d
.endm

.macro xar_m0 d s0 s1 imm
    xar \\d\\().2d, \\s0\\().2d, \\s1\\().2d, #\\imm
.endm

.macro bcax_m0 d s0 s1 s2
    bcax \\d\\().16b, \\s0\\().16b, \\s1\\().16b, \\s2\\().16b
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
    eor3_m1_0 \\d, \\s0, \\s1, \\s2
    eor3_m1_1 \\d, \\s0, \\s1, \\s2
.endm

.macro rax1_m1 d s0 s1
   // Use add instead of SHL #1
   add tmp.2d, \\s1\\().2d, \\s1\\().2d
   sri tmp.2d, \\s1\\().2d, #63
   eor \\d\\().16b, tmp.16b, \\s0\\().16b
.endm

 .macro xar_m1 d s0 s1 imm
   // Special cases where we can replace SHLs by ADDs
   .if \\imm == 63
     eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
     add \\d\\().2d, \\s0\\().2d, \\s0\\().2d
     sri \\d\\().2d, \\s0\\().2d, #(63)
   .else
     eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
     shl \\d\\().2d, \\s0\\().2d, #(64-\\imm)
     sri \\d\\().2d, \\s0\\().2d, #(\\imm)
   .endif
.endm

.macro bcax_m1 d s0 s1 s2
    bic tmp.16b, \\s1\\().16b, \\s2\\().16b
    eor \\d\\().16b, tmp.16b, \\s0\\().16b
.endm

.macro keccak_f1600_round_pre
    eor3_m0 $vC[1], $vA[0][1], $vA[1][1], $vA[2][1]
    eor3_m1 $vC[3], $vA[0][3], $vA[1][3], $vA[2][3]
    eor3_m0 $vC[0], $vA[0][0], $vA[1][0], $vA[2][0]
    eor3_m1 $vC[2], $vA[0][2], $vA[1][2], $vA[2][2]
    eor3_m0 $vC[4], $vA[0][4], $vA[1][4], $vA[2][4]
    eor3_m1 $vC[1], $vC[1], $vA[3][1],  $vA[4][1]
    eor3_m0 $vC[3], $vC[3], $vA[3][3],  $vA[4][3]
    eor3_m1 $vC[0], $vC[0], $vA[3][0],  $vA[4][0]
    eor3_m0 $vC[2], $vC[2], $vA[3][2],  $vA[4][2]
    eor3_m1 $vC[4], $vC[4], $vA[3][4],  $vA[4][4]
.endm

.macro keccak_f1600_round
    eor3_m1_0 $vC[0], $vA[0][0], $vA[1][0], $vA[2][0]
    eor3_m1_0 $vC[1], $vA[0][1], $vA[1][1], $vA[2][1]
    eor3_m1_0 $vC[2], $vA[0][2], $vA[1][2], $vA[2][2]
    eor3_m1_0 $vC[3], $vA[0][3], $vA[1][3], $vA[2][3]
    eor3_m1_0 $vC[4], $vA[0][4], $vA[1][4], $vA[2][4]
    eor3_m1_1 $vC[0], $vA[0][0], $vA[1][0], $vA[2][0]
    eor3_m1_1 $vC[1], $vA[0][1], $vA[1][1], $vA[2][1]
    eor3_m1_1 $vC[2], $vA[0][2], $vA[1][2], $vA[2][2]
    eor3_m1_1 $vC[3], $vA[0][3], $vA[1][3], $vA[2][3]
    eor3_m1_1 $vC[4], $vA[0][4], $vA[1][4], $vA[2][4]
    eor3_m1_0 $vC[0], $vC[0], $vA[3][0],  $vA[4][0]
    eor3_m1_0 $vC[1], $vC[1], $vA[3][1],  $vA[4][1]
    eor3_m1_0 $vC[2], $vC[2], $vA[3][2],  $vA[4][2]
    eor3_m1_0 $vC[3], $vC[3], $vA[3][3],  $vA[4][3]
    eor3_m1_0 $vC[4], $vC[4], $vA[3][4],  $vA[4][4]
    eor3_m1_1 $vC[0], $vC[0], $vA[3][0],  $vA[4][0]
    eor3_m1_1 $vC[1], $vC[1], $vA[3][1],  $vA[4][1]
    eor3_m1_1 $vC[2], $vC[2], $vA[3][2],  $vA[4][2]
    eor3_m1_1 $vC[3], $vC[3], $vA[3][3],  $vA[4][3]
    eor3_m1_1 $vC[4], $vC[4], $vA[3][4],  $vA[4][4]

    tmp .req $vA_[0][0]
    rax1_m1 $vE[2], $vC[1], $vC[3]
    rax1_m1 $vE[4], $vC[3], $vC[0]
    rax1_m1 $vE[1], $vC[0], $vC[2]
    rax1_m1 $vE[3], $vC[2], $vC[4]
    rax1_m1 $vE[0], $vC[4], $vC[1]
    .unreq tmp

    tmp  .req $vC[1]
    tmpq .req $vCq[1]

    eor $vA_[0][0].16b, $vA[0][0].16b, $vE[0].16b
    xar_m1 $vA_[4][0], $vA[0][2], $vE[2], 2
    xar_m1 $vA_[0][2], $vA[2][2], $vE[2], 21
    xar_m1 $vA_[2][2], $vA[2][3], $vE[3], 39
    xar_m1 $vA_[2][3], $vA[3][4], $vE[4], 56
    xar_m1 $vA_[3][4], $vA[4][3], $vE[3], 8
    xar_m1 $vA_[4][3], $vA[3][0], $vE[0], 23
    xar_m1 $vA_[2][0], $vA[0][1], $vE[1], 63
    xar_m1 $vA_[4][1], $vA[1][3], $vE[3], 9
    xar_m1 $vA_[1][3], $vA[3][1], $vE[1], 19
    xar_m1 $vA_[2][1], $vA[1][2], $vE[2], 58
    xar_m1 $vA_[1][2], $vA[2][0], $vE[0], 61
    xar_m1 $vA_[1][0], $vA[0][3], $vE[3], 36
    xar_m1 $vA_[0][3], $vA[3][3], $vE[3], 43
    xar_m1 $vA_[3][3], $vA[3][2], $vE[2], 49
    xar_m1 $vA_[3][2], $vA[2][1], $vE[1], 54
    xar_m1 $vA_[1][1], $vA[1][4], $vE[4], 44
    xar_m1 $vA_[1][4], $vA[4][2], $vE[2], 3
    xar_m1 $vA_[4][2], $vA[2][4], $vE[4], 25
    xar_m1 $vA_[2][4], $vA[4][0], $vE[0], 46
    xar_m1 $vA_[3][0], $vA[0][4], $vE[4], 37
    xar_m1 $vA_[0][4], $vA[4][4], $vE[4], 50
    xar_m1 $vA_[4][4], $vA[4][1], $vE[1], 62
    xar_m1 $vA_[3][1], $vA[1][0], $vE[0], 28
    xar_m1 $vA_[0][1], $vA[1][1], $vE[1], 20

    bcax_m1 $vA[1][0], $vA_[1][0], $vA_[1][2], $vA_[1][1]
    bcax_m1 $vA[1][1], $vA_[1][1], $vA_[1][3], $vA_[1][2]
    bcax_m1 $vA[1][2], $vA_[1][2], $vA_[1][4], $vA_[1][3]
    bcax_m1 $vA[1][3], $vA_[1][3], $vA_[1][0], $vA_[1][4]
    bcax_m1 $vA[1][4], $vA_[1][4], $vA_[1][1], $vA_[1][0]
    bcax_m1 $vA[2][0], $vA_[2][0], $vA_[2][2], $vA_[2][1]
    bcax_m1 $vA[2][1], $vA_[2][1], $vA_[2][3], $vA_[2][2]
    bcax_m1 $vA[2][2], $vA_[2][2], $vA_[2][4], $vA_[2][3]
    bcax_m1 $vA[2][3], $vA_[2][3], $vA_[2][0], $vA_[2][4]
    bcax_m1 $vA[2][4], $vA_[2][4], $vA_[2][1], $vA_[2][0]
    bcax_m1 $vA[3][0], $vA_[3][0], $vA_[3][2], $vA_[3][1]
    bcax_m1 $vA[3][1], $vA_[3][1], $vA_[3][3], $vA_[3][2]
    bcax_m1 $vA[3][2], $vA_[3][2], $vA_[3][4], $vA_[3][3]
    bcax_m1 $vA[3][3], $vA_[3][3], $vA_[3][0], $vA_[3][4]
    bcax_m1 $vA[3][4], $vA_[3][4], $vA_[3][1], $vA_[3][0]
    bcax_m1 $vA[4][0], $vA_[4][0], $vA_[4][2], $vA_[4][1]
    bcax_m1 $vA[4][1], $vA_[4][1], $vA_[4][3], $vA_[4][2]
    bcax_m1 $vA[4][2], $vA_[4][2], $vA_[4][4], $vA_[4][3]
    bcax_m1 $vA[4][3], $vA_[4][3], $vA_[4][0], $vA_[4][4]
    bcax_m1 $vA[4][4], $vA_[4][4], $vA_[4][1], $vA_[4][0]
    bcax_m1 $vA[0][0], $vA_[0][0], $vA_[0][2], $vA_[0][1]
    bcax_m1 $vA[0][1], $vA_[0][1], $vA_[0][3], $vA_[0][2]
    bcax_m1 $vA[0][2], $vA_[0][2], $vA_[0][4], $vA_[0][3]
    bcax_m1 $vA[0][3], $vA_[0][3], $vA_[0][0], $vA_[0][4]
    bcax_m1 $vA[0][4], $vA_[0][4], $vA_[0][1], $vA_[0][0]

    ldr tmpq, [$const_addr], #16
    eor $vA[0][0].16b, $vA[0][0].16b, tmp.16b

    .unreq tmp
    .unreq tmpq
.endm

.macro keccak_f1600_round_core
    tmp .req $vA_[0][0]
    rax1_m0 $vE[2], $vC[1], $vC[3]
    rax1_m1 $vE[4], $vC[3], $vC[0]
    rax1_m0 $vE[1], $vC[0], $vC[2]
    rax1_m1 $vE[3], $vC[2], $vC[4]
    rax1_m0 $vE[0], $vC[4], $vC[1]

    .unreq tmp
    tmp .req $vC[1]
    tmpq .req $vCq[1]

    eor $vA_[0][0].16b, $vA[0][0].16b, $vE[0].16b
    xar_m1 $vA_[4][0], $vA[0][2], $vE[2], 2
    xar_m0 $vA_[0][2], $vA[2][2], $vE[2], #21
    xar_m1 $vA_[2][2], $vA[2][3], $vE[3], 39
    xar_m0 $vA_[2][3], $vA[3][4], $vE[4], #56
    xar_m1 $vA_[3][4], $vA[4][3], $vE[3], 8
    xar_m0 $vA_[4][3], $vA[3][0], $vE[0], #23
    xar_m1 $vA_[2][0], $vA[0][1], $vE[1], 63
    xar_m0 $vA_[4][1], $vA[1][3], $vE[3], #9
    xar_m1 $vA_[1][3], $vA[3][1], $vE[1], 19
    xar_m0 $vA_[2][1], $vA[1][2], $vE[2], #58
    xar_m1 $vA_[1][2], $vA[2][0], $vE[0], 61
    xar_m0 $vA_[1][0], $vA[0][3], $vE[3], #36
    xar_m1 $vA_[0][3], $vA[3][3], $vE[3], 43
    xar_m0 $vA_[3][3], $vA[3][2], $vE[2], #49
    xar_m1 $vA_[3][2], $vA[2][1], $vE[1], 54
    xar_m0 $vA_[1][1], $vA[1][4], $vE[4], #44
    mov $vE[3].16b, $vA[1][0].16b
    bcax_m1 $vA[1][0], $vA_[1][0], $vA_[1][2], $vA_[1][1]
    xar_m0 $vA_[1][4], $vA[4][2], $vE[2], #3
    xar_m1 $vA_[4][2], $vA[2][4], $vE[4], 25
    xar_m0 $vA_[2][4], $vA[4][0], $vE[0], #46
    xar_m1 $vA_[3][0], $vA[0][4], $vE[4], 37
    xar_m0 $vA_[0][4], $vA[4][4], $vE[4], #50
    xar_m1 $vA_[4][4], $vA[4][1], $vE[1], 62
    xar_m0 $vA_[3][1], $vE[3], $vE[0], #28
    xar_m1 $vA_[0][1], $vA[1][1], $vE[1], 20

    bcax_m1 $vA[1][1], $vA_[1][1], $vA_[1][3], $vA_[1][2]
    bcax_m0 $vA[1][2], $vA_[1][2], $vA_[1][4], $vA_[1][3]
    bcax_m1 $vA[1][3], $vA_[1][3], $vA_[1][0], $vA_[1][4]
    bcax_m0 $vA[1][4], $vA_[1][4], $vA_[1][1], $vA_[1][0]
    bcax_m1 $vA[2][0], $vA_[2][0], $vA_[2][2], $vA_[2][1]
    bcax_m0 $vA[2][1], $vA_[2][1], $vA_[2][3], $vA_[2][2]

    .unreq tmp
    .unreq tmpq

    eor2    $vC[0],  $vA[2][0], $vA[1][0]
    str $vAq[1][0], [sp, #(STACK_BASE_TMP + 16 * vAq_offset)]

    tmp .req $vA[1][0]
    tmpq .req $vAq[1][0]
    bcax_m0 $vA[2][2], $vA_[2][2], $vA_[2][4], $vA_[2][3]
    bcax_m1 $vA[2][3], $vA_[2][3], $vA_[2][0], $vA_[2][4]
    eor2    $vC[1],  $vA[2][1], $vA[1][1]
    bcax_m0 $vA[2][4], $vA_[2][4], $vA_[2][1], $vA_[2][0]
    eor2    $vC[2],  $vA[2][2], $vA[1][2]
    bcax_m1 $vA[3][0], $vA_[3][0], $vA_[3][2], $vA_[3][1]
    eor2    $vC[3],  $vA[2][3], $vA[1][3]
    bcax_m0 $vA[3][1], $vA_[3][1], $vA_[3][3], $vA_[3][2]
    eor2    $vC[4],  $vA[2][4], $vA[1][4]
    bcax_m1 $vA[3][2], $vA_[3][2], $vA_[3][4], $vA_[3][3]
    eor2    $vC[0],  $vC[0],  $vA[3][0]
    bcax_m0 $vA[3][3], $vA_[3][3], $vA_[3][0], $vA_[3][4]
    eor2    $vC[1],  $vC[1],  $vA[3][1]
    bcax_m1 $vA[3][4], $vA_[3][4], $vA_[3][1], $vA_[3][0]
    eor2    $vC[2],  $vC[2],  $vA[3][2]
    bcax_m0 $vA[4][0], $vA_[4][0], $vA_[4][2], $vA_[4][1]
    eor2    $vC[3],  $vC[3],  $vA[3][3]
    bcax_m1 $vA[4][1], $vA_[4][1], $vA_[4][3], $vA_[4][2]
    eor2    $vC[4],  $vC[4],  $vA[3][4]
    bcax_m0 $vA[4][2], $vA_[4][2], $vA_[4][4], $vA_[4][3]
    eor2    $vC[0],  $vC[0],  $vA[4][0]
    bcax_m1 $vA[4][3], $vA_[4][3], $vA_[4][0], $vA_[4][4]
    eor2    $vC[1],  $vC[1],  $vA[4][1]
    bcax_m0 $vA[4][4], $vA_[4][4], $vA_[4][1], $vA_[4][0]
    eor2    $vC[2],  $vC[2],  $vA[4][2]
    eor2    $vC[3],  $vC[3],  $vA[4][3]
    bcax_m1 $vA[0][0], $vA_[0][0], $vA_[0][2], $vA_[0][1]
    bcax_m0 $vA[0][1], $vA_[0][1], $vA_[0][3], $vA_[0][2]
    eor2    $vC[1],  $vC[1],  $vA[0][1]

    ldr tmpq, [$const_addr], #16
    eor $vA[0][0].16b, $vA[0][0].16b, tmp.16b
    eor2    $vC[4],  $vC[4],  $vA[4][4]
    bcax_m0 $vA[0][2], $vA_[0][2], $vA_[0][4], $vA_[0][3]
    bcax_m1 $vA[0][3], $vA_[0][3], $vA_[0][0], $vA_[0][4]
    eor2    $vC[3],  $vC[3],  $vA[0][3]
    eor2    $vC[2],  $vC[2],  $vA[0][2]
    eor2    $vC[0],  $vC[0],  $vA[0][0]
    bcax_m0 $vA[0][4], $vA_[0][4], $vA_[0][1], $vA_[0][0]
    eor2    $vC[4],  $vC[4],  $vA[0][4]

    ldr $vAq[1][0], [sp, #(STACK_BASE_TMP + 16 * vAq_offset)]
    .unreq tmp
    .unreq tmpq
.endm

.macro keccak_f1600_round_post
    tmp .req $vA_[0][0]
    rax1_m0 $vE[2], $vC[1], $vC[3]
    rax1_m1 $vE[4], $vC[3], $vC[0]
    rax1_m0 $vE[1], $vC[0], $vC[2]
    rax1_m1 $vE[3], $vC[2], $vC[4]
    rax1_m0 $vE[0], $vC[4], $vC[1]

    .unreq tmp
    tmp .req $vC[1]
    tmpq .req $vCq[1]

    eor $vA_[0][0].16b, $vA[0][0].16b, $vE[0].16b
    xar_m0 $vA_[4][0], $vA[0][2], $vE[2], #2
    xar_m1 $vA_[0][2], $vA[2][2], $vE[2], 21
    xar_m0 $vA_[2][2], $vA[2][3], $vE[3], #39
    xar_m1 $vA_[2][3], $vA[3][4], $vE[4], 56
    xar_m0 $vA_[3][4], $vA[4][3], $vE[3], #8
    xar_m1 $vA_[4][3], $vA[3][0], $vE[0], 23
    xar_m0 $vA_[2][0], $vA[0][1], $vE[1], #63
    xar_m1 $vA_[4][1], $vA[1][3], $vE[3], 9
    xar_m0 $vA_[1][3], $vA[3][1], $vE[1], #19
    xar_m1 $vA_[2][1], $vA[1][2], $vE[2], 58
    xar_m0 $vA_[1][2], $vA[2][0], $vE[0], #61
    xar_m1 $vA_[1][0], $vA[0][3], $vE[3], 36
    xar_m0 $vA_[0][3], $vA[3][3], $vE[3], #43
    xar_m1 $vA_[3][3], $vA[3][2], $vE[2], 49
    xar_m0 $vA_[3][2], $vA[2][1], $vE[1], #54
    xar_m1 $vA_[1][1], $vA[1][4], $vE[4], 44
    mov $vE[3].16b, $vA[1][0].16b
    bcax_m1 $vA[1][0], $vA_[1][0], $vA_[1][2], $vA_[1][1]
    xar_m0 $vA_[1][4], $vA[4][2], $vE[2], #3
    xar_m1 $vA_[4][2], $vA[2][4], $vE[4], 25
    xar_m0 $vA_[2][4], $vA[4][0], $vE[0], #46
    xar_m1 $vA_[3][0], $vA[0][4], $vE[4], 37
    xar_m0 $vA_[0][4], $vA[4][4], $vE[4], #50
    xar_m1 $vA_[4][4], $vA[4][1], $vE[1], 62
    xar_m0 $vA_[3][1], $vE[3], $vE[0], #28
    xar_m1 $vA_[0][1], $vA[1][1], $vE[1], 20

    bcax_m0 $vA[1][1], $vA_[1][1], $vA_[1][3], $vA_[1][2]
    bcax_m1 $vA[1][2], $vA_[1][2], $vA_[1][4], $vA_[1][3]
    bcax_m0 $vA[1][3], $vA_[1][3], $vA_[1][0], $vA_[1][4]
    bcax_m1 $vA[1][4], $vA_[1][4], $vA_[1][1], $vA_[1][0]
    bcax_m0 $vA[2][0], $vA_[2][0], $vA_[2][2], $vA_[2][1]
    bcax_m1 $vA[2][1], $vA_[2][1], $vA_[2][3], $vA_[2][2]
    bcax_m0 $vA[2][2], $vA_[2][2], $vA_[2][4], $vA_[2][3]
    bcax_m1 $vA[2][3], $vA_[2][3], $vA_[2][0], $vA_[2][4]
    bcax_m0 $vA[2][4], $vA_[2][4], $vA_[2][1], $vA_[2][0]
    bcax_m1 $vA[3][0], $vA_[3][0], $vA_[3][2], $vA_[3][1]
    bcax_m0 $vA[3][1], $vA_[3][1], $vA_[3][3], $vA_[3][2]
    bcax_m1 $vA[3][2], $vA_[3][2], $vA_[3][4], $vA_[3][3]
    bcax_m0 $vA[3][3], $vA_[3][3], $vA_[3][0], $vA_[3][4]
    bcax_m1 $vA[3][4], $vA_[3][4], $vA_[3][1], $vA_[3][0]
    bcax_m0 $vA[4][0], $vA_[4][0], $vA_[4][2], $vA_[4][1]
    bcax_m1 $vA[4][1], $vA_[4][1], $vA_[4][3], $vA_[4][2]
    bcax_m0 $vA[4][2], $vA_[4][2], $vA_[4][4], $vA_[4][3]
    bcax_m1 $vA[4][3], $vA_[4][3], $vA_[4][0], $vA_[4][4]
    bcax_m0 $vA[4][4], $vA_[4][4], $vA_[4][1], $vA_[4][0]
    bcax_m1 $vA[0][0], $vA_[0][0], $vA_[0][2], $vA_[0][1]
    bcax_m0 $vA[0][1], $vA_[0][1], $vA_[0][3], $vA_[0][2]
    bcax_m1 $vA[0][2], $vA_[0][2], $vA_[0][4], $vA_[0][3]
    bcax_m0 $vA[0][3], $vA_[0][3], $vA_[0][0], $vA_[0][4]
    bcax_m1 $vA[0][4], $vA_[0][4], $vA_[0][1], $vA_[0][0]

    ldr tmpq, [$const_addr], #16
    eor $vA[0][0].16b, $vA[0][0].16b, tmp.16b

    .unreq tmp
    .unreq tmpq
.endm

.text
.align 4
.global keccak_f1600_x2_v84a
.global _keccak_f1600_x2_v84a
keccak_f1600_x2_v84a:
_keccak_f1600_x2_v84a:
    alloc_stack
    save_vregs
    load_constant_ptr
    load_input

    mov $count, #11
    keccak_f1600_round_pre
loop:
    keccak_f1600_round_core
    keccak_f1600_round_core
    sub $count, $count, #1
    cbnz $count, loop

    keccak_f1600_round_core
    keccak_f1600_round_post
    store_input
    restore_vregs
    free_stack
    ret
___
										
$code.=<<___;
.asciz	"Keccak-1600 absorb and squeeze for ARMv8, CRYPTOGAMS by <appro\@openssl.org>"
___
{
    my  %opcode = (
    "rax1_m0"    => 0xce608c00,    "eor3_m0"    => 0xce000000,
    "bcax_m0"    => 0xce200000,    "xar_m0"     => 0xce800000);

    sub unsha3 {
         my ($mnemonic,$arg)=@_;

         $arg =~ m/[qv]([0-9]+)[^,]*,\s*[qv]([0-9]+)[^,]*(?:,\s*[qv]([0-9]+)[^,]*(?:,\s*[qv#]([0-9\-]+))?)?/
         &&
         sprintf ".inst\t0x%08x\t//%s %s",
            $opcode{$mnemonic}|$1|($2<<5)|($3<<16)|(eval($4)<<10),
            $mnemonic,$arg;
    }

    sub unvmov {
        my $arg=shift;

        $arg =~ m/q([0-9]+)#(lo|hi),\s*q([0-9]+)#(lo|hi)/o &&
        sprintf "ins    v%d.d[%d],v%d.d[%d]",$1<8?$1:$1+8,($2 eq "lo")?0:1,
                             $3<8?$3:$3+8,($4 eq "lo")?0:1;
    }

     foreach(split("\n",$code)) {
        s/@\s/\/\//o;               # old->new style commentary
        s/\`([^\`]*)\`/eval($1)/ge;

        m/\bld1r\b/ and s/\.16b/.2d/g    or
        s/\b(eor3_m0|xar_m0|rax1_m0|bcax_m0)\s+(v.*)/unsha3($1,$2)/ge;
        print $_,"\n";
     }
}
close STDOUT or die "error closing STDOUT: $!";