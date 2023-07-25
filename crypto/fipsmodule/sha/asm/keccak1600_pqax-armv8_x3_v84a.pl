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
# include <openssl/arm_arch.h>

#define SEP ;
#define KECCAK_F1600_ROUNDS 24

.align(8)
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
 
 # Alias symbol C and E with registers
 # C[x] = A[x, 0] xor A[x, 1] xor A[x, 2] xor A[x, 3] xor A[x, 4],   for x in 0..4
 # E[x] = C[x-1] xor rot(C[x+1], 1), for x in 0..4
my @C = map("x$_", (30, 26, 27, 28, 29));
my @E = map("x$_", (29, 0, 26, 27, 28));

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
 # C[x] = A[x, 0] xor A[x, 1] xor A[x, 2] xor A[x, 3] xor A[x, 4],   for x in 0..4
 # E[x] = C[x-1] xor rot(C[x+1], 1), for x in 0..4
my @vC = map("v$_", (27, 28, 29, 30, 31));
my @vE = map("v$_", (31, 27, 26, 29, 30));
 
 # Alias symbol vA (the bit-state matrix) with vector registers
$vAq[0][4] = "q4"; $vAq[1][4] = "q9"; $vAq[2][4] = "q14"; $vAq[3][4] = "q19"; $vAq[4][4] = "q24";
$vAq[0][3] = "q3"; $vAq[1][3] = "q8"; $vAq[2][3] = "q13"; $vAq[3][3] = "q18"; $vAq[4][3] = "q23";
$vAq[0][2] = "q2"; $vAq[1][2] = "q7"; $vAq[2][2] = "q12"; $vAq[3][2] = "q17"; $vAq[4][2] = "q22";
$vAq[0][1] = "q1"; $vAq[1][1] = "q6"; $vAq[2][1] = "q11"; $vAq[3][1] = "q16"; $vAq[4][1] = "q21";
$vAq[0][0] = "q0"; $vAq[1][0] = "q5"; $vAq[2][0] = "q10"; $vAq[3][0] = "q15"; $vAq[4][0] = "q20";
    
 # Alias symbol vA_ (the permuted bit-state matrix) with vector registers
 # vA_[y, 2*x+3*y] = rot(vA[x, y])
$vAq_[0][4] = "q4";  $vAq_[1][4] = "q9";  $vAq_[2][4] = "q14"; $vAq_[3][4] = "q19"; $vAq_[4][4] = "q24";
$vAq_[0][3] = "q3";  $vAq_[1][3] = "q8";  $vAq_[2][3] = "q13"; $vAq_[3][3] = "q18"; $vAq_[4][3] = "q23";
$vAq_[0][2] = "q2";  $vAq_[1][2] = "q7";  $vAq_[2][2] = "q12"; $vAq_[3][2] = "q17"; $vAq_[4][2] = "q22";
$vAq_[0][1] = "q26"; $vAq_[1][1] = "q11"; $vAq_[2][1] = "q16"; $vAq_[3][1] = "q21"; $vAq_[4][1] = "q1";
$vAq_[0][0] = "q25"; $vAq_[1][0] = "q10"; $vAq_[2][0] = "q15"; $vAq_[3][0] = "q20"; $vAq_[4][0] = "q0";

my @vCq = map("q$_", (27, 28, 29, 30, 31));
my @vEq = map("q$_", (31, 27, 26, 29, 30));
   
$tmp0          =   "x0";
$tmp1          =  "x29";

$input_addr    =  "x26";
$const_addr    =  "x26";
$cur_const     =  "x26";
$count         =  "w29";

$code.=<<___;

/****************** STACK ALLOCATIONS *******************/
#define STACK_SIZE (8*8 + 8*12 + 8*6) // VREGS (8*8), GPRs (8*12), temp (8*6)
#define STACK_BASE_GPRS  (0)
#define STACK_BASE_VREGS (8*12)
#define STACK_BASE_TMP (8*8 + 8*12)
#define STACK_OFFSET_INPUT     (STACK_BASE_TMP   + 0*8)
#define STACK_OFFSET_CONST     (STACK_BASE_TMP   + 1*8)
#define STACK_OFFSET_COUNT     (STACK_BASE_TMP   + 2*8)
#define STACK_OFFSET_x27_A44   (STACK_BASE_TMP   + 3*8)
#define STACK_OFFSET_CONST_VEC (STACK_BASE_TMP   + 4*8)
#define vAga_offset            (STACK_BASE_TMP   + 5*8)

/****************** MEMORY ACCESSING MACROS *******************/
.macro load_input_vector
    ldr $vAq[0][0], [$input_addr, #(24*0)] 
    ldr $vAq[0][1], [$input_addr, #(24*1)]
    ldr $vAq[0][2], [$input_addr, #(24*2)]
    ldr $vAq[0][3], [$input_addr, #(24*3)]
    ldr $vAq[0][4], [$input_addr, #(24*4)]  
    ldr $vAq[1][0], [$input_addr, #(24*5)]
    ldr $vAq[1][1], [$input_addr, #(24*6)]  
    ldr $vAq[1][2], [$input_addr, #(24*7)] 
    ldr $vAq[1][3], [$input_addr, #(24*8)]    
    ldr $vAq[1][4], [$input_addr, #(24*9)]
    add $input_addr, $input_addr, #24*10
    ldr $vAq[2][0], [$input_addr, #(24*0)]
    ldr $vAq[2][1], [$input_addr, #(24*1)]
    ldr $vAq[2][2], [$input_addr, #(24*2)] 
    ldr $vAq[2][3], [$input_addr, #(24*3)]
    ldr $vAq[2][4], [$input_addr, #(24*4)] 
    ldr $vAq[3][0], [$input_addr, #(24*5)]
    ldr $vAq[3][1], [$input_addr, #(24*6)]   
    ldr $vAq[3][2], [$input_addr, #(24*7)]
    ldr $vAq[3][3], [$input_addr, #(24*8)]     
    ldr $vAq[3][4], [$input_addr, #(24*9)]
    add $input_addr, $input_addr, #24*10   
    ldr $vAq[4][0], [$input_addr, #(24*0)] 
    ldr $vAq[4][1], [$input_addr, #(24*1)]
    ldr $vAq[4][2], [$input_addr, #(24*2)]   
    ldr $vAq[4][3], [$input_addr, #(24*3)]
    ldr $vAq[4][4], [$input_addr, #(24*4)]  
    sub $input_addr, $input_addr, #24*20   
.endm

.macro store_input_vector
    str $vAq[0][0], [$input_addr, #(24*0)] 
    str $vAq[0][1], [$input_addr, #(24*1)] 
    str $vAq[0][2], [$input_addr, #(24*2)] 
    str $vAq[0][3], [$input_addr, #(24*3)] 
    str $vAq[0][4], [$input_addr, #(24*4)] 
    str $vAq[1][0], [$input_addr, #(24*5)] 
    str $vAq[1][1], [$input_addr, #(24*6)] 
    str $vAq[1][2], [$input_addr, #(24*7)] 
    str $vAq[1][3], [$input_addr, #(24*8)] 
    str $vAq[1][4], [$input_addr, #(24*9)] 
    add $input_addr, $input_addr, #24*10
    str $vAq[2][0], [$input_addr, #(24*0)]
    str $vAq[2][1], [$input_addr, #(24*1)]
    str $vAq[2][2], [$input_addr, #(24*2)] 
    str $vAq[2][3], [$input_addr, #(24*3)]
    str $vAq[2][4], [$input_addr, #(24*4)] 
    str $vAq[3][0], [$input_addr, #(24*5)]
    str $vAq[3][1], [$input_addr, #(24*6)]   
    str $vAq[3][2], [$input_addr, #(24*7)]
    str $vAq[3][3], [$input_addr, #(24*8)]     
    str $vAq[3][4], [$input_addr, #(24*9)] 
    add $input_addr, $input_addr, #24*10    
    str $vAq[4][0], [$input_addr, #(24*0)] 
    str $vAq[4][1], [$input_addr, #(24*1)]
    str $vAq[4][2], [$input_addr, #(24*2)]   
    str $vAq[4][3], [$input_addr, #(24*3)]
    str $vAq[4][4], [$input_addr, #(24*4)]  
    sub $input_addr, $input_addr, #24*20       
.endm

.macro store_input_scalar
    str $A[0][0], [$input_addr, 24*0]
    str $A[0][1], [$input_addr, 24*1]
    str $A[0][2], [$input_addr, 24*2]
    str $A[0][3], [$input_addr, 24*3]
    str $A[0][4], [$input_addr, 24*4]
    str $A[1][0], [$input_addr, 24*5]
    str $A[1][1], [$input_addr, 24*6]
    str $A[1][2], [$input_addr, 24*7]
    str $A[1][3], [$input_addr, 24*8]
    str $A[1][4], [$input_addr, 24*9]
    str $A[2][0], [$input_addr, 24*10]
    str $A[2][1], [$input_addr, 24*11]
    str $A[2][2], [$input_addr, 24*12]
    str $A[2][3], [$input_addr, 24*13]
    str $A[2][4], [$input_addr, 24*14]
    str $A[3][0], [$input_addr, 24*15]
    str $A[3][1], [$input_addr, 24*16]
    str $A[3][2], [$input_addr, 24*17]
    str $A[3][3], [$input_addr, 24*18]
    str $A[3][4], [$input_addr, 24*19]
    str $A[4][0], [$input_addr, 24*20]
    str $A[4][1], [$input_addr, 24*21]
    str $A[4][2], [$input_addr, 24*22]
    str $A[4][3], [$input_addr, 24*23]
    str $A[4][4], [$input_addr, 24*24]
.endm

.macro load_input_scalar
    ldr $A[0][0], [$input_addr, 24*0]
    ldr $A[0][1], [$input_addr, 24*1]
    ldr $A[0][2], [$input_addr, 24*2]
    ldr $A[0][3], [$input_addr, 24*3]
    ldr $A[0][4], [$input_addr, 24*4]
    ldr $A[1][0], [$input_addr, 24*5]
    ldr $A[1][1], [$input_addr, 24*6]
    ldr $A[1][2], [$input_addr, 24*7]
    ldr $A[1][3], [$input_addr, 24*8]
    ldr $A[1][4], [$input_addr, 24*9]
    ldr $A[2][0], [$input_addr, 24*10]
    ldr $A[2][1], [$input_addr, 24*11]
    ldr $A[2][2], [$input_addr, 24*12]
    ldr $A[2][3], [$input_addr, 24*13]
    ldr $A[2][4], [$input_addr, 24*14]
    ldr $A[3][0], [$input_addr, 24*15]
    ldr $A[3][1], [$input_addr, 24*16]
    ldr $A[3][2], [$input_addr, 24*17]
    ldr $A[3][3], [$input_addr, 24*18]
    ldr $A[3][4], [$input_addr, 24*19]
    ldr $A[4][0], [$input_addr, 24*20]
    ldr $A[4][1], [$input_addr, 24*21]
    ldr $A[4][2], [$input_addr, 24*22]
    ldr $A[4][3], [$input_addr, 24*23]
    ldr $A[4][4], [$input_addr, 24*24]
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

/****************** SHA3 NEON and Feat_SHA3 MACROS *******************/
.macro eor3_m0 d s0 s1 s2
    eor3 \\d\\().16b, \\s0\\().16b, \\s1\\().16b, \\s2\\().16b
.endm

.macro rax1_m0 d s0 s1
    rax1 \\d\\().2d, \\s0\\().2d, \\s1\\().2d
.endm

.macro xar_m0 d s0 s1 imm
    xar \\d\\().2d, \\s0\\().2d, \\s1\\().2d, \\imm
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

.macro bcax_m1 d s0 s1 s2
    bic vvtmp.16b, \\s1\\().16b, \\s2\\().16b
    eor \\d\\().16b, vvtmp.16b, \\s0\\().16b
.endm

.macro save reg, offset
    str \\reg, [sp, #\\offset]
.endm

.macro restore reg, offset
    ldr \\reg, [sp, #\\offset]
.endm

.macro load_constant_ptr
	adr $const_addr, round_constants
.endm

.macro load_constant_ptr_stack
    ldr $const_addr, [sp, #(STACK_OFFSET_CONST)]
.endm

.macro hybrid_round_initial
eor $C[4], $A[3][4], $A[4][4]                               SEP
str x27, [sp, #STACK_OFFSET_x27_A44]                        SEP      eor3_m0 $vC[1],$vA[0][1],$vA[1][1],$vA[2][1]                                                                           
eor $C[0], $A[3][0], $A[4][0]                               SEP      eor3_m1 $vC[3],$vA[0][3],$vA[1][3],$vA[2][3]                                                                            
eor $C[1], $A[3][1], $A[4][1]                               SEP      eor3_m0 $vC[0],$vA[0][0],$vA[1][0],$vA[2][0]                                                                                
eor $C[2], $A[3][2], $A[4][2]                               SEP      eor3_m1 $vC[2],$vA[0][2],$vA[1][2],$vA[2][2]                                                                           
eor $C[3], $A[3][3], $A[4][3]                               SEP      eor3_m0 $vC[4],$vA[0][4],$vA[1][4],$vA[2][4]                                                                            
eor $C[0], $A[2][0], $C[0]                                  SEP      eor3_m1 $vC[1], $vC[1],$vA[3][1], $vA[4][1]                                                                           
eor $C[1], $A[2][1], $C[1]                                  SEP      eor3_m0 $vC[3], $vC[3],$vA[3][3], $vA[4][3]                                                                           
eor $C[2], $A[2][2], $C[2]                                  SEP      eor3_m1 $vC[0], $vC[0],$vA[3][0], $vA[4][0]                                                                           
eor $C[3], $A[2][3], $C[3]                                  SEP      eor3_m0 $vC[2], $vC[2],$vA[3][2], $vA[4][2]                                                                           
eor $C[4], $A[2][4], $C[4]                                  SEP      eor3_m1 $vC[4], $vC[4],$vA[3][4], $vA[4][4]                                                                            
eor $C[0], $A[1][0], $C[0]                                  SEP      vvtmp .req $vA_[0][0]                                                                           
eor $C[1], $A[1][1], $C[1]                                  SEP                                                                           
eor $C[2], $A[1][2], $C[2]                                  SEP      rax1_m0 $vE[2], $vC[1], $vC[3]                                                                           
eor $C[3], $A[1][3], $C[3]                                  SEP      rax1_m1 $vE[4], $vC[3], $vC[0]                                                                            
eor $C[4], $A[1][4], $C[4]                                  SEP      rax1_m0 $vE[1], $vC[0], $vC[2]                                                                           
eor $C[0], $A[0][0], $C[0]                                  SEP      rax1_m1 $vE[3], $vC[2], $vC[4]                                                                           
eor $C[1], $A[0][1], $C[1]                                  SEP      rax1_m0 $vE[0], $vC[4], $vC[1]                                                                           
eor $C[2], $A[0][2], $C[2]                                  SEP      .unreq vvtmp                                                                           
eor $C[3], $A[0][3], $C[3]                                  SEP      vvtmp .req $vC[1]                                                                           
eor $C[4], $A[0][4], $C[4]                                  SEP      vvtmpq .req $vCq[1]                                                                           
eor $E[1], $C[0], $C[2], ROR #63                            SEP      eor $vA_[0][0].16b, $vA[0][0].16b, $vE[0].16b                                                                           
eor $E[3], $C[2], $C[4], ROR #63                            SEP      xar_m1 $vA_[4][0], $vA[0][2], $vE[2], 2                                                                            
eor $E[0], $C[4], $C[1], ROR #63                            SEP                                                                           
eor $E[2], $C[1], $C[3], ROR #63                            SEP      xar_m0 $vA_[0][2], $vA[2][2], $vE[2], #21                                                                           
eor $E[4], $C[3], $C[0], ROR #63                            SEP      xar_m1 $vA_[2][2], $vA[2][3], $vE[3], 39                                                                           
eor $A_[0][0], $A[0][0], $E[0]                              SEP      xar_m0 $vA_[2][3], $vA[3][4], $vE[4], #56                                                                           
eor $A_[4][0], $A[0][2], $E[2]                              SEP      xar_m1 $vA_[3][4], $vA[4][3], $vE[3], 8                                                                            
eor $A_[0][2], $A[2][2], $E[2]                              SEP      xar_m0 $vA_[4][3], $vA[3][0], $vE[0], #23                                                                           
eor $A_[2][2], $A[2][3], $E[3]                              SEP      xar_m1 $vA_[2][0], $vA[0][1], $vE[1], 63                                                                           
eor $A_[2][3], $A[3][4], $E[4]                              SEP      xar_m0 $vA_[4][1], $vA[1][3], $vE[3], #9                                                                            
eor $A_[3][4], $A[4][3], $E[3]                              SEP      xar_m1 $vA_[1][3], $vA[3][1], $vE[1], 19                                                                           
eor $A_[4][3], $A[3][0], $E[0]                              SEP      xar_m0 $vA_[2][1], $vA[1][2], $vE[2], #58                                                                           
eor $A_[2][0], $A[0][1], $E[1]                              SEP      xar_m1 $vA_[1][2], $vA[2][0], $vE[0], 61                                                                             
eor $A_[4][1], $A[1][3], $E[3]                              SEP                                                                           
eor $A_[1][3], $A[3][1], $E[1]                              SEP      xar_m0 $vA_[1][0], $vA[0][3], $vE[3], #36                                                                           
eor $A_[2][1], $A[1][2], $E[2]                              SEP      xar_m1 $vA_[0][3], $vA[3][3], $vE[3], 43                                                                           
eor $A_[1][2], $A[2][0], $E[0]                              SEP      xar_m0 $vA_[3][3], $vA[3][2], $vE[2], #49                                                                           
eor $A_[1][0], $A[0][3], $E[3]                              SEP      xar_m1 $vA_[3][2], $vA[2][1], $vE[1], 54                                                                           
eor $A_[0][3], $A[3][3], $E[3]                              SEP      xar_m0 $vA_[1][1], $vA[1][4], $vE[4], #44                                                                           
eor $A_[3][3], $A[3][2], $E[2]                              SEP      mov $vE[3].16b, $vA[1][0].16b                                                                                       
eor $A_[3][2], $A[2][1], $E[1]                              SEP      bcax_m1 $vA[1][0], $vA_[1][0], $vA_[1][2], $vA_[1][1]                                                                           
eor $A_[1][1], $A[1][4], $E[4]                              SEP      xar_m0 $vA_[1][4], $vA[4][2], $vE[2], #3                                                                            
eor $A_[1][4], $A[4][2], $E[2]                              SEP      xar_m1 $vA_[4][2], $vA[2][4], $vE[4], 25                                                                           
eor $A_[4][2], $A[2][4], $E[4]                              SEP      xar_m0 $vA_[2][4], $vA[4][0], $vE[0], #46                                                                           
eor $A_[2][4], $A[4][0], $E[0]                              SEP                                                                                                               
eor $A_[3][0], $A[0][4], $E[4]                              SEP      xar_m1 $vA_[3][0], $vA[0][4], $vE[4], 37                                                                           
ldr x27, [sp, STACK_OFFSET_x27_A44]                         SEP      xar_m0 $vA_[0][4], $vA[4][4], $vE[4], #50                                                                           
eor $A_[0][4], $A[4][4], $E[4]                              SEP      xar_m1 $vA_[4][4], $vA[4][1], $vE[1], 62                                                                           
eor $A_[4][4], $A[4][1], $E[1]                              SEP      xar_m0 $vA_[3][1], $vE[3], $vE[0], #28                                                                             
eor $A_[3][1], $A[1][0], $E[0]                              SEP      xar_m1 $vA_[0][1], $vA[1][1], $vE[1], 20                                                                           
eor $A_[0][1], $A[1][1], $E[1]                              SEP      bcax_m1 $vA[1][1], $vA_[1][1], $vA_[1][3], $vA_[1][2]                                                                           
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                    SEP      bcax_m0 $vA[1][2], $vA_[1][2], $vA_[1][4], $vA_[1][3]                                                                           
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                    SEP      bcax_m1 $vA[1][3], $vA_[1][3], $vA_[1][0], $vA_[1][4]                                                                           
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                     SEP      bcax_m0 $vA[1][4], $vA_[1][4], $vA_[1][1], $vA_[1][0]                                                                           
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                    SEP      bcax_m1 $vA[2][0], $vA_[2][0], $vA_[2][2], $vA_[2][1]                                                                           
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                     SEP      bcax_m0 $vA[2][1], $vA_[2][1], $vA_[2][3], $vA_[2][2]                                                                           
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                    SEP                                                                           
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                     SEP      .unreq vvtmp                                                                                               
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                    SEP      .unreq vvtmpq                                                                                               
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                     SEP      eor2    $vC[0],  $vA[2][0], $vA[1][0]                                                                                    
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                    SEP      str $vAq[1][0], [sp, #(vAga_offset)]                                                                                                    
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                     SEP      vvtmp .req $vA[1][0]                                                                                                   
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                    SEP      vvtmpq .req $vAq[1][0]                                                                                                    
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                     SEP      bcax_m0 $vA[2][2], $vA_[2][2], $vA_[2][4], $vA_[2][3]                                                                                  
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                    SEP      bcax_m1 $vA[2][3], $vA_[2][3], $vA_[2][0], $vA_[2][4]                                                                                 
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                      SEP      eor2    $vC[1],  $vA[2][1], $vA[1][1]                                                                                             
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                    SEP      bcax_m0 $vA[2][4], $vA_[2][4], $vA_[2][1], $vA_[2][0]                                                                                    
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                     SEP                                                                                 
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                     SEP      eor2    $vC[2],  $vA[2][2], $vA[1][2]                                                                                     
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                     SEP      bcax_m1 $vA[3][0], $vA_[3][0], $vA_[3][2], $vA_[3][1]                                                                            
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                    SEP      eor2    $vC[3],  $vA[2][3], $vA[1][3]                                                                                      
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                     SEP      bcax_m0 $vA[3][1], $vA_[3][1], $vA_[3][3], $vA_[3][2]                                                                           
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                     SEP      eor2    $vC[4],  $vA[2][4], $vA[1][4]                                                                                       
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                     SEP      bcax_m1 $vA[3][2], $vA_[3][2], $vA_[3][4], $vA_[3][3]                                                                           
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                    SEP      eor2    $vC[0],  $vC[0],  $vA[3][0]                                                                                     
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                     SEP      bcax_m0 $vA[3][3], $vA_[3][3], $vA_[3][0], $vA_[3][4]                                                                           
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                    SEP      eor2    $vC[1],  $vC[1],  $vA[3][1]                                                                                     
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                     SEP      bcax_m1 $vA[3][4], $vA_[3][4], $vA_[3][1], $vA_[3][0]                                                                           
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                     SEP                                                                           
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                     SEP      eor2    $vC[2],  $vC[2],  $vA[3][2]                                                                                        
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                    SEP      bcax_m0 $vA[4][0], $vA_[4][0], $vA_[4][2], $vA_[4][1]                                                                           
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                     SEP      eor2    $vC[3],  $vC[3],  $vA[3][3]                                                                                       
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                     SEP      bcax_m1 $vA[4][1], $vA_[4][1], $vA_[4][3], $vA_[4][2]                                                                           
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                     SEP      eor2    $vC[4],  $vC[4],  $vA[3][4]                                                                                       
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                    SEP      bcax_m0 $vA[4][2], $vA_[4][2], $vA_[4][4], $vA_[4][3]                                                                           
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                     SEP      eor2    $vC[0],  $vC[0],  $vA[4][0]                                                                                      
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                    SEP      bcax_m1 $vA[4][3], $vA_[4][3], $vA_[4][0], $vA_[4][4]                                                                           
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                     SEP      eor2    $vC[1],  $vC[1],  $vA[4][1]                                                                                     
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                    SEP      bcax_m0 $vA[4][4], $vA_[4][4], $vA_[4][1], $vA_[4][0]                                                                           
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                     SEP                                                                           
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                    SEP                                                                           
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                     SEP      eor2    $vC[2],  $vC[2],  $vA[4][2]                                                                           
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                    SEP      eor2    $vC[3],  $vC[3],  $vA[4][3]                                                                           
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                     SEP      bcax_m1 $vA[0][0], $vA_[0][0], $vA_[0][2], $vA_[0][1]                                                                           
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                    SEP      bcax_m0 $vA[0][1], $vA_[0][1], $vA_[0][3], $vA_[0][2]                                                                           
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                     SEP      eor2    $vC[1],  $vC[1],  $vA[0][1]                                                                           
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                    SEP      restore x26, STACK_OFFSET_CONST_VEC                                                                           
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                     SEP      ldr vvtmpq, [x26], #16                                                                           
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                    SEP      save x26, STACK_OFFSET_CONST_VEC                                                                            
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                     SEP      eor $vA[0][0].16b, $vA[0][0].16b, vvtmp.16b                                                                           
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                     SEP      eor2    $vC[4],  $vC[4],  $vA[4][4]                                                                           
load_constant_ptr                                           SEP                                                                           
str $const_addr, [sp, #(STACK_OFFSET_CONST)]                SEP      bcax_m0 $vA[0][2], $vA_[0][2], $vA_[0][4], $vA_[0][3]                                                                           
ldr $cur_const, [$const_addr]                               SEP      bcax_m1 $vA[0][3], $vA_[0][3], $vA_[0][0], $vA_[0][4]                                                                           
mov $count, #1                                              SEP      eor2    $vC[3],  $vC[3],  $vA[0][3]                                                                           
str $count, [sp, #STACK_OFFSET_COUNT]                       SEP      eor2    $vC[2],  $vC[2],  $vA[0][2]                                                                           
eor $A[0][0], $A[0][0], $cur_const                          SEP      eor2    $vC[0],  $vC[0],  $vA[0][0]                                                                           
eor $C[4], $A[2][4], $A[1][4], ROR #50                      SEP      bcax_m0 $vA[0][4], $vA_[0][4], $vA_[0][1], $vA_[0][0]                                                                           
eor $C[4], $C[4], $A[3][4], ROR #34                         SEP      eor2    $vC[4],  $vC[4],  $vA[0][4]                                                                           
eor $C[1], $A[2][1], $A[3][1], ROR #57                      SEP      ldr $vAq[1][0], [sp, #(vAga_offset)]                                                                          
eor $C[4], $C[4], $A[0][4], ROR #26                         SEP      .unreq vvtmp                                                                           
eor $C[0], $A[0][0], $A[1][0], ROR #61                      SEP      .unreq vvtmpq                                                                           
eor $C[4], $C[4], $A[4][4], ROR #15                         SEP      vvtmp .req $vA_[0][0]                                                                            
str x27, [sp, #STACK_OFFSET_x27_A44]                        SEP                                                                           
eor $C[2], $A[4][2], $A[0][2], ROR #52                      SEP      rax1_m0 $vE[2], $vC[1], $vC[3]                                                                           
eor $C[3], $A[0][3], $A[2][3], ROR #63                      SEP      rax1_m1 $vE[4], $vC[3], $vC[0]                                                                           
eor $C[2], $C[2], $A[2][2], ROR #48                         SEP      rax1_m0 $vE[1], $vC[0], $vC[2]                                                                           
eor $C[0], $C[0], $A[3][0], ROR #54                         SEP      rax1_m1 $vE[3], $vC[2], $vC[4]                                                                           
eor $C[1], $C[1], $A[0][1], ROR #51                         SEP      rax1_m0 $vE[0], $vC[4], $vC[1]                                                                           
eor $C[3], $C[3], $A[3][3], ROR #37                         SEP      .unreq vvtmp                                                                           
eor $C[2], $C[2], $A[3][2], ROR #10                         SEP      vvtmp .req $vC[1]                                                                           
eor $C[0], $C[0], $A[2][0], ROR #39                         SEP      vvtmpq .req $vCq[1]                                                                           
eor $C[1], $C[1], $A[4][1], ROR #31                         SEP      eor $vA_[0][0].16b, $vA[0][0].16b, $vE[0].16b                                                                           
eor $C[3], $C[3], $A[1][3], ROR #36                         SEP      xar_m1 $vA_[4][0], $vA[0][2], $vE[2], 2                                                                             
eor $C[2], $C[2], $A[1][2], ROR #5                          SEP                                                                           
eor $C[0], $C[0], $A[4][0], ROR #25                         SEP      xar_m0 $vA_[0][2], $vA[2][2], $vE[2], #21                                                                           
eor $C[1], $C[1], $A[1][1], ROR #27                         SEP      xar_m1 $vA_[2][2], $vA[2][3], $vE[3], 39                                                                           
eor $C[3], $C[3], $A[4][3], ROR #2                          SEP      xar_m0 $vA_[2][3], $vA[3][4], $vE[4], #56                                                                           
eor $E[1], $C[0], $C[2], ROR #61                            SEP      xar_m1 $vA_[3][4], $vA[4][3], $vE[3], 8                                                                            
ror $C[2], $C[2], 62                                        SEP      xar_m0 $vA_[4][3], $vA[3][0], $vE[0], #23                                                                           
eor $E[3], $C[2], $C[4], ROR #57                            SEP      xar_m1 $vA_[2][0], $vA[0][1], $vE[1], 63                                                                           
ror $C[4], $C[4], 58                                        SEP      xar_m0 $vA_[4][1], $vA[1][3], $vE[3], #9                                                                            
eor $E[0], $C[4], $C[1], ROR #55                            SEP      xar_m1 $vA_[1][3], $vA[3][1], $vE[1], 19                                                                           
ror $C[1], $C[1], 56                                        SEP      xar_m0 $vA_[2][1], $vA[1][2], $vE[2], #58                                                                           
eor $E[2], $C[1], $C[3], ROR #63                            SEP      xar_m1 $vA_[1][2], $vA[2][0], $vE[0], 61                                                                           
eor $E[4], $C[3], $C[0], ROR #63                            SEP                                                                           
eor $A_[0][0], $E[0], $A[0][0]                              SEP      xar_m0 $vA_[1][0], $vA[0][3], $vE[3], #36                                                                           
eor $A_[4][0], $E[2], $A[0][2], ROR #50                     SEP      xar_m1 $vA_[0][3], $vA[3][3], $vE[3], 43                                                                           
eor $A_[0][2], $E[2], $A[2][2], ROR #46                     SEP      xar_m0 $vA_[3][3], $vA[3][2], $vE[2], #49                                                                           
eor $A_[2][2], $E[3], $A[2][3], ROR #63                     SEP      xar_m1 $vA_[3][2], $vA[2][1], $vE[1], 54                                                                           
eor $A_[2][3], $E[4], $A[3][4], ROR #28                     SEP      xar_m0 $vA_[1][1], $vA[1][4], $vE[4], #44                                                                           
eor $A_[3][4], $E[3], $A[4][3], ROR #2                      SEP      mov $vE[3].16b, $vA[1][0].16b                                                                           
eor $A_[4][3], $E[0], $A[3][0], ROR #54                     SEP      bcax_m1 $vA[1][0], $vA_[1][0], $vA_[1][2], $vA_[1][1]                                                                           
eor $A_[2][0], $E[1], $A[0][1], ROR #43                     SEP      xar_m0 $vA_[1][4], $vA[4][2], $vE[2], #3                                                                           
eor $A_[4][1], $E[3], $A[1][3], ROR #36                     SEP      xar_m1 $vA_[4][2], $vA[2][4], $vE[4], 25                                                                           
eor $A_[1][3], $E[1], $A[3][1], ROR #49                     SEP      xar_m0 $vA_[2][4], $vA[4][0], $vE[0], #46                                                                           
eor $A_[2][1], $E[2], $A[1][2], ROR #3                      SEP                                                                           
eor $A_[1][2], $E[0], $A[2][0], ROR #39                     SEP      xar_m1 $vA_[3][0], $vA[0][4], $vE[4], 37                                                                           
eor $A_[1][0], $E[3], $A[0][3]                              SEP      xar_m0 $vA_[0][4], $vA[4][4], $vE[4], #50                                                                           
eor $A_[0][3], $E[3], $A[3][3], ROR #37                     SEP      xar_m1 $vA_[4][4], $vA[4][1], $vE[1], 62                                                                           
eor $A_[3][3], $E[2], $A[3][2], ROR #8                      SEP      xar_m0 $vA_[3][1], $vE[3], $vE[0], #28                                                                           
eor $A_[3][2], $E[1], $A[2][1], ROR #56                     SEP      xar_m1 $vA_[0][1], $vA[1][1], $vE[1], 20                                                                           
eor $A_[1][1], $E[4], $A[1][4], ROR #44                     SEP      bcax_m1 $vA[1][1], $vA_[1][1], $vA_[1][3], $vA_[1][2]                                                                           
eor $A_[1][4], $E[2], $A[4][2], ROR #62                     SEP      bcax_m0 $vA[1][2], $vA_[1][2], $vA_[1][4], $vA_[1][3]                                                                           
eor $A_[4][2], $E[4], $A[2][4], ROR #58                     SEP      bcax_m1 $vA[1][3], $vA_[1][3], $vA_[1][0], $vA_[1][4]                                                                           
eor $A_[2][4], $E[0], $A[4][0], ROR #25                     SEP      bcax_m0 $vA[1][4], $vA_[1][4], $vA_[1][1], $vA_[1][0]                                                                           
eor $A_[3][0], $E[4], $A[0][4], ROR #20                     SEP      bcax_m1 $vA[2][0], $vA_[2][0], $vA_[2][2], $vA_[2][1]                                                                           
ldr x27, [sp, #STACK_OFFSET_x27_A44]                        SEP                                                                           
eor $A_[0][4], $E[4], $A[4][4], ROR #9                      SEP      bcax_m0 $vA[2][1], $vA_[2][1], $vA_[2][3], $vA_[2][2]                                                                           
eor $A_[4][4], $E[1], $A[4][1], ROR #23                     SEP      .unreq vvtmp                                                                           
eor $A_[3][1], $E[0], $A[1][0], ROR #61                     SEP      .unreq vvtmpq                                                                           
eor $A_[0][1], $E[1], $A[1][1], ROR #19                     SEP      eor2    $vC[0],  $vA[2][0], $vA[1][0]                                                                           
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                    SEP      str $vAq[1][0], [sp, #(vAga_offset)]                                                                        
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                    SEP      vvtmp .req $vA[1][0]                                                                           
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                     SEP      vvtmpq .req $vAq[1][0]                                                                           
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                    SEP      bcax_m0 $vA[2][2], $vA_[2][2], $vA_[2][4], $vA_[2][3]                                                                           
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                     SEP      bcax_m1 $vA[2][3], $vA_[2][3], $vA_[2][0], $vA_[2][4]                                                                           
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                    SEP      eor2    $vC[1],  $vA[2][1], $vA[1][1]                                                                           
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                     SEP      bcax_m0 $vA[2][4], $vA_[2][4], $vA_[2][1], $vA_[2][0]                                                                           
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                    SEP                                                                           
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                     SEP      eor2    $vC[2],  $vA[2][2], $vA[1][2]                                                                           
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                    SEP      bcax_m1 $vA[3][0], $vA_[3][0], $vA_[3][2], $vA_[3][1]                                                                           
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                     SEP      eor2    $vC[3],  $vA[2][3], $vA[1][3]                                                                           
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                    SEP      bcax_m0 $vA[3][1], $vA_[3][1], $vA_[3][3], $vA_[3][2]                                                                           
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                     SEP      eor2    $vC[4],  $vA[2][4], $vA[1][4]                                                                           
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                    SEP      bcax_m1 $vA[3][2], $vA_[3][2], $vA_[3][4], $vA_[3][3]                                                                           
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                      SEP      eor2    $vC[0],  $vC[0],  $vA[3][0]                                                                           
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                    SEP      bcax_m0 $vA[3][3], $vA_[3][3], $vA_[3][0], $vA_[3][4]                                                                           
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                     SEP      eor2    $vC[1],  $vC[1],  $vA[3][1]                                                                           
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                     SEP      bcax_m1 $vA[3][4], $vA_[3][4], $vA_[3][1], $vA_[3][0]                                                                           
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                     SEP                                                                           
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                    SEP      eor2    $vC[2],  $vC[2],  $vA[3][2]                                                                           
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                     SEP      bcax_m0 $vA[4][0], $vA_[4][0], $vA_[4][2], $vA_[4][1]                                                                           
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                     SEP      eor2    $vC[3],  $vC[3],  $vA[3][3]                                                                           
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                     SEP      bcax_m1 $vA[4][1], $vA_[4][1], $vA_[4][3], $vA_[4][2]                                                                           
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                    SEP      eor2    $vC[4],  $vC[4],  $vA[3][4]                                                                           
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                     SEP      bcax_m0 $vA[4][2], $vA_[4][2], $vA_[4][4], $vA_[4][3]                                                                           
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                    SEP      eor2    $vC[0],  $vC[0],  $vA[4][0]                                                                           
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                     SEP      bcax_m1 $vA[4][3], $vA_[4][3], $vA_[4][0], $vA_[4][4]                                                                           
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                     SEP      eor2    $vC[1],  $vC[1],  $vA[4][1]                                                                           
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                     SEP      bcax_m0 $vA[4][4], $vA_[4][4], $vA_[4][1], $vA_[4][0]                                                                           
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                    SEP      eor2    $vC[2],  $vC[2],  $vA[4][2]                                                                           
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                     SEP      eor2    $vC[3],  $vC[3],  $vA[4][3]                                                                           
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                     SEP      bcax_m1 $vA[0][0], $vA_[0][0], $vA_[0][2], $vA_[0][1]                                                                           
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                     SEP      bcax_m0 $vA[0][1], $vA_[0][1], $vA_[0][3], $vA_[0][2]                                                                           
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                    SEP      eor2    $vC[1],  $vC[1],  $vA[0][1]                                                                           
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                     SEP      restore x26, STACK_OFFSET_CONST_VEC                                                                            
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                    SEP      ldr vvtmpq, [x26], #16                                                                           
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                     SEP      save x26, STACK_OFFSET_CONST_VEC                                                                            
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                    SEP      eor $vA[0][0].16b, $vA[0][0].16b, vvtmp.16b                                                                           
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                     SEP      eor2    $vC[4],  $vC[4],  $vA[4][4]                                                                           
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                    SEP                                                                           
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                     SEP                                                                           
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                    SEP      bcax_m0 $vA[0][2], $vA_[0][2], $vA_[0][4], $vA_[0][3]                                                                           
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                     SEP      bcax_m1 $vA[0][3], $vA_[0][3], $vA_[0][0], $vA_[0][4]                                                                           
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                    SEP      eor2    $vC[3],  $vC[3],  $vA[0][3]                                                                           
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                     SEP      eor2    $vC[2],  $vC[2],  $vA[0][2]                                                                           
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                    SEP      eor2    $vC[0],  $vC[0],  $vA[0][0]                                                                           
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                     SEP      bcax_m0 $vA[0][4], $vA_[0][4], $vA_[0][1], $vA_[0][0]                                                                           
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                    SEP      eor2    $vC[4],  $vC[4],  $vA[0][4]                                                                           
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                     SEP      ldr $vAq[1][0], [sp, #(vAga_offset)]                                                                          
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                     SEP      .unreq vvtmp                                                                           
ldr $count, [sp, #STACK_OFFSET_COUNT]                       SEP      .unreq vvtmpq                                                                           
load_constant_ptr_stack                                     SEP    
ldr $cur_const, [$const_addr, $count, UXTW #3]              SEP     
add $count, $count, #1                                      SEP       
str $count , [sp , #STACK_OFFSET_COUNT]                     SEP           
eor $A[0][0], $A[0][0], $cur_const  
.endm

.macro  hybrid_round_noninitial
eor $C[4], $A[2][4], $A[1][4], ROR #50                      SEP
eor $C[4], $C[4], $A[3][4], ROR #34                         SEP      vvtmp .req $vA_[0][0]
eor $C[1], $A[2][1], $A[3][1], ROR #57                      SEP      rax1_m0 $vE[2], $vC[1], $vC[3]
eor $C[4], $C[4], $A[0][4], ROR #26                         SEP      rax1_m1 $vE[4], $vC[3], $vC[0]
eor $C[0], $A[0][0], $A[1][0], ROR #61                      SEP      rax1_m0 $vE[1], $vC[0], $vC[2]
eor $C[4], $C[4], $A[4][4], ROR #15                         SEP      rax1_m1 $vE[3], $vC[2], $vC[4]
str x27, [sp, #STACK_OFFSET_x27_A44]                        SEP      rax1_m0 $vE[0], $vC[4], $vC[1]
eor $C[2], $A[4][2], $A[0][2], ROR #52                      SEP
eor $C[3], $A[0][3], $A[2][3], ROR #63                      SEP      .unreq vvtmp
eor $C[2], $C[2], $A[2][2], ROR #48                         SEP      vvtmp .req $vC[1]
eor $C[0], $C[0], $A[3][0], ROR #54                         SEP      vvtmpq .req  $vCq[1]
eor $C[1], $C[1], $A[0][1], ROR #51                         SEP      eor $vA_[0][0].16b, $vA[0][0].16b, $vE[0].16b
eor $C[3], $C[3], $A[3][3], ROR #37                         SEP      xar_m1 $vA_[4][0], $vA[0][2], $vE[2], 2
eor $C[2], $C[2], $A[3][2], ROR #10                         SEP
eor $C[0], $C[0], $A[2][0], ROR #39                         SEP      xar_m0 $vA_[0][2], $vA[2][2], $vE[2], #21
eor $C[1], $C[1], $A[4][1], ROR #31                         SEP      xar_m1 $vA_[2][2], $vA[2][3], $vE[3], 39
eor $C[3], $C[3], $A[1][3], ROR #36                         SEP      xar_m0 $vA_[2][3], $vA[3][4], $vE[4], #56
eor $C[2], $C[2], $A[1][2], ROR #5                          SEP      xar_m1 $vA_[3][4], $vA[4][3], $vE[3], 8
eor $C[0], $C[0], $A[4][0], ROR #25                         SEP      xar_m0 $vA_[4][3], $vA[3][0], $vE[0], #23
eor $C[1], $C[1], $A[1][1], ROR #27                         SEP      xar_m1 $vA_[2][0], $vA[0][1], $vE[1], 63
eor $C[3], $C[3], $A[4][3], ROR #2                          SEP
eor $E[1], $C[0], $C[2], ROR #61                            SEP      xar_m0 $vA_[4][1], $vA[1][3], $vE[3], #9
ror $C[2], $C[2], 62                                        SEP      xar_m1 $vA_[1][3], $vA[3][1], $vE[1], 19
eor $E[3], $C[2], $C[4], ROR #57                            SEP      xar_m0 $vA_[2][1], $vA[1][2], $vE[2], #58
ror $C[4], $C[4], 58                                        SEP      xar_m1 $vA_[1][2], $vA[2][0], $vE[0], 61
eor $E[0], $C[4], $C[1], ROR #55                            SEP      xar_m0 $vA_[1][0], $vA[0][3], $vE[3], #36
ror $C[1], $C[1], 56                                        SEP
eor $E[2], $C[1], $C[3], ROR #63                            SEP      xar_m1 $vA_[0][3], $vA[3][3], $vE[3], 43
eor $E[4], $C[3], $C[0], ROR #63                            SEP      xar_m0 $vA_[3][3], $vA[3][2], $vE[2], #49
eor $A_[0][0], $E[0], $A[0][0]                              SEP      xar_m1 $vA_[3][2], $vA[2][1], $vE[1], 54
eor $A_[4][0], $E[2], $A[0][2], ROR #50                     SEP      xar_m0 $vA_[1][1], $vA[1][4], $vE[4], #44
eor $A_[0][2], $E[2], $A[2][2], ROR #46                     SEP      mov $vE[3].16b, $vA[1][0].16b
eor $A_[2][2], $E[3], $A[2][3], ROR #63                     SEP      bcax_m1 $vA[1][0], $vA_[1][0], $vA_[1][2], $vA_[1][1]
eor $A_[2][3], $E[4], $A[3][4], ROR #28                     SEP
eor $A_[3][4], $E[3], $A[4][3], ROR #2                      SEP      xar_m0 $vA_[1][4], $vA[4][2], $vE[2], #3
eor $A_[4][3], $E[0], $A[3][0], ROR #54                     SEP      xar_m1 $vA_[4][2], $vA[2][4], $vE[4], 25
eor $A_[2][0], $E[1], $A[0][1], ROR #43                     SEP      xar_m0 $vA_[2][4], $vA[4][0], $vE[0], #46
eor $A_[4][1], $E[3], $A[1][3], ROR #36                     SEP      xar_m1 $vA_[3][0], $vA[0][4], $vE[4], 37
eor $A_[1][3], $E[1], $A[3][1], ROR #49                     SEP      xar_m0 $vA_[0][4], $vA[4][4], $vE[4], #50
eor $A_[2][1], $E[2], $A[1][2], ROR #3                      SEP
eor $A_[1][2], $E[0], $A[2][0], ROR #39                     SEP      xar_m1 $vA_[4][4], $vA[4][1], $vE[1], 62
eor $A_[1][0], $E[3], $A[0][3]                              SEP      xar_m0 $vA_[3][1], $vE[3], $vE[0], #28
eor $A_[0][3], $E[3], $A[3][3], ROR #37                     SEP      xar_m1 $vA_[0][1], $vA[1][1], $vE[1], 20
eor $A_[3][3], $E[2], $A[3][2], ROR #8                      SEP      bcax_m1 $vA[1][1], $vA_[1][1], $vA_[1][3], $vA_[1][2]
eor $A_[3][2], $E[1], $A[2][1], ROR #56                     SEP      bcax_m0 $vA[1][2], $vA_[1][2], $vA_[1][4], $vA_[1][3]
eor $A_[1][1], $E[4], $A[1][4], ROR #44                     SEP
eor $A_[1][4], $E[2], $A[4][2], ROR #62                     SEP      bcax_m1 $vA[1][3], $vA_[1][3], $vA_[1][0], $vA_[1][4]
eor $A_[4][2], $E[4], $A[2][4], ROR #58                     SEP      bcax_m0 $vA[1][4], $vA_[1][4], $vA_[1][1], $vA_[1][0]
eor $A_[2][4], $E[0], $A[4][0], ROR #25                     SEP      bcax_m1 $vA[2][0], $vA_[2][0], $vA_[2][2], $vA_[2][1]
eor $A_[3][0], $E[4], $A[0][4], ROR #20                     SEP      bcax_m0 $vA[2][1], $vA_[2][1], $vA_[2][3], $vA_[2][2]
ldr x27, [sp, #STACK_OFFSET_x27_A44]                        SEP      .unreq vvtmp
eor $A_[0][4], $E[4], $A[4][4], ROR #9                      SEP      .unreq vvtmpq
eor $A_[4][4], $E[1], $A[4][1], ROR #23                     SEP
eor $A_[3][1], $E[0], $A[1][0], ROR #61                     SEP      eor2    $vC[0],  $vA[2][0], $vA[1][0]
eor $A_[0][1], $E[1], $A[1][1], ROR #19                     SEP      str $vAq[1][0], [sp, #(vAga_offset)]
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                    SEP      vvtmp .req $vA[1][0]
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                    SEP      vvtmpq .req $vAq[1][0]
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                     SEP      bcax_m0 $vA[2][2], $vA_[2][2], $vA_[2][4], $vA_[2][3]
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                    SEP
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                     SEP      bcax_m1 $vA[2][3], $vA_[2][3], $vA_[2][0], $vA_[2][4]
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                    SEP      eor2    $vC[1],  $vA[2][1], $vA[1][1]
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                     SEP      bcax_m0 $vA[2][4], $vA_[2][4], $vA_[2][1], $vA_[2][0]
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                    SEP      eor2    $vC[2],  $vA[2][2], $vA[1][2]
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                     SEP      bcax_m1 $vA[3][0], $vA_[3][0], $vA_[3][2], $vA_[3][1]
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                    SEP      eor2    $vC[3],  $vA[2][3], $vA[1][3]
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                     SEP
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                    SEP      bcax_m0 $vA[3][1], $vA_[3][1], $vA_[3][3], $vA_[3][2]
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                     SEP      eor2    $vC[4],  $vA[2][4], $vA[1][4]
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                    SEP      bcax_m1 $vA[3][2], $vA_[3][2], $vA_[3][4], $vA_[3][3]
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                      SEP      eor2    $vC[0],  $vC[0],  $vA[3][0]
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                    SEP      bcax_m0 $vA[3][3], $vA_[3][3], $vA_[3][0], $vA_[3][4]
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                     SEP
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                     SEP      eor2    $vC[1],  $vC[1],  $vA[3][1]
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                     SEP      bcax_m1 $vA[3][4], $vA_[3][4], $vA_[3][1], $vA_[3][0]
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                    SEP      eor2    $vC[2],  $vC[2],  $vA[3][2]
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                     SEP      bcax_m0 $vA[4][0], $vA_[4][0], $vA_[4][2], $vA_[4][1]
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                     SEP      eor2    $vC[3],  $vC[3],  $vA[3][3]
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                     SEP
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                    SEP      bcax_m1 $vA[4][1], $vA_[4][1], $vA_[4][3], $vA_[4][2]
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                     SEP      eor2    $vC[4],  $vC[4],  $vA[3][4]
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                    SEP      bcax_m0 $vA[4][2], $vA_[4][2], $vA_[4][4], $vA_[4][3]
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                     SEP      eor2    $vC[0],  $vC[0],  $vA[4][0]
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                     SEP      bcax_m1 $vA[4][3], $vA_[4][3], $vA_[4][0], $vA_[4][4]
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                     SEP      eor2    $vC[1],  $vC[1],  $vA[4][1]
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                    SEP
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                     SEP      bcax_m0 $vA[4][4], $vA_[4][4], $vA_[4][1], $vA_[4][0]
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                     SEP      eor2    $vC[2],  $vC[2],  $vA[4][2]
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                     SEP      eor2    $vC[3],  $vC[3],  $vA[4][3]
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                    SEP      bcax_m1 $vA[0][0], $vA_[0][0], $vA_[0][2], $vA_[0][1]
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                     SEP      bcax_m0 $vA[0][1], $vA_[0][1], $vA_[0][3], $vA_[0][2]
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                    SEP
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                     SEP
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                    SEP      eor2    $vC[1],  $vC[1],  $vA[0][1]
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                     SEP      restore x26, STACK_OFFSET_CONST_VEC 
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                    SEP      ldr vvtmpq, [x26], #16
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                     SEP      save x26, STACK_OFFSET_CONST_VEC 
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                    SEP      eor $vA[0][0].16b, $vA[0][0].16b, vvtmp.16b
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                     SEP      eor2    $vC[4],  $vC[4],  $vA[4][4]
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                    SEP
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                     SEP      bcax_m0 $vA[0][2], $vA_[0][2], $vA_[0][4], $vA_[0][3]
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                    SEP      bcax_m1 $vA[0][3], $vA_[0][3], $vA_[0][0], $vA_[0][4]
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                     SEP      eor2    $vC[3],  $vC[3],  $vA[0][3]
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                    SEP      eor2    $vC[2],  $vC[2],  $vA[0][2]
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                     SEP      eor2    $vC[0],  $vC[0],  $vA[0][0]
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                     SEP
ldr $count, [sp, #STACK_OFFSET_COUNT]                       SEP      bcax_m0 $vA[0][4], $vA_[0][4], $vA_[0][1], $vA_[0][0]
load_constant_ptr_stack                                     SEP      eor2    $vC[4],  $vC[4],  $vA[0][4]
ldr $cur_const, [$const_addr, $count, UXTW #3]              SEP      ldr $vAq[1][0], [sp, #(vAga_offset)]
add $count, $count, #1                                      SEP      .unreq vvtmp
str $count , [sp , #STACK_OFFSET_COUNT]                     SEP      .unreq vvtmpq
eor $A[0][0], $A[0][0], $cur_const                          SEP      vvtmp .req $vA_[0][0]
eor $C[4], $A[2][4], $A[1][4], ROR #50                      SEP      rax1_m0 $vE[2], $vC[1], $vC[3]
eor $C[4], $C[4], $A[3][4], ROR #34                         SEP      rax1_m1 $vE[4], $vC[3], $vC[0]
eor $C[1], $A[2][1], $A[3][1], ROR #57                      SEP      rax1_m0 $vE[1], $vC[0], $vC[2]
eor $C[4], $C[4], $A[0][4], ROR #26                         SEP      rax1_m1 $vE[3], $vC[2], $vC[4]
eor $C[0], $A[0][0], $A[1][0], ROR #61                      SEP      rax1_m0 $vE[0], $vC[4], $vC[1]
eor $C[4], $C[4], $A[4][4], ROR #15                         SEP
str x27, [sp, #STACK_OFFSET_x27_A44]                        SEP      .unreq vvtmp
eor $C[2], $A[4][2], $A[0][2], ROR #52                      SEP      vvtmp .req $vC[1]
eor $C[3], $A[0][3], $A[2][3], ROR #63                      SEP      vvtmpq .req  $vCq[1]
eor $C[2], $C[2], $A[2][2], ROR #48                         SEP      eor $vA_[0][0].16b, $vA[0][0].16b, $vE[0].16b
eor $C[0], $C[0], $A[3][0], ROR #54                         SEP      xar_m1 $vA_[4][0], $vA[0][2], $vE[2], 2
eor $C[1], $C[1], $A[0][1], ROR #51                         SEP
eor $C[3], $C[3], $A[3][3], ROR #37                         SEP      xar_m0 $vA_[0][2], $vA[2][2], $vE[2], #21
eor $C[2], $C[2], $A[3][2], ROR #10                         SEP      xar_m1 $vA_[2][2], $vA[2][3], $vE[3], 39
eor $C[0], $C[0], $A[2][0], ROR #39                         SEP      xar_m0 $vA_[2][3], $vA[3][4], $vE[4], #56
eor $C[1], $C[1], $A[4][1], ROR #31                         SEP      xar_m1 $vA_[3][4], $vA[4][3], $vE[3], 8
eor $C[3], $C[3], $A[1][3], ROR #36                         SEP      xar_m0 $vA_[4][3], $vA[3][0], $vE[0], #23
eor $C[2], $C[2], $A[1][2], ROR #5                          SEP      xar_m1 $vA_[2][0], $vA[0][1], $vE[1], 63
eor $C[0], $C[0], $A[4][0], ROR #25                         SEP
eor $C[1], $C[1], $A[1][1], ROR #27                         SEP      xar_m0 $vA_[4][1], $vA[1][3], $vE[3], #9
eor $C[3], $C[3], $A[4][3], ROR #2                          SEP      xar_m1 $vA_[1][3], $vA[3][1], $vE[1], 19
eor $E[1], $C[0], $C[2], ROR #61                            SEP      xar_m0 $vA_[2][1], $vA[1][2], $vE[2], #58
ror $C[2], $C[2], 62                                        SEP      xar_m1 $vA_[1][2], $vA[2][0], $vE[0], 61
eor $E[3], $C[2], $C[4], ROR #57                            SEP      xar_m0 $vA_[1][0], $vA[0][3], $vE[3], #36
ror $C[4], $C[4], 58                                        SEP 
eor $E[0], $C[4], $C[1], ROR #55                            SEP      xar_m1 $vA_[0][3], $vA[3][3], $vE[3], 43
ror $C[1], $C[1], 56                                        SEP      xar_m0 $vA_[3][3], $vA[3][2], $vE[2], #49
eor $E[2], $C[1], $C[3], ROR #63                            SEP      xar_m1 $vA_[3][2], $vA[2][1], $vE[1], 54
eor $E[4], $C[3], $C[0], ROR #63                            SEP      xar_m0 $vA_[1][1], $vA[1][4], $vE[4], #44
eor $A_[0][0], $E[0], $A[0][0]                              SEP      mov $vE[3].16b, $vA[1][0].16b
eor $A_[4][0], $E[2], $A[0][2], ROR #50                     SEP      bcax_m1 $vA[1][0], $vA_[1][0], $vA_[1][2], $vA_[1][1]
eor $A_[0][2], $E[2], $A[2][2], ROR #46                     SEP
eor $A_[2][2], $E[3], $A[2][3], ROR #63                     SEP      xar_m0 $vA_[1][4], $vA[4][2], $vE[2], #3
eor $A_[2][3], $E[4], $A[3][4], ROR #28                     SEP      xar_m1 $vA_[4][2], $vA[2][4], $vE[4], 25
eor $A_[3][4], $E[3], $A[4][3], ROR #2                      SEP      xar_m0 $vA_[2][4], $vA[4][0], $vE[0], #46
eor $A_[4][3], $E[0], $A[3][0], ROR #54                     SEP      xar_m1 $vA_[3][0], $vA[0][4], $vE[4], 37
eor $A_[2][0], $E[1], $A[0][1], ROR #43                     SEP      xar_m0 $vA_[0][4], $vA[4][4], $vE[4], #50
eor $A_[4][1], $E[3], $A[1][3], ROR #36                     SEP
eor $A_[1][3], $E[1], $A[3][1], ROR #49                     SEP      xar_m1 $vA_[4][4], $vA[4][1], $vE[1], 62
eor $A_[2][1], $E[2], $A[1][2], ROR #3                      SEP      xar_m0 $vA_[3][1], $vE[3], $vE[0], #28
eor $A_[1][2], $E[0], $A[2][0], ROR #39                     SEP      xar_m1 $vA_[0][1], $vA[1][1], $vE[1], 20
eor $A_[1][0], $E[3], $A[0][3]                              SEP      bcax_m1 $vA[1][1], $vA_[1][1], $vA_[1][3], $vA_[1][2]
eor $A_[0][3], $E[3], $A[3][3], ROR #37                     SEP      bcax_m0 $vA[1][2], $vA_[1][2], $vA_[1][4], $vA_[1][3]
eor $A_[3][3], $E[2], $A[3][2], ROR #8                      SEP
eor $A_[3][2], $E[1], $A[2][1], ROR #56                     SEP      bcax_m1 $vA[1][3], $vA_[1][3], $vA_[1][0], $vA_[1][4]
eor $A_[1][1], $E[4], $A[1][4], ROR #44                     SEP      bcax_m0 $vA[1][4], $vA_[1][4], $vA_[1][1], $vA_[1][0]
eor $A_[1][4], $E[2], $A[4][2], ROR #62                     SEP      bcax_m1 $vA[2][0], $vA_[2][0], $vA_[2][2], $vA_[2][1]
eor $A_[4][2], $E[4], $A[2][4], ROR #58                     SEP      bcax_m0 $vA[2][1], $vA_[2][1], $vA_[2][3], $vA_[2][2]
eor $A_[2][4], $E[0], $A[4][0], ROR #25                     SEP      .unreq vvtmp
eor $A_[3][0], $E[4], $A[0][4], ROR #20                     SEP      .unreq vvtmpq
ldr x27, [sp, #STACK_OFFSET_x27_A44]                        SEP
eor $A_[0][4], $E[4], $A[4][4], ROR #9                      SEP      eor2    $vC[0],  $vA[2][0], $vA[1][0]
eor $A_[4][4], $E[1], $A[4][1], ROR #23                     SEP      str $vAq[1][0], [sp, #(vAga_offset)]
eor $A_[3][1], $E[0], $A[1][0], ROR #61                     SEP      vvtmp .req $vA[1][0]
eor $A_[0][1], $E[1], $A[1][1], ROR #19                     SEP      vvtmpq .req $vAq[1][0]
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                    SEP      bcax_m1 $vA[2][2], $vA_[2][2], $vA_[2][4], $vA_[2][3]
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                    SEP
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                     SEP      bcax_m1 $vA[2][3], $vA_[2][3], $vA_[2][0], $vA_[2][4]
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                    SEP      eor2    $vC[1],  $vA[2][1], $vA[1][1]
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                     SEP      bcax_m0 $vA[2][4], $vA_[2][4], $vA_[2][1], $vA_[2][0]
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                    SEP      eor2    $vC[2],  $vA[2][2], $vA[1][2]
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                     SEP      bcax_m1 $vA[3][0], $vA_[3][0], $vA_[3][2], $vA_[3][1]
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                    SEP      eor2    $vC[3],  $vA[2][3], $vA[1][3]
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                     SEP
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                    SEP      bcax_m0 $vA[3][1], $vA_[3][1], $vA_[3][3], $vA_[3][2]
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                     SEP      eor2    $vC[4],  $vA[2][4], $vA[1][4]
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                    SEP      bcax_m1 $vA[3][2], $vA_[3][2], $vA_[3][4], $vA_[3][3]
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                     SEP      eor2    $vC[0],  $vC[0],  $vA[3][0]
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                    SEP      bcax_m0 $vA[3][3], $vA_[3][3], $vA_[3][0], $vA_[3][4]
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                      SEP
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                    SEP      eor2    $vC[1],  $vC[1],  $vA[3][1]
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                     SEP      bcax_m1 $vA[3][4], $vA_[3][4], $vA_[3][1], $vA_[3][0]
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                     SEP      eor2    $vC[2],  $vC[2],  $vA[3][2]
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                     SEP      bcax_m0 $vA[4][0], $vA_[4][0], $vA_[4][2], $vA_[4][1]
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                    SEP      eor2    $vC[3],  $vC[3],  $vA[3][3]
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                     SEP
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                     SEP      bcax_m1 $vA[4][1], $vA_[4][1], $vA_[4][3], $vA_[4][2]
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                     SEP      eor2    $vC[4],  $vC[4],  $vA[3][4]
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                    SEP      bcax_m0 $vA[4][2], $vA_[4][2], $vA_[4][4], $vA_[4][3]
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                     SEP      eor2    $vC[0],  $vC[0],  $vA[4][0]
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                    SEP      bcax_m1 $vA[4][3], $vA_[4][3], $vA_[4][0], $vA_[4][4]
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                     SEP      eor2    $vC[1],  $vC[1],  $vA[4][1]
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                     SEP      bcax_m0 $vA[4][4], $vA_[4][4], $vA_[4][1], $vA_[4][0]
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                     SEP      eor2    $vC[2],  $vC[2],  $vA[4][2]
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                    SEP      eor2    $vC[3],  $vC[3],  $vA[4][3]
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                     SEP      bcax_m1 $vA[0][0], $vA_[0][0], $vA_[0][2], $vA_[0][1]
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                     SEP      bcax_m0 $vA[0][1], $vA_[0][1], $vA_[0][3], $vA_[0][2]
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                     SEP
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                    SEP      eor2    $vC[1],  $vC[1],  $vA[0][1]
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                     SEP      restore x26, STACK_OFFSET_CONST_VEC
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                    SEP      ldr vvtmpq, [x26], #16
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                     SEP      save x26, STACK_OFFSET_CONST_VEC
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                    SEP      eor $vA[0][0].16b, $vA[0][0].16b, vvtmp.16b
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                     SEP      eor2    $vC[4],  $vC[4],  $vA[4][4]
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                    SEP
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                     SEP
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                    SEP
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                     SEP      bcax_m0 $vA[0][2], $vA_[0][2], $vA_[0][4], $vA_[0][3]
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                    SEP      bcax_m1 $vA[0][3], $vA_[0][3], $vA_[0][0], $vA_[0][4]
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                     SEP      eor2    $vC[3],  $vC[3],  $vA[0][3]
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                    SEP      eor2    $vC[2],  $vC[2],  $vA[0][2]
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                     SEP      eor2    $vC[0],  $vC[0],  $vA[0][0]
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                    SEP
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                     SEP      bcax_m0 $vA[0][4], $vA_[0][4], $vA_[0][1], $vA_[0][0]
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                     SEP      eor2    $vC[4],  $vC[4],  $vA[0][4]
ldr $count, [sp, #STACK_OFFSET_COUNT]                       SEP      ldr $vAq[1][0], [sp, #(vAga_offset)]
load_constant_ptr_stack                                     SEP      .unreq vvtmp
ldr $cur_const, [$const_addr, $count, UXTW #3]              SEP      .unreq vvtmpq
add $count, $count, #1                                    
str $count , [sp , #STACK_OFFSET_COUNT]                
eor $A[0][0], $A[0][0], $cur_const                     
.endm


.macro  hybrid_round_final
eor $C[4], $A[2][4], $A[1][4], ROR #50                      SEP
eor $C[4], $C[4], $A[3][4], ROR #34                         SEP      vvtmp .req $vA_[0][0]
eor $C[1], $A[2][1], $A[3][1], ROR #57                      SEP      rax1_m0 $vE[2], $vC[1], $vC[3]
eor $C[4], $C[4], $A[0][4], ROR #26                         SEP
eor $C[0], $A[0][0], $A[1][0], ROR #61                      SEP      rax1_m1 $vE[4], $vC[3], $vC[0]
eor $C[4], $C[4], $A[4][4], ROR #15                         SEP      rax1_m0 $vE[1], $vC[0], $vC[2]
str x27, [sp, #STACK_OFFSET_x27_A44]                        SEP
eor $C[2], $A[4][2], $A[0][2], ROR #52                      SEP      rax1_m1 $vE[3], $vC[2], $vC[4]
eor $C[3], $A[0][3], $A[2][3], ROR #63                      SEP      rax1_m0 $vE[0], $vC[4], $vC[1]
eor $C[2], $C[2], $A[2][2], ROR #48                         SEP
eor $C[0], $C[0], $A[3][0], ROR #54                         SEP      .unreq vvtmp
eor $C[1], $C[1], $A[0][1], ROR #51                         SEP      vvtmp .req $vC[1]
eor $C[3], $C[3], $A[3][3], ROR #37                         SEP
eor $C[2], $C[2], $A[3][2], ROR #10                         SEP      vvtmpq .req  $vCq[1]
eor $C[0], $C[0], $A[2][0], ROR #39                         SEP      eor $vA_[0][0].16b, $vA[0][0].16b, $vE[0].16b
eor $C[1], $C[1], $A[4][1], ROR #31                         SEP
eor $C[3], $C[3], $A[1][3], ROR #36                         SEP      xar_m1 $vA_[4][0], $vA[0][2], $vE[2], 2
eor $C[2], $C[2], $A[1][2], ROR #5                          SEP      xar_m0 $vA_[0][2], $vA[2][2], $vE[2], #21
eor $C[0], $C[0], $A[4][0], ROR #25                         SEP
eor $C[1], $C[1], $A[1][1], ROR #27                         SEP      xar_m1 $vA_[2][2], $vA[2][3], $vE[3], 39
eor $C[3], $C[3], $A[4][3], ROR #2                          SEP      xar_m0 $vA_[2][3], $vA[3][4], $vE[4], #56
eor $E[1], $C[0], $C[2], ROR #61                            SEP
ror $C[2], $C[2], 62                                        SEP      xar_m1 $vA_[3][4], $vA[4][3], $vE[3], 8
eor $E[3], $C[2], $C[4], ROR #57                            SEP      xar_m0 $vA_[4][3], $vA[3][0], $vE[0], #23
ror $C[4], $C[4], 58                                        SEP
eor $E[0], $C[4], $C[1], ROR #55                            SEP      xar_m1 $vA_[2][0], $vA[0][1], $vE[1], 63
ror $C[1], $C[1], 56                                        SEP      xar_m0 $vA_[4][1], $vA[1][3], $vE[3], #9
eor $E[2], $C[1], $C[3], ROR #63                            SEP
eor $E[4], $C[3], $C[0], ROR #63                            SEP      xar_m1 $vA_[1][3], $vA[3][1], $vE[1], 19
eor $A_[0][0], $E[0], $A[0][0]                              SEP      xar_m0 $vA_[2][1], $vA[1][2], $vE[2], #58
eor $A_[4][0], $E[2], $A[0][2], ROR #50                     SEP
eor $A_[0][2], $E[2], $A[2][2], ROR #46                     SEP      xar_m1 $vA_[1][2], $vA[2][0], $vE[0], 61
eor $A_[2][2], $E[3], $A[2][3], ROR #63                     SEP
eor $A_[2][3], $E[4], $A[3][4], ROR #28                     SEP      xar_m0 $vA_[1][0], $vA[0][3], $vE[3], #36
eor $A_[3][4], $E[3], $A[4][3], ROR #2                      SEP      xar_m1 $vA_[0][3], $vA[3][3], $vE[3], 43
eor $A_[4][3], $E[0], $A[3][0], ROR #54                     SEP
eor $A_[2][0], $E[1], $A[0][1], ROR #43                     SEP      xar_m0 $vA_[3][3], $vA[3][2], $vE[2], #49
eor $A_[4][1], $E[3], $A[1][3], ROR #36                     SEP      xar_m1 $vA_[3][2], $vA[2][1], $vE[1], 54
eor $A_[1][3], $E[1], $A[3][1], ROR #49                     SEP
eor $A_[2][1], $E[2], $A[1][2], ROR #3                      SEP      xar_m0 $vA_[1][1], $vA[1][4], $vE[4], #44
eor $A_[1][2], $E[0], $A[2][0], ROR #39                     SEP      mov $vE[3].16b, $vA[1][0].16b
eor $A_[1][0], $E[3], $A[0][3]                              SEP
eor $A_[0][3], $E[3], $A[3][3], ROR #37                     SEP      bcax_m1 $vA[1][0], $vA_[1][0], $vA_[1][2], $vA_[1][1]
eor $A_[3][3], $E[2], $A[3][2], ROR #8                      SEP      xar_m0 $vA_[1][4], $vA[4][2], $vE[2], #3
eor $A_[3][2], $E[1], $A[2][1], ROR #56                     SEP
eor $A_[1][1], $E[4], $A[1][4], ROR #44                     SEP      xar_m1 $vA_[4][2], $vA[2][4], $vE[4], 25
eor $A_[1][4], $E[2], $A[4][2], ROR #62                     SEP      xar_m0 $vA_[2][4], $vA[4][0], $vE[0], #46
eor $A_[4][2], $E[4], $A[2][4], ROR #58                     SEP
eor $A_[2][4], $E[0], $A[4][0], ROR #25                     SEP      xar_m1 $vA_[3][0], $vA[0][4], $vE[4], 37
eor $A_[3][0], $E[4], $A[0][4], ROR #20                     SEP      xar_m0 $vA_[0][4], $vA[4][4], $vE[4], #50
ldr x27, [sp, #STACK_OFFSET_x27_A44]                        SEP
eor $A_[0][4], $E[4], $A[4][4], ROR #9                      SEP      xar_m1 $vA_[4][4], $vA[4][1], $vE[1], 62
eor $A_[4][4], $E[1], $A[4][1], ROR #23                     SEP      xar_m0 $vA_[3][1], $vE[3], $vE[0], #28
eor $A_[3][1], $E[0], $A[1][0], ROR #61                     SEP
eor $A_[0][1], $E[1], $A[1][1], ROR #19                     SEP      xar_m1 $vA_[0][1], $vA[1][1], $vE[1], 20
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                    SEP      bcax_m1 $vA[1][1], $vA_[1][1], $vA_[1][3], $vA_[1][2]
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                    SEP
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                     SEP      bcax_m0 $vA[1][2], $vA_[1][2], $vA_[1][4], $vA_[1][3]
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                    SEP      bcax_m1 $vA[1][3], $vA_[1][3], $vA_[1][0], $vA_[1][4]
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                     SEP
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                    SEP      bcax_m0 $vA[1][4], $vA_[1][4], $vA_[1][1], $vA_[1][0]
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                     SEP
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                    SEP      bcax_m1 $vA[2][0], $vA_[2][0], $vA_[2][2], $vA_[2][1]
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                     SEP      bcax_m0 $vA[2][1], $vA_[2][1], $vA_[2][3], $vA_[2][2]
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                    SEP
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                     SEP      .unreq vvtmp
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                    SEP      .unreq vvtmpq
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                     SEP
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                    SEP      eor2    $vC[0],  $vA[2][0], $vA[1][0]
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                      SEP      str $vAq[1][0], [sp, #(vAga_offset)]
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                    SEP
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                     SEP      vvtmp .req $vA[1][0]
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                     SEP      vvtmpq .req $vAq[1][0]
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                     SEP
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                    SEP      bcax_m0 $vA[2][2], $vA_[2][2], $vA_[2][4], $vA_[2][3]
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                     SEP      bcax_m1 $vA[2][3], $vA_[2][3], $vA_[2][0], $vA_[2][4]
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                     SEP
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                     SEP      eor2    $vC[1],  $vA[2][1], $vA[1][1]
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                    SEP      bcax_m0 $vA[2][4], $vA_[2][4], $vA_[2][1], $vA_[2][0]
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                     SEP
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                    SEP      eor2    $vC[2],  $vA[2][2], $vA[1][2]
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                     SEP      bcax_m1 $vA[3][0], $vA_[3][0], $vA_[3][2], $vA_[3][1]
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                     SEP
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                     SEP      eor2    $vC[3],  $vA[2][3], $vA[1][3]
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                    SEP      bcax_m0 $vA[3][1], $vA_[3][1], $vA_[3][3], $vA_[3][2]
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                     SEP
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                     SEP      eor2    $vC[4],  $vA[2][4], $vA[1][4]
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                     SEP      bcax_m1 $vA[3][2], $vA_[3][2], $vA_[3][4], $vA_[3][3]
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                    SEP
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                     SEP      eor2    $vC[0],  $vC[0],  $vA[3][0]
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                    SEP      bcax_m0 $vA[3][3], $vA_[3][3], $vA_[3][0], $vA_[3][4]
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                     SEP
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                    SEP      eor2    $vC[1],  $vC[1],  $vA[3][1]
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                     SEP
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                    SEP      bcax_m1 $vA[3][4], $vA_[3][4], $vA_[3][1], $vA_[3][0]
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                     SEP      eor2    $vC[2],  $vC[2],  $vA[3][2]
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                    SEP
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                     SEP      bcax_m0 $vA[4][0], $vA_[4][0], $vA_[4][2], $vA_[4][1]
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                    SEP      eor2    $vC[3],  $vC[3],  $vA[3][3]
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                     SEP
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                    SEP      bcax_m1 $vA[4][1], $vA_[4][1], $vA_[4][3], $vA_[4][2]
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                     SEP      eor2    $vC[4],  $vC[4],  $vA[3][4]
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                    SEP
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                     SEP      bcax_m0 $vA[4][2], $vA_[4][2], $vA_[4][4], $vA_[4][3]
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                     SEP      eor2    $vC[0],  $vC[0],  $vA[4][0]
ldr $count, [sp, #STACK_OFFSET_COUNT]                       SEP
load_constant_ptr_stack                                     SEP      bcax_m1 $vA[4][3], $vA_[4][3], $vA_[4][0], $vA_[4][4]
ldr $cur_const, [$const_addr, $count, UXTW #3]              SEP      eor2    $vC[1],  $vC[1],  $vA[4][1]
add $count, $count, #1                                      SEP
str $count , [sp , #STACK_OFFSET_COUNT]                     SEP      bcax_m0 $vA[4][4], $vA_[4][4], $vA_[4][1], $vA_[4][0]
eor $A[0][0], $A[0][0], $cur_const                          SEP      eor2    $vC[2],  $vC[2],  $vA[4][2]
eor $C[4], $A[2][4], $A[1][4], ROR #50                      SEP
eor $C[4], $C[4], $A[3][4], ROR #34                         SEP      eor2    $vC[3],  $vC[3],  $vA[4][3]
eor $C[1], $A[2][1], $A[3][1], ROR #57                      SEP      bcax_m1 $vA[0][0], $vA_[0][0], $vA_[0][2], $vA_[0][1]
eor $C[4], $C[4], $A[0][4], ROR #26                         SEP
eor $C[0], $A[0][0], $A[1][0], ROR #61                      SEP      bcax_m0 $vA[0][1], $vA_[0][1], $vA_[0][3], $vA_[0][2]
eor $C[4], $C[4], $A[4][4], ROR #15                         SEP      eor2    $vC[1],  $vC[1],  $vA[0][1]
str x27, [sp, #STACK_OFFSET_x27_A44]                        SEP
eor $C[2], $A[4][2], $A[0][2], ROR #52                      SEP      restore x0, STACK_OFFSET_CONST_VEC
eor $C[3], $A[0][3], $A[2][3], ROR #63                      SEP      ldr vvtmpq, [x0], #16
eor $C[2], $C[2], $A[2][2], ROR #48                         SEP
eor $C[0], $C[0], $A[3][0], ROR #54                         SEP      save x0, STACK_OFFSET_CONST_VEC
eor $C[1], $C[1], $A[0][1], ROR #51                         SEP
eor $C[3], $C[3], $A[3][3], ROR #37                         SEP      eor $vA[0][0].16b, $vA[0][0].16b, vvtmp.16b
eor $C[2], $C[2], $A[3][2], ROR #10                         SEP      eor2    $vC[4],  $vC[4],  $vA[4][4]
eor $C[0], $C[0], $A[2][0], ROR #39                         SEP
eor $C[1], $C[1], $A[4][1], ROR #31                         SEP      bcax_m0 $vA[0][2], $vA_[0][2], $vA_[0][4], $vA_[0][3]
eor $C[3], $C[3], $A[1][3], ROR #36                         SEP      bcax_m1 $vA[0][3], $vA_[0][3], $vA_[0][0], $vA_[0][4]
eor $C[2], $C[2], $A[1][2], ROR #5                          SEP
eor $C[0], $C[0], $A[4][0], ROR #25                         SEP      eor2    $vC[3],  $vC[3],  $vA[0][3]
eor $C[1], $C[1], $A[1][1], ROR #27                         SEP      eor2    $vC[2],  $vC[2],  $vA[0][2]
eor $C[3], $C[3], $A[4][3], ROR #2                          SEP
eor $E[1], $C[0], $C[2], ROR #61                            SEP      eor2    $vC[0],  $vC[0],  $vA[0][0]
ror $C[2], $C[2], 62                                        SEP      bcax_m0 $vA[0][4], $vA_[0][4], $vA_[0][1], $vA_[0][0]
eor $E[3], $C[2], $C[4], ROR #57                            SEP
ror $C[4], $C[4], 58                                        SEP      eor2    $vC[4],  $vC[4],  $vA[0][4]
eor $E[0], $C[4], $C[1], ROR #55                            SEP      ldr $vAq[1][0], [sp, #(vAga_offset)]
ror $C[1], $C[1], 56                                        SEP
eor $E[2], $C[1], $C[3], ROR #63                            SEP      .unreq vvtmp
eor $E[4], $C[3], $C[0], ROR #63                            SEP      .unreq vvtmpq
eor $A_[0][0], $E[0], $A[0][0]                              SEP
eor $A_[4][0], $E[2], $A[0][2], ROR #50                     SEP      vvtmp .req $vA_[0][0]
eor $A_[0][2], $E[2], $A[2][2], ROR #46                     SEP      rax1_m0 $vE[2], $vC[1], $vC[3]
eor $A_[2][2], $E[3], $A[2][3], ROR #63                     SEP
eor $A_[2][3], $E[4], $A[3][4], ROR #28                     SEP      rax1_m1 $vE[4], $vC[3], $vC[0]
eor $A_[3][4], $E[3], $A[4][3], ROR #2                      SEP      rax1_m0 $vE[1], $vC[0], $vC[2]
eor $A_[4][3], $E[0], $A[3][0], ROR #54                     SEP
eor $A_[2][0], $E[1], $A[0][1], ROR #43                     SEP      rax1_m1 $vE[3], $vC[2], $vC[4]
eor $A_[4][1], $E[3], $A[1][3], ROR #36                     SEP      rax1_m0 $vE[0], $vC[4], $vC[1]
eor $A_[1][3], $E[1], $A[3][1], ROR #49                     SEP
eor $A_[2][1], $E[2], $A[1][2], ROR #3                      SEP      .unreq vvtmp
eor $A_[1][2], $E[0], $A[2][0], ROR #39                     SEP
eor $A_[1][0], $E[3], $A[0][3]                              SEP      vvtmp .req $vC[1]
eor $A_[0][3], $E[3], $A[3][3], ROR #37                     SEP      vvtmpq .req  $vCq[1]
eor $A_[3][3], $E[2], $A[3][2], ROR #8                      SEP
eor $A_[3][2], $E[1], $A[2][1], ROR #56                     SEP      eor $vA_[0][0].16b, $vA[0][0].16b, $vE[0].16b
eor $A_[1][1], $E[4], $A[1][4], ROR #44                     SEP      xar_m1 $vA_[4][0], $vA[0][2], $vE[2], 2
eor $A_[1][4], $E[2], $A[4][2], ROR #62                     SEP
eor $A_[4][2], $E[4], $A[2][4], ROR #58                     SEP      xar_m0 $vA_[0][2], $vA[2][2], $vE[2], #21
eor $A_[2][4], $E[0], $A[4][0], ROR #25                     SEP      xar_m1 $vA_[2][2], $vA[2][3], $vE[3], 39
eor $A_[3][0], $E[4], $A[0][4], ROR #20                     SEP
ldr x27, [sp, #STACK_OFFSET_x27_A44]                        SEP      xar_m0 $vA_[2][3], $vA[3][4], $vE[4], #56
eor $A_[0][4], $E[4], $A[4][4], ROR #9                      SEP      xar_m1 $vA_[3][4], $vA[4][3], $vE[3], 8
eor $A_[4][4], $E[1], $A[4][1], ROR #23                     SEP
eor $A_[3][1], $E[0], $A[1][0], ROR #61                     SEP      xar_m0 $vA_[4][3], $vA[3][0], $vE[0], #23
eor $A_[0][1], $E[1], $A[1][1], ROR #19                     SEP      xar_m1 $vA_[2][0], $vA[0][1], $vE[1], 63
bic $tmp0, $A_[1][2], $A_[1][1], ROR #47                    SEP
bic $tmp1, $A_[1][3], $A_[1][2], ROR #42                    SEP      xar_m0 $vA_[4][1], $vA[1][3], $vE[3], #9
eor $A[1][0], $tmp0, $A_[1][0], ROR #39                     SEP      xar_m1 $vA_[1][3], $vA[3][1], $vE[1], 19
bic $tmp0, $A_[1][4], $A_[1][3], ROR #16                    SEP
eor $A[1][1], $tmp1, $A_[1][1], ROR #25                     SEP      xar_m0 $vA_[2][1], $vA[1][2], $vE[2], #58
bic $tmp1, $A_[1][0], $A_[1][4], ROR #31                    SEP      xar_m1 $vA_[1][2], $vA[2][0], $vE[0], 61
eor $A[1][2], $tmp0, $A_[1][2], ROR #58                     SEP
bic $tmp0, $A_[1][1], $A_[1][0], ROR #56                    SEP      xar_m0 $vA_[1][0], $vA[0][3], $vE[3], #36
eor $A[1][3], $tmp1, $A_[1][3], ROR #47                     SEP      xar_m1 $vA_[0][3], $vA[3][3], $vE[3], 43
bic $tmp1, $A_[2][2], $A_[2][1], ROR #19                    SEP
eor $A[1][4], $tmp0, $A_[1][4], ROR #23                     SEP      xar_m0 $vA_[3][3], $vA[3][2], $vE[2], #49
bic $tmp0, $A_[2][3], $A_[2][2], ROR #47                    SEP      xar_m1 $vA_[3][2], $vA[2][1], $vE[1], 54
eor $A[2][0], $tmp1, $A_[2][0], ROR #24                     SEP
bic $tmp1, $A_[2][4], $A_[2][3], ROR #10                    SEP      xar_m0 $vA_[1][1], $vA[1][4], $vE[4], #44
eor $A[2][1], $tmp0, $A_[2][1], ROR #2                      SEP      mov $vE[3].16b, $vA[1][0].16b
bic $tmp0, $A_[2][0], $A_[2][4], ROR #47                    SEP
eor $A[2][2], $tmp1, $A_[2][2], ROR #57                     SEP      bcax_m1 $vA[1][0], $vA_[1][0], $vA_[1][2], $vA_[1][1]
bic $tmp1, $A_[2][1], $A_[2][0], ROR #5                     SEP
eor $A[2][3], $tmp0, $A_[2][3], ROR #57                     SEP      xar_m0 $vA_[1][4], $vA[4][2], $vE[2], #3
bic $tmp0, $A_[3][2], $A_[3][1], ROR #38                    SEP      xar_m1 $vA_[4][2], $vA[2][4], $vE[4], 25
eor $A[2][4], $tmp1, $A_[2][4], ROR #52                     SEP
bic $tmp1, $A_[3][3], $A_[3][2], ROR #5                     SEP      xar_m0 $vA_[2][4], $vA[4][0], $vE[0], #46
eor $A[3][0], $tmp0, $A_[3][0], ROR #47                     SEP      xar_m1 $vA_[3][0], $vA[0][4], $vE[4], 37
bic $tmp0, $A_[3][4], $A_[3][3], ROR #41                    SEP
eor $A[3][1], $tmp1, $A_[3][1], ROR #43                     SEP      xar_m0 $vA_[0][4], $vA[4][4], $vE[4], #50
bic $tmp1, $A_[3][0], $A_[3][4], ROR #35                    SEP      xar_m1 $vA_[4][4], $vA[4][1], $vE[1], 62
eor $A[3][2], $tmp0, $A_[3][2], ROR #46                     SEP
bic $tmp0, $A_[3][1], $A_[3][0], ROR #9                     SEP      xar_m0 $vA_[3][1], $vE[3], $vE[0], #28
eor $A[3][3], $tmp1, $A_[3][3], ROR #12                     SEP      xar_m1 $vA_[0][1], $vA[1][1], $vE[1], 20
bic $tmp1, $A_[4][2], $A_[4][1], ROR #48                    SEP
eor $A[3][4], $tmp0, $A_[3][4], ROR #44                     SEP      bcax_m0 $vA[1][1], $vA_[1][1], $vA_[1][3], $vA_[1][2]
bic $tmp0, $A_[4][3], $A_[4][2], ROR #2                     SEP      bcax_m1 $vA[1][2], $vA_[1][2], $vA_[1][4], $vA_[1][3]
eor $A[4][0], $tmp1, $A_[4][0], ROR #41                     SEP
bic $tmp1, $A_[4][4], $A_[4][3], ROR #25                    SEP      bcax_m0 $vA[1][3], $vA_[1][3], $vA_[1][0], $vA_[1][4]
eor $A[4][1], $tmp0, $A_[4][1], ROR #50                     SEP      bcax_m1 $vA[1][4], $vA_[1][4], $vA_[1][1], $vA_[1][0]
bic $tmp0, $A_[4][0], $A_[4][4], ROR #60                    SEP
eor $A[4][2], $tmp1, $A_[4][2], ROR #27                     SEP      bcax_m0 $vA[2][0], $vA_[2][0], $vA_[2][2], $vA_[2][1]
bic $tmp1, $A_[4][1], $A_[4][0], ROR #57                    SEP      bcax_m1 $vA[2][1], $vA_[2][1], $vA_[2][3], $vA_[2][2]
eor $A[4][3], $tmp0, $A_[4][3], ROR #21                     SEP
bic $tmp0, $A_[0][2], $A_[0][1], ROR #63                    SEP      bcax_m0 $vA[2][2], $vA_[2][2], $vA_[2][4], $vA_[2][3]
eor $A[4][4], $tmp1, $A_[4][4], ROR #53                     SEP      bcax_m1 $vA[2][3], $vA_[2][3], $vA_[2][0], $vA_[2][4]
bic $tmp1, $A_[0][3], $A_[0][2], ROR #42                    SEP
eor $A[0][0], $A_[0][0], $tmp0, ROR #21                     SEP      bcax_m0 $vA[2][4], $vA_[2][4], $vA_[2][1], $vA_[2][0]
bic $tmp0, $A_[0][4], $A_[0][3], ROR #57                    SEP      bcax_m1 $vA[3][0], $vA_[3][0], $vA_[3][2], $vA_[3][1]
eor $A[0][1], $tmp1, $A_[0][1], ROR #41                     SEP
bic $tmp1, $A_[0][0], $A_[0][4], ROR #50                    SEP      bcax_m0 $vA[3][1], $vA_[3][1], $vA_[3][3], $vA_[3][2]
eor $A[0][2], $tmp0, $A_[0][2], ROR #35                     SEP
bic $tmp0, $A_[0][1], $A_[0][0], ROR #44                    SEP      bcax_m1 $vA[3][2], $vA_[3][2], $vA_[3][4], $vA_[3][3]
eor $A[0][3], $tmp1, $A_[0][3], ROR #43                     SEP      bcax_m0 $vA[3][3], $vA_[3][3], $vA_[3][0], $vA_[3][4]
eor $A[0][4], $tmp0, $A_[0][4], ROR #30                     SEP
ldr $count, [sp, #STACK_OFFSET_COUNT]                       SEP      bcax_m1 $vA[3][4], $vA_[3][4], $vA_[3][1], $vA_[3][0]
load_constant_ptr_stack                                     SEP      bcax_m0 $vA[4][0], $vA_[4][0], $vA_[4][2], $vA_[4][1]
ldr $cur_const, [$const_addr, $count, UXTW #3]              SEP
add $count, $count, #1                                      SEP      bcax_m1 $vA[4][1], $vA_[4][1], $vA_[4][3], $vA_[4][2]
str $count , [sp , #STACK_OFFSET_COUNT]                     SEP      bcax_m0 $vA[4][2], $vA_[4][2], $vA_[4][4], $vA_[4][3]
eor $A[0][0], $A[0][0], $cur_const                          SEP
ror $A[1][0], $A[1][0], #(64-3)                             SEP      bcax_m1 $vA[4][3], $vA_[4][3], $vA_[4][0], $vA_[4][4]
ror $A[0][4], $A[0][4], #(64-44)                            SEP      bcax_m0 $vA[4][4], $vA_[4][4], $vA_[4][1], $vA_[4][0]
ror $A[2][0], $A[2][0], #(64-25)                            SEP
ror $A[2][1], $A[2][1], #(64-8)                             SEP      bcax_m1 $vA[0][0], $vA_[0][0], $vA_[0][2], $vA_[0][1]
ror $A[3][0], $A[3][0], #(64-10)                            SEP      bcax_m0 $vA[0][1], $vA_[0][1], $vA_[0][3], $vA_[0][2]
ror $A[2][4], $A[2][4], #(64-6)                             SEP
ror $A[4][0], $A[4][0], #(64-39)                            SEP      bcax_m1 $vA[0][2], $vA_[0][2], $vA_[0][4], $vA_[0][3]
ror $A[4][1], $A[4][1], #(64-41)                            SEP      bcax_m0 $vA[0][3], $vA_[0][3], $vA_[0][0], $vA_[0][4]
ror $A[0][1], $A[0][1], #(64-21)                            SEP      
ror $A[1][1], $A[1][1], #(64-45)                            SEP      bcax_m1 $vA[0][4], $vA_[0][4], $vA_[0][1], $vA_[0][0]
ror $A[1][2], $A[1][2], #(64-61)                            SEP
ror $A[3][1], $A[3][1], #(64-15)                            SEP
ror $A[3][2], $A[3][2], #(64-56)                            SEP      restore x26, STACK_OFFSET_CONST_VEC
ror $A[0][2], $A[0][2], #(64-14)                            SEP      ldr vvtmpq, [x26], #16
ror $A[2][2], $A[2][2], #(64-18)                            SEP
ror $A[2][3], $A[2][3], #(64-1)                             SEP      save x26, STACK_OFFSET_CONST_VEC
ror $A[4][2], $A[4][2], #(64-2)                             SEP      eor $vA[0][0].16b, $vA[0][0].16b, vvtmp.16b
ror $A[4][3], $A[4][3], #(64-62)                            SEP   
ror $A[1][3], $A[1][3], #(64-28)                            SEP   
ror $A[1][4], $A[1][4], #(64-20)                            SEP     .unreq vvtmp
ror $A[3][3], $A[3][3], #(64-27)                            SEP     .unreq vvtmpq
ror $A[3][4], $A[3][4], #(64-36)                            SEP   
ror $A[4][4], $A[4][4], #(64-55)                            SEP      
.endm

.text
.align 4
.global keccak_f1600_x3_hybrid_asm_v6
.global _keccak_f1600_x3_hybrid_asm_v6

keccak_f1600_x3_hybrid_asm_v6:
_keccak_f1600_x3_hybrid_asm_v6:
    alloc_stack
    save_gprs
    save_vregs
    
    mov $input_addr, x0
    save $input_addr, STACK_OFFSET_INPUT
    load_input_vector
    add $input_addr, $input_addr, #16
    load_input_scalar

    adr $const_addr, round_constants_vec
    save $const_addr, STACK_OFFSET_CONST_VEC
     
    hybrid_round_initial
loop_0:
    hybrid_round_noninitial
    cmp $count, #(KECCAK_F1600_ROUNDS-3)
    ble loop_0

    hybrid_round_final

    restore $input_addr, STACK_OFFSET_INPUT
    store_input_vector
    add $input_addr, $input_addr, #16
    store_input_scalar

    restore_vregs
    restore_gprs
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