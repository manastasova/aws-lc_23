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
    $vAba = "v0";
    $vAbe = "v1";
    $vAbi = "v2";
    $vAbo = "v3";
    $vAbu = "v4";
    $vAga = "v5";
    $vAge = "v6";
    $vAgi = "v7";
    $vAgo = "v8";
    $vAgu = "v9";
    $vAka = "v10";
    $vAke = "v11";
    $vAki = "v12";
    $vAko = "v13";
    $vAku = "v14";
    $vAma = "v15";
    $vAme = "v16";
    $vAmi = "v17";
    $vAmo = "v18";
    $vAmu = "v19";
    $vAsa = "v20";
    $vAse = "v21";
    $vAsi = "v22";
    $vAso = "v23";
    $vAsu = "v24";

    $vAbaq = "q0";
    $vAbeq = "q1";
    $vAbiq = "q2";
    $vAboq = "q3";
    $vAbuq = "q4";
    $vAgaq = "q5";
    $vAgeq = "q6";
    $vAgiq = "q7";
    $vAgoq = "q8";
    $vAguq = "q9";
    $vAkaq = "q10";
    $vAkeq = "q11";
    $vAkiq = "q12";
    $vAkoq = "q13";
    $vAkuq = "q14";
    $vAmaq = "q15";
    $vAmeq = "q16";
    $vAmiq = "q17";
    $vAmoq = "q18";
    $vAmuq = "q19";
    $vAsaq = "q20";
    $vAseq = "q21";
    $vAsiq = "q22";
    $vAsoq = "q23";
    $vAsuq = "q24";

    $vC0 = "v30";
    $vC1 = "v29";
    $vC2 = "v28";
    $vC3 = "v27";
    $vC4 = "v26";

    $vE0 = "v26";
    $vE1 = "v25";
    $vE2 = "v29";
    $vE3 = "v28";
    $vE4 = "v27";

    $vAbi_ = "v2";
    $vAbo_ = "v3";
    $vAbu_ = "v4";
    $vAga_ = "v10";
    $vAge_ = "v11";
    $vAgi_ = "v7";
    $vAgo_ = "v8";
    $vAgu_ = "v9";
    $vAka_ = "v15";
    $vAke_ = "v16";
    $vAki_ = "v12";
    $vAko_ = "v13";
    $vAku_ = "v14";
    $vAma_ = "v20";
    $vAme_ = "v21";
    $vAmi_ = "v17";
    $vAmo_ = "v18";
    $vAmu_ = "v19";
    $vAsa_ = "v0";
    $vAse_ = "v1";
    $vAsi_ = "v22";
    $vAso_ = "v23";
    $vAsu_ = "v24";
    $vAba_ = "v30";
    $vAbe_ = "v27";

    $vtmp = "v31";

$code.=<<___;
#ifndef	__KERNEL__
# include <openssl/arm_arch.h>
#endif

#define SEP ;
#include <openssl/arm_arch.h>

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
								{{{

$code.=<<___;

/****************** REGISTER ALLOCATIONS *******************/

    input_addr     .req x0
    const_addr     .req x29
    count          .req w27
    cur_const      .req x26

    s_Aba     .req x1
    sAbe     .req x6
    sAbi     .req x11
    sAbo     .req x16
    sAbu     .req x21
    sAga     .req x2
    sAge     .req x7
    sAgi     .req x12
    sAgo     .req x17
    sAgu     .req x22
    sAka     .req x3
    sAke     .req x8
    sAki     .req x13
    sAko     .req x18
    sAku     .req x23
    sAma     .req x4
    sAme     .req x9
    sAmi     .req x14
    sAmo     .req x19
    sAmu     .req x24
    sAsa     .req x5
    sAse     .req x10
    sAsi     .req x15
    sAso     .req x20
    sAsu     .req x25

    /* sA_[y,2*x+3*y] = rot(A[x,y]) */
    s_Aba_ .req x0
    sAbe_ .req x28
    sAbi_ .req x11
    sAbo_ .req x16
    sAbu_ .req x21
    sAga_ .req x3
    sAge_ .req x8
    sAgi_ .req x12
    sAgo_ .req x17
    sAgu_ .req x22
    sAka_ .req x4
    sAke_ .req x9
    sAki_ .req x13
    sAko_ .req x18
    sAku_ .req x23
    sAma_ .req x5
    sAme_ .req x10
    sAmi_ .req x14
    sAmo_ .req x19
    sAmu_ .req x24
    sAsa_ .req x1
    sAse_ .req x6
    sAsi_ .req x15
    sAso_ .req x20
    sAsu_ .req x25

    /* sC[x] = sA[x,0] xor sA[x,1] xor sA[x,2] xor sA[x,3] xor sA[x,4],   for x in 0..4 */
    /* sE[x] = sC[x-1] xor rot(C[x+1],1), for x in 0..4 */
    sC0 .req x0
    sE0 .req x29
    sC1 .req x26
    sE1 .req x30
    sC2 .req x27
    sE2 .req x26
    sC3 .req x28
    sE3 .req x27
    sC4 .req x29
    sE4 .req x28

    tmp .req x30

/************************ MACROS ****************************/

/* Macros using v8.4-A SHA-3 instructions */

.macro eor3_m1 d s0 s1 s2
	eor \\d\\().16b, \\s0\\().16b, \\s1\\().16b
	eor \\d\\().16b, \\d\\().16b,  \\s2\\().16b
.endm

.macro rax1_m1 d s0 s1
   add $vtmp.2d, \\s1\\().2d, \\s1\\().2d
   sri $vtmp.2d, \\s1\\().2d, #63
   eor \\d\\().16b, $vtmp.16b, \\s0\\().16b
.endm

.macro xar_m1 d s0 s1 imm
   eor $vtmp.16b, \\s0\\().16b, \\s1\\().16b
   shl \\d\\().2d, $vtmp.2d, #(64-\\imm)
   sri \\d\\().2d, $vtmp.2d, #(\\imm)
.endm

.macro bcax_m1 d s0 s1 s2
    bic $vtmp.16b, \\s1\\().16b, \\s2\\().16b
    eor \\d\\().16b, $vtmp.16b, \\s0\\().16b
        .endm


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

.macro load_input_vector num idx
    ldr $vAbaq, [ input_addr, #(24*    0        )] 
    ldr $vAbeq, [ input_addr, #(24*    1        )]
    ldr $vAbiq, [ input_addr, #(24*    2        )]
    ldr $vAboq, [ input_addr, #(24*    3        )]
    ldr $vAbuq, [ input_addr, #(24*    4        )]  
    ldr $vAgaq, [ input_addr, #(24*    5        )]
    ldr $vAgeq, [ input_addr, #(24*    6        )]  
    ldr $vAgiq, [ input_addr, #(24*    7        )] 
    ldr $vAgoq, [ input_addr, #(24*    8        )]    
    ldr $vAguq, [ input_addr, #(24*    9        )]
      
    add input_addr, input_addr, #24*10
    ldr $vAkaq, [ input_addr, #(24*    0       )]
    ldr $vAkeq, [ input_addr, #(24*    1       )]
    ldr $vAkiq, [ input_addr, #(24*    2       )] 
    ldr $vAkoq, [ input_addr, #(24*    3       )]
    ldr $vAkuq, [ input_addr, #(24*    4       )] 
    ldr $vAmaq, [ input_addr, #(24*    5       )]
    ldr $vAmeq, [ input_addr, #(24*    6       )]   
    ldr $vAmiq, [ input_addr, #(24*    7       )]
    ldr $vAmoq, [ input_addr, #(24*    8       )]     
    ldr $vAmuq, [ input_addr, #(24*    9       )]
     
    add input_addr, input_addr, #24*10   
    ldr $vAsaq, [ input_addr, #(24*    0      )] 
    ldr $vAseq, [ input_addr, #(24*    1       )]
    ldr $vAsiq, [ input_addr, #(24*    2       )]   
    ldr $vAsoq, [ input_addr, #(24*    3       )]
    ldr $vAsuq, [ input_addr, #(24*    4       )]  
    sub input_addr, input_addr, #480       
.endm

.macro store_input_vector num idx
    str $vAbaq, [ input_addr, #(24*    0 )] 
    str $vAbeq, [ input_addr, #(24*    1 )] 
    str $vAbiq, [ input_addr, #(24*    2 )] 
    str $vAboq, [ input_addr, #(24*    3 )] 
    str $vAbuq, [ input_addr, #(24*    4 )] 
    str $vAgaq, [ input_addr, #(24*    5 )] 
    str $vAgeq, [ input_addr, #(24*    6 )] 
    str $vAgiq, [ input_addr, #(24*    7 )] 
    str $vAgoq, [ input_addr, #(24*    8 )] 
    str $vAguq, [ input_addr, #(24*    9 )] 
    add input_addr, input_addr, #24*10
    str $vAkaq, [ input_addr, #(24*    0       )]
    str $vAkeq, [ input_addr, #(24*    1       )]
    str $vAkiq, [ input_addr, #(24*    2       )] 
    str $vAkoq, [ input_addr, #(24*    3       )]
    str $vAkuq, [ input_addr, #(24*    4       )] 
    str $vAmaq, [ input_addr, #(24*    5       )]
    str $vAmeq, [ input_addr, #(24*    6       )]   
    str $vAmiq, [ input_addr, #(24*    7       )]
    str $vAmoq, [ input_addr, #(24*    8       )]     
    str $vAmuq, [ input_addr, #(24*    9       )] 
    add input_addr, input_addr, #24*10    
    str $vAsaq, [ input_addr, #(24*    0       )] 
    str $vAseq, [ input_addr, #(24*    1       )]
    str $vAsiq, [ input_addr, #(24*    2       )]   
    str $vAsoq, [ input_addr, #(24*    3       )]
    str $vAsuq, [ input_addr, #(24*    4       )]  
    sub input_addr, input_addr, #24*20       
.endm

.macro store_input_scalar num idx
    str s_Aba,[input_addr, 24*(0)]
    str sAbe, [input_addr, 24*(1)]
    str sAbi, [input_addr, 24*(2)]
    str sAbo, [input_addr, 24*(3)]
    str sAbu, [input_addr, 24*(4)]
    str sAga, [input_addr, 24*(5)]
    str sAge, [input_addr, 24*(6)]
    str sAgi, [input_addr, 24*(7)]
    str sAgo, [input_addr, 24*(8)]
    str sAgu, [input_addr, 24*(9)]
    str sAka, [input_addr, 24*(10)]
    str sAke, [input_addr, 24*(11)]
    str sAki, [input_addr, 24*(12)]
    str sAko, [input_addr, 24*(13)]
    str sAku, [input_addr, 24*(14)]
    str sAma, [input_addr, 24*(15)]
    str sAme, [input_addr, 24*(16)]
    str sAmi, [input_addr, 24*(17)]
    str sAmo, [input_addr, 24*(18)]
    str sAmu, [input_addr, 24*(19)]
    str sAsa, [input_addr, 24*(20)]
    str sAse, [input_addr, 24*(21)]
    str sAsi, [input_addr, 24*(22)]
    str sAso, [input_addr, 24*(23)]
    str sAsu, [input_addr, 24*(24)]
.endm

.macro load_input_scalar num idx
    ldr s_Aba, [input_addr,24*(0)]
    ldr sAbe, [input_addr, 24*(1)]
    ldr sAbi, [input_addr, 24*(2)]
    ldr sAbo, [input_addr, 24*(3)]
    ldr sAbu, [input_addr, 24*(4)]
    ldr sAga, [input_addr, 24*(5)]
    ldr sAge, [input_addr, 24*(6)]
    ldr sAgi, [input_addr, 24*(7)]
    ldr sAgo, [input_addr, 24*(8)]
    ldr sAgu, [input_addr, 24*(9)]
    ldr sAka, [input_addr, 24*(10)]
    ldr sAke, [input_addr, 24*(11)]
    ldr sAki, [input_addr, 24*(12)]
    ldr sAko, [input_addr, 24*(13)]
    ldr sAku, [input_addr, 24*(14)]
    ldr sAma, [input_addr, 24*(15)]
    ldr sAme, [input_addr, 24*(16)]
    ldr sAmi, [input_addr, 24*(17)]
    ldr sAmo, [input_addr, 24*(18)]
    ldr sAmu, [input_addr, 24*(19)]
    ldr sAsa, [input_addr, 24*(20)]
    ldr sAse, [input_addr, 24*(21)]
    ldr sAsi, [input_addr, 24*(22)]
    ldr sAso, [input_addr, 24*(23)]
    ldr sAsu, [input_addr, 24*(24)]
.endm

#define STACK_SIZE (4*16 + 8*12 + 4*8)
#define STACK_BASE_GPRS  (0)
#define STACK_BASE_VREGS (12*8)
#define STACK_BASE_TMP_GPRS (12*8 + 4*16)
#define STACK_OFFSET_INPUT (0*8)
#define STACK_OFFSET_CONST (1*8)
#define STACK_OFFSET_COUNT (2*8)

.macro save reg, offset
    str \\reg, [sp, #(STACK_BASE_TMP_GPRS + \\offset)]
.endm

.macro restore reg, offset
    ldr \\reg, [sp, #(STACK_BASE_TMP_GPRS + \\offset)]
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

.macro load_constant_ptr
	adr const_addr, round_constants
.endm

.macro hybrid_round_initial
eor sC0, sAma, sAsa                             SEP
eor sC1, sAme, sAse                             SEP      eor3_m1 $vC0, $vAba, $vAga, $vAka
eor sC2, sAmi, sAsi                             SEP      eor3_m1 $vC0, $vC0, $vAma,  $vAsa
eor sC3, sAmo, sAso                             SEP
eor sC4, sAmu, sAsu                             SEP      eor3_m1 $vC1, $vAbe, $vAge, $vAke
eor sC0, sAka, sC0                              SEP      eor3_m1 $vC1, $vC1, $vAme,  $vAse
eor sC1, sAke, sC1                              SEP
eor sC2, sAki, sC2                              SEP      eor3_m1 $vC2, $vAbi, $vAgi, $vAki
eor sC3, sAko, sC3                              SEP      eor3_m1 $vC2, $vC2, $vAmi,  $vAsi
eor sC4, sAku, sC4                              SEP
eor sC0, sAga, sC0                              SEP      eor3_m1 $vC3, $vAbo, $vAgo, $vAko
eor sC1, sAge, sC1                              SEP      eor3_m1 $vC3, $vC3, $vAmo,  $vAso
eor sC2, sAgi, sC2                              SEP
eor sC3, sAgo, sC3                              SEP      eor3_m1 $vC4, $vAbu, $vAgu, $vAku
eor sC4, sAgu, sC4                              SEP      eor3_m1 $vC4, $vC4, $vAmu,  $vAsu
eor sC0, s_Aba, sC0                             SEP
eor sC1, sAbe, sC1                              SEP      rax1_m1 $vE1, $vC0, $vC2
eor sC2, sAbi, sC2                              SEP      rax1_m1 $vE3, $vC2, $vC4
eor sC3, sAbo, sC3                              SEP
eor sC4, sAbu, sC4                              SEP      rax1_m1 $vE0, $vC4, $vC1
eor sE1, sC0, sC2, ROR #63                      SEP
eor sE3, sC2, sC4, ROR #63                      SEP      rax1_m1 $vE2, $vC1, $vC3
eor sE0, sC4, sC1, ROR #63                      SEP      rax1_m1 $vE4, $vC3, $vC0
eor sE2, sC1, sC3, ROR #63                      SEP
eor sE4, sC3, sC0, ROR #63                      SEP      eor $vAba_.16b, $vAba.16b, $vE0.16b
eor s_Aba_, s_Aba, sE0                          SEP      xar_m1 $vAsa_, $vAbi, $vE2, 2
eor sAsa_, sAbi, sE2                            SEP
eor sAbi_, sAki, sE2                            SEP      xar_m1 $vAbi_, $vAki, $vE2, 21
eor sAki_, sAko, sE3                            SEP      xar_m1 $vAki_, $vAko, $vE3, 39
eor sAko_, sAmu, sE4                            SEP
eor sAmu_, sAso, sE3                            SEP      xar_m1 $vAko_, $vAmu, $vE4, 56
eor sAso_, sAma, sE0                            SEP      xar_m1 $vAmu_, $vAso, $vE3, 8
eor sAka_, sAbe, sE1                            SEP
eor sAse_, sAgo, sE3                            SEP      xar_m1 $vAso_, $vAma, $vE0, 23
eor sAgo_, sAme, sE1                            SEP      xar_m1 $vAka_, $vAbe, $vE1, 63
eor sAke_, sAgi, sE2                            SEP
eor sAgi_, sAka, sE0                            SEP      xar_m1 $vAse_, $vAgo, $vE3, 9
eor sAga_, sAbo, sE3                            SEP
eor sAbo_, sAmo, sE3                            SEP      xar_m1 $vAgo_, $vAme, $vE1, 19
eor sAmo_, sAmi, sE2                            SEP      xar_m1 $vAke_, $vAgi, $vE2, 58
eor sAmi_, sAke, sE1                            SEP
eor sAge_, sAgu, sE4                            SEP      xar_m1 $vAgi_, $vAka, $vE0, 61
eor sAgu_, sAsi, sE2                            SEP      xar_m1 $vAga_, $vAbo, $vE3, 36
eor sAsi_, sAku, sE4                            SEP
eor sAku_, sAsa, sE0                            SEP      xar_m1 $vAbo_, $vAmo, $vE3, 43
eor sAma_, sAbu, sE4                            SEP      xar_m1 $vAmo_, $vAmi, $vE2, 49
eor sAbu_, sAsu, sE4                            SEP
eor sAsu_, sAse, sE1                            SEP      xar_m1 $vAmi_, $vAke, $vE1, 54
eor sAme_, sAga, sE0                            SEP      xar_m1 $vAge_, $vAgu, $vE4, 44
eor sAbe_, sAge, sE1                            SEP
load_constant_ptr                               SEP      xar_m1 $vAgu_, $vAsi, $vE2, 3
bic tmp, sAgi_, sAge_, ROR #47                  SEP      xar_m1 $vAsi_, $vAku, $vE4, 25
eor sAga, tmp,  sAga_, ROR #39                  SEP
bic tmp, sAgo_, sAgi_, ROR #42                  SEP      xar_m1 $vAku_, $vAsa, $vE0, 46
eor sAge, tmp,  sAge_, ROR #25                  SEP
bic tmp, sAgu_, sAgo_, ROR #16                  SEP      xar_m1 $vAma_, $vAbu, $vE4, 37
eor sAgi, tmp,  sAgi_, ROR #58                  SEP      xar_m1 $vAbu_, $vAsu, $vE4, 50
bic tmp, sAga_, sAgu_, ROR #31                  SEP
eor sAgo, tmp,  sAgo_, ROR #47                  SEP      xar_m1 $vAsu_, $vAse, $vE1, 62
bic tmp, sAge_, sAga_, ROR #56                  SEP      xar_m1 $vAme_, $vAga, $vE0, 28
eor sAgu, tmp,  sAgu_, ROR #23                  SEP
bic tmp, sAki_, sAke_, ROR #19                  SEP      xar_m1 $vAbe_, $vAge, $vE1, 20
eor sAka, tmp,  sAka_, ROR #24                  SEP      bcax_m1 $vAga, $vAga_, $vAgi_, $vAge_
bic tmp, sAko_, sAki_, ROR #47                  SEP
eor sAke, tmp,  sAke_, ROR #2                   SEP      bcax_m1 $vAge, $vAge_, $vAgo_, $vAgi_
bic tmp, sAku_, sAko_, ROR #10                  SEP      bcax_m1 $vAgi, $vAgi_, $vAgu_, $vAgo_
eor sAki, tmp,  sAki_, ROR #57                  SEP
bic tmp, sAka_, sAku_, ROR #47                  SEP      bcax_m1 $vAgo, $vAgo_, $vAga_, $vAgu_
eor sAko, tmp,  sAko_, ROR #57                  SEP      bcax_m1 $vAgu, $vAgu_, $vAge_, $vAga_
bic tmp, sAke_, sAka_, ROR #5                   SEP
eor sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m1 $vAka, $vAka_, $vAki_, $vAke_
bic tmp, sAmi_, sAme_, ROR #38                  SEP
eor sAma, tmp,  sAma_, ROR #47                  SEP      restore x26, STACK_OFFSET_CONST
bic tmp, sAmo_, sAmi_, ROR #5                   SEP      ld1r {v28.2d}, [x26], #8
eor sAme, tmp,  sAme_, ROR #43                  SEP      save x26, STACK_OFFSET_CONST
bic tmp, sAmu_, sAmo_, ROR #41                  SEP
eor sAmi, tmp,  sAmi_, ROR #46                  SEP      bcax_m1 $vAke, $vAke_, $vAko_, $vAki_
ldr cur_const, [const_addr]                     SEP      bcax_m1 $vAki, $vAki_, $vAku_, $vAko_
mov count, #1                                   SEP
bic tmp, sAma_, sAmu_, ROR #35                  SEP      bcax_m1 $vAko, $vAko_, $vAka_, $vAku_
eor sAmo, tmp,  sAmo_, ROR #12                  SEP      bcax_m1 $vAku, $vAku_, $vAke_, $vAka_
bic tmp, sAme_, sAma_, ROR #9                   SEP
eor sAmu, tmp,  sAmu_, ROR #44                  SEP
bic tmp, sAsi_, sAse_, ROR #48                  SEP      bcax_m1 $vAma, $vAma_, $vAmi_, $vAme_
eor sAsa, tmp,  sAsa_, ROR #41                  SEP      bcax_m1 $vAme, $vAme_, $vAmo_, $vAmi_
bic tmp, sAso_, sAsi_, ROR #2                   SEP      bcax_m1 $vAmi, $vAmi_, $vAmu_, $vAmo_
eor sAse, tmp,  sAse_, ROR #50                  SEP
bic tmp, sAsu_, sAso_, ROR #25                  SEP      bcax_m1 $vAmo, $vAmo_, $vAma_, $vAmu_
eor sAsi, tmp,  sAsi_, ROR #27                  SEP      bcax_m1 $vAmu, $vAmu_, $vAme_, $vAma_
bic tmp, sAsa_, sAsu_, ROR #60                  SEP
eor sAso, tmp,  sAso_, ROR #21                  SEP      bcax_m1 $vAsa, $vAsa_, $vAsi_, $vAse_
bic tmp, sAse_, sAsa_, ROR #57                  SEP
eor sAsu, tmp,  sAsu_, ROR #53                  SEP      bcax_m1 $vAse, $vAse_, $vAso_, $vAsi_
bic tmp, sAbi_, sAbe_, ROR #63                  SEP      bcax_m1 $vAsi, $vAsi_, $vAsu_, $vAso_
eor s_Aba, s_Aba_, tmp,  ROR #21                SEP
bic tmp, sAbo_, sAbi_, ROR #42                  SEP      bcax_m1 $vAso, $vAso_, $vAsa_, $vAsu_
eor sAbe, tmp,  sAbe_, ROR #41                  SEP      bcax_m1 $vAsu, $vAsu_, $vAse_, $vAsa_
bic tmp, sAbu_, sAbo_, ROR #57                  SEP
eor sAbi, tmp,  sAbi_, ROR #35                  SEP      bcax_m1 $vAba, $vAba_, $vAbi_, $vAbe_
bic tmp, s_Aba_, sAbu_, ROR #50                 SEP      bcax_m1 $vAbe, $vAbe_, $vAbo_, $vAbi_
eor sAbo, tmp,  sAbo_, ROR #43                  SEP
bic tmp, sAbe_, s_Aba_, ROR #44                 SEP      bcax_m1 $vAbi, $vAbi_, $vAbu_, $vAbo_
eor sAbu, tmp,  sAbu_, ROR #30                  SEP      bcax_m1 $vAbo, $vAbo_, $vAba_, $vAbu_
eor s_Aba, s_Aba, cur_const                     SEP
save count, STACK_OFFSET_COUNT                  SEP      bcax_m1 $vAbu, $vAbu_, $vAbe_, $vAba_
eor sC0, sAka, sAsa, ROR #50                    SEP      eor $vAba.16b, $vAba.16b, v28.16b
eor sC1, sAse, sAge, ROR #60                    SEP
eor sC2, sAmi, sAgi, ROR #59                    SEP      eor3_m1 $vC0, $vAba, $vAga, $vAka
eor sC3, sAgo, sAso, ROR #30                    SEP
eor sC4, sAbu, sAsu, ROR #53                    SEP      eor3_m1 $vC0, $vC0, $vAma,  $vAsa
eor sC0, sAma, sC0, ROR #49                     SEP      eor3_m1 $vC1, $vAbe, $vAge, $vAke
eor sC1, sAbe, sC1, ROR #44                     SEP
eor sC2, sAki, sC2, ROR #26                     SEP      eor3_m1 $vC1, $vC1, $vAme,  $vAse
eor sC3, sAmo, sC3, ROR #63                     SEP      eor3_m1 $vC2, $vAbi, $vAgi, $vAki
eor sC4, sAmu, sC4, ROR #56                     SEP
eor sC0, sAga, sC0, ROR #57                     SEP      eor3_m1 $vC2, $vC2, $vAmi,  $vAsi
eor sC1, sAme, sC1, ROR #58                     SEP      eor3_m1 $vC3, $vAbo, $vAgo, $vAko
eor sC2, sAbi, sC2, ROR #60                     SEP
eor sC3, sAko, sC3, ROR #38                     SEP      eor3_m1 $vC3, $vC3, $vAmo,  $vAso
eor sC4, sAgu, sC4, ROR #48                     SEP      eor3_m1 $vC4, $vAbu, $vAgu, $vAku
eor sC0, s_Aba, sC0, ROR #61                    SEP
eor sC1, sAke, sC1, ROR #57                     SEP      eor3_m1 $vC4, $vC4, $vAmu,  $vAsu
eor sC2, sAsi, sC2, ROR #52                     SEP      rax1_m1 $vE1, $vC0, $vC2
eor sC3, sAbo, sC3, ROR #63                     SEP
eor sC4, sAku, sC4, ROR #50                     SEP      rax1_m1 $vE3, $vC2, $vC4
ror sC1, sC1, 56                                SEP
ror sC4, sC4, 58                                SEP      rax1_m1 $vE0, $vC4, $vC1
ror sC2, sC2, 62                                SEP      rax1_m1 $vE2, $vC1, $vC3
eor sE1, sC0, sC2, ROR #63                      SEP
eor sE3, sC2, sC4, ROR #63                      SEP      rax1_m1 $vE4, $vC3, $vC0
eor sE0, sC4, sC1, ROR #63                      SEP      eor $vAba_.16b, $vAba.16b, $vE0.16b
eor sE2, sC1, sC3, ROR #63                      SEP
eor sE4, sC3, sC0, ROR #63                      SEP      xar_m1 $vAsa_, $vAbi, $vE2, 2
eor s_Aba_, sE0, s_Aba                          SEP      xar_m1 $vAbi_, $vAki, $vE2, 21
eor sAsa_, sE2, sAbi, ROR #50                   SEP
eor sAbi_, sE2, sAki, ROR #46                   SEP      xar_m1 $vAki_, $vAko, $vE3, 39
eor sAki_, sE3, sAko, ROR #63                   SEP      xar_m1 $vAko_, $vAmu, $vE4, 56
eor sAko_, sE4, sAmu, ROR #28                   SEP
eor sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 $vAmu_, $vAso, $vE3, 8
eor sAso_, sE0, sAma, ROR #54                   SEP      xar_m1 $vAso_, $vAma, $vE0, 23
eor sAka_, sE1, sAbe, ROR #43                   SEP
eor sAse_, sE3, sAgo, ROR #36                   SEP      xar_m1 $vAka_, $vAbe, $vE1, 63
eor sAgo_, sE1, sAme, ROR #49                   SEP
eor sAke_, sE2, sAgi, ROR #3                    SEP      xar_m1 $vAse_, $vAgo, $vE3, 9
eor sAgi_, sE0, sAka, ROR #39                   SEP      xar_m1 $vAgo_, $vAme, $vE1, 19
eor sAga_, sE3, sAbo                            SEP
eor sAbo_, sE3, sAmo, ROR #37                   SEP      xar_m1 $vAke_, $vAgi, $vE2, 58
eor sAmo_, sE2, sAmi, ROR #8                    SEP      xar_m1 $vAgi_, $vAka, $vE0, 61
eor sAmi_, sE1, sAke, ROR #56                   SEP
eor sAge_, sE4, sAgu, ROR #44                   SEP      xar_m1 $vAga_, $vAbo, $vE3, 36
eor sAgu_, sE2, sAsi, ROR #62                   SEP      xar_m1 $vAbo_, $vAmo, $vE3, 43
eor sAsi_, sE4, sAku, ROR #58                   SEP
eor sAku_, sE0, sAsa, ROR #25                   SEP      xar_m1 $vAmo_, $vAmi, $vE2, 49
eor sAma_, sE4, sAbu, ROR #20                   SEP      xar_m1 $vAmi_, $vAke, $vE1, 54
eor sAbu_, sE4, sAsu, ROR #9                    SEP
eor sAsu_, sE1, sAse, ROR #23                   SEP      xar_m1 $vAge_, $vAgu, $vE4, 44
eor sAme_, sE0, sAga, ROR #61                   SEP      xar_m1 $vAgu_, $vAsi, $vE2, 3
eor sAbe_, sE1, sAge, ROR #19                   SEP
load_constant_ptr                               SEP      xar_m1 $vAsi_, $vAku, $vE4, 25
restore count, STACK_OFFSET_COUNT               SEP      xar_m1 $vAku_, $vAsa, $vE0, 46
bic tmp, sAgi_, sAge_, ROR #47                  SEP
eor sAga, tmp,  sAga_, ROR #39                  SEP      xar_m1 $vAma_, $vAbu, $vE4, 37
bic tmp, sAgo_, sAgi_, ROR #42                  SEP
eor sAge, tmp,  sAge_, ROR #25                  SEP      xar_m1 $vAbu_, $vAsu, $vE4, 50
bic tmp, sAgu_, sAgo_, ROR #16                  SEP      xar_m1 $vAsu_, $vAse, $vE1, 62
eor sAgi, tmp,  sAgi_, ROR #58                  SEP
bic tmp, sAga_, sAgu_, ROR #31                  SEP      xar_m1 $vAme_, $vAga, $vE0, 28
eor sAgo, tmp,  sAgo_, ROR #47                  SEP      xar_m1 $vAbe_, $vAge, $vE1, 20
bic tmp, sAge_, sAga_, ROR #56                  SEP
eor sAgu, tmp,  sAgu_, ROR #23                  SEP      bcax_m1 $vAga, $vAga_, $vAgi_, $vAge_
bic tmp, sAki_, sAke_, ROR #19                  SEP      bcax_m1 $vAge, $vAge_, $vAgo_, $vAgi_
eor sAka, tmp,  sAka_, ROR #24                  SEP
bic tmp, sAko_, sAki_, ROR #47                  SEP      bcax_m1 $vAgi, $vAgi_, $vAgu_, $vAgo_
eor sAke, tmp,  sAke_, ROR #2                   SEP      bcax_m1 $vAgo, $vAgo_, $vAga_, $vAgu_
bic tmp, sAku_, sAko_, ROR #10                  SEP
eor sAki, tmp,  sAki_, ROR #57                  SEP      bcax_m1 $vAgu, $vAgu_, $vAge_, $vAga_
bic tmp, sAka_, sAku_, ROR #47                  SEP      bcax_m1 $vAka, $vAka_, $vAki_, $vAke_
eor sAko, tmp,  sAko_, ROR #57                  SEP
bic tmp, sAke_, sAka_, ROR #5                   SEP      bcax_m1 $vAke, $vAke_, $vAko_, $vAki_
eor sAku, tmp,  sAku_, ROR #52                  SEP
bic tmp, sAmi_, sAme_, ROR #38                  SEP      bcax_m1 $vAki, $vAki_, $vAku_, $vAko_
eor sAma, tmp,  sAma_, ROR #47                  SEP      bcax_m1 $vAko, $vAko_, $vAka_, $vAku_
bic tmp, sAmo_, sAmi_, ROR #5                   SEP
eor sAme, tmp,  sAme_, ROR #43                  SEP      bcax_m1 $vAku, $vAku_, $vAke_, $vAka_
bic tmp, sAmu_, sAmo_, ROR #41                  SEP      restore x26, STACK_OFFSET_CONST
eor sAmi, tmp,  sAmi_, ROR #46                  SEP      ld1r {v28.2d}, [x26], #8
bic tmp, sAma_, sAmu_, ROR #35                  SEP      save x26, STACK_OFFSET_CONST
ldr cur_const, [const_addr, count, UXTW #3]     SEP      bcax_m1 $vAme, $vAme_, $vAmo_, $vAmi_
eor sAmo, tmp,  sAmo_, ROR #12                  SEP      bcax_m1 $vAma, $vAma_, $vAmi_, $vAme_
bic tmp, sAme_, sAma_, ROR #9                   SEP
eor sAmu, tmp,  sAmu_, ROR #44                  SEP      bcax_m1 $vAmi, $vAmi_, $vAmu_, $vAmo_
bic tmp, sAsi_, sAse_, ROR #48                  SEP
eor sAsa, tmp,  sAsa_, ROR #41                  SEP
bic tmp, sAso_, sAsi_, ROR #2                   SEP      bcax_m1 $vAmo, $vAmo_, $vAma_, $vAmu_
eor sAse, tmp,  sAse_, ROR #50                  SEP
bic tmp, sAsu_, sAso_, ROR #25                  SEP      bcax_m1 $vAmu, $vAmu_, $vAme_, $vAma_
eor sAsi, tmp,  sAsi_, ROR #27                  SEP
bic tmp, sAsa_, sAsu_, ROR #60                  SEP      bcax_m1 $vAsa, $vAsa_, $vAsi_, $vAse_
eor sAso, tmp,  sAso_, ROR #21                  SEP      bcax_m1 $vAse, $vAse_, $vAso_, $vAsi_
bic tmp, sAse_, sAsa_, ROR #57                  SEP
eor sAsu, tmp,  sAsu_, ROR #53                  SEP      bcax_m1 $vAsi, $vAsi_, $vAsu_, $vAso_
bic tmp, sAbi_, sAbe_, ROR #63                  SEP      bcax_m1 $vAso, $vAso_, $vAsa_, $vAsu_
eor s_Aba, s_Aba_, tmp,  ROR #21                SEP
bic tmp, sAbo_, sAbi_, ROR #42                  SEP      bcax_m1 $vAsu, $vAsu_, $vAse_, $vAsa_
eor sAbe, tmp,  sAbe_, ROR #41                  SEP      bcax_m1 $vAba, $vAba_, $vAbi_, $vAbe_
bic tmp, sAbu_, sAbo_, ROR #57                  SEP
eor sAbi, tmp,  sAbi_, ROR #35                  SEP      bcax_m1 $vAbe, $vAbe_, $vAbo_, $vAbi_
bic tmp, s_Aba_, sAbu_, ROR #50                 SEP      bcax_m1 $vAbi, $vAbi_, $vAbu_, $vAbo_
eor sAbo, tmp,  sAbo_, ROR #43                  SEP
bic tmp, sAbe_, s_Aba_, ROR #44                 SEP      bcax_m1 $vAbo, $vAbo_, $vAba_, $vAbu_
eor sAbu, tmp,  sAbu_, ROR #30                  SEP      bcax_m1 $vAbu, $vAbu_, $vAbe_, $vAba_
add count, count, #1                            SEP
eor s_Aba, s_Aba, cur_const                     SEP      eor $vAba.16b, $vAba.16b, v28.16b
.endm


.macro  hybrid_round_noninitial
save count, STACK_OFFSET_COUNT                  SEP
eor sC0, sAka, sAsa, ROR #50                    SEP      eor3_m1 $vC0, $vAba, $vAga, $vAka
eor sC1, sAse, sAge, ROR #60                    SEP      eor3_m1 $vC0, $vC0, $vAma,  $vAsa
eor sC2, sAmi, sAgi, ROR #59                    SEP
eor sC3, sAgo, sAso, ROR #30                    SEP      eor3_m1 $vC1, $vAbe, $vAge, $vAke
eor sC4, sAbu, sAsu, ROR #53                    SEP      eor3_m1 $vC1, $vC1, $vAme,  $vAse
eor sC0, sAma, sC0, ROR #49                     SEP
eor sC1, sAbe, sC1, ROR #44                     SEP      eor3_m1 $vC2, $vAbi, $vAgi, $vAki
eor sC2, sAki, sC2, ROR #26                     SEP      eor3_m1 $vC2, $vC2, $vAmi,  $vAsi
eor sC3, sAmo, sC3, ROR #63                     SEP
eor sC4, sAmu, sC4, ROR #56                     SEP      eor3_m1 $vC3, $vAbo, $vAgo, $vAko
eor sC0, sAga, sC0, ROR #57                     SEP
eor sC1, sAme, sC1, ROR #58                     SEP      eor3_m1 $vC3, $vC3, $vAmo,  $vAso
eor sC2, sAbi, sC2, ROR #60                     SEP      eor3_m1 $vC4, $vAbu, $vAgu, $vAku
eor sC3, sAko, sC3, ROR #38                     SEP
eor sC4, sAgu, sC4, ROR #48                     SEP      eor3_m1 $vC4, $vC4, $vAmu,  $vAsu
eor sC0, s_Aba, sC0, ROR #61                    SEP      rax1_m1 $vE1, $vC0, $vC2
eor sC1, sAke, sC1, ROR #57                     SEP
eor sC2, sAsi, sC2, ROR #52                     SEP      rax1_m1 $vE3, $vC2, $vC4
eor sC3, sAbo, sC3, ROR #63                     SEP      rax1_m1 $vE0, $vC4, $vC1
eor sC4, sAku, sC4, ROR #50                     SEP
ror sC1, sC1, 56                                SEP      rax1_m1 $vE2, $vC1, $vC3
ror sC4, sC4, 58                                SEP
ror sC2, sC2, 62                                SEP      rax1_m1 $vE4, $vC3, $vC0
eor sE1, sC0, sC2, ROR #63                      SEP      eor $vAba_.16b, $vAba.16b, $vE0.16b
eor sE3, sC2, sC4, ROR #63                      SEP
eor sE0, sC4, sC1, ROR #63                      SEP      xar_m1 $vAsa_, $vAbi, $vE2, 2
eor sE2, sC1, sC3, ROR #63                      SEP      xar_m1 $vAbi_, $vAki, $vE2, 21
eor sE4, sC3, sC0, ROR #63                      SEP
eor s_Aba_, sE0, s_Aba                          SEP      xar_m1 $vAki_, $vAko, $vE3, 39
eor sAsa_, sE2, sAbi, ROR #50                   SEP
eor sAbi_, sE2, sAki, ROR #46                   SEP      xar_m1 $vAko_, $vAmu, $vE4, 56
eor sAki_, sE3, sAko, ROR #63                   SEP      xar_m1 $vAmu_, $vAso, $vE3, 8
eor sAko_, sE4, sAmu, ROR #28                   SEP
eor sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 $vAso_, $vAma, $vE0, 23
eor sAso_, sE0, sAma, ROR #54                   SEP      xar_m1 $vAka_, $vAbe, $vE1, 63
eor sAka_, sE1, sAbe, ROR #43                   SEP
eor sAse_, sE3, sAgo, ROR #36                   SEP      xar_m1 $vAse_, $vAgo, $vE3, 9
eor sAgo_, sE1, sAme, ROR #49                   SEP      xar_m1 $vAgo_, $vAme, $vE1, 19
eor sAke_, sE2, sAgi, ROR #3                    SEP
eor sAgi_, sE0, sAka, ROR #39                   SEP      xar_m1 $vAke_, $vAgi, $vE2, 58
eor sAga_, sE3, sAbo                            SEP
eor sAbo_, sE3, sAmo, ROR #37                   SEP      xar_m1 $vAgi_, $vAka, $vE0, 61
eor sAmo_, sE2, sAmi, ROR #8                    SEP      xar_m1 $vAga_, $vAbo, $vE3, 36
eor sAmi_, sE1, sAke, ROR #56                   SEP
eor sAge_, sE4, sAgu, ROR #44                   SEP      xar_m1 $vAbo_, $vAmo, $vE3, 43
eor sAgu_, sE2, sAsi, ROR #62                   SEP      xar_m1 $vAmo_, $vAmi, $vE2, 49
eor sAsi_, sE4, sAku, ROR #58                   SEP
eor sAku_, sE0, sAsa, ROR #25                   SEP      xar_m1 $vAmi_, $vAke, $vE1, 54
eor sAma_, sE4, sAbu, ROR #20                   SEP      xar_m1 $vAge_, $vAgu, $vE4, 44
eor sAbu_, sE4, sAsu, ROR #9                    SEP
eor sAsu_, sE1, sAse, ROR #23                   SEP      xar_m1 $vAgu_, $vAsi, $vE2, 3
eor sAme_, sE0, sAga, ROR #61                   SEP
eor sAbe_, sE1, sAge, ROR #19                   SEP      xar_m1 $vAsi_, $vAku, $vE4, 25
load_constant_ptr                               SEP      xar_m1 $vAku_, $vAsa, $vE0, 46
restore count, STACK_OFFSET_COUNT               SEP
bic tmp, sAgi_, sAge_, ROR #47                  SEP      xar_m1 $vAma_, $vAbu, $vE4, 37
eor sAga, tmp,  sAga_, ROR #39                  SEP      xar_m1 $vAbu_, $vAsu, $vE4, 50
bic tmp, sAgo_, sAgi_, ROR #42                  SEP
eor sAge, tmp,  sAge_, ROR #25                  SEP      xar_m1 $vAsu_, $vAse, $vE1, 62
bic tmp, sAgu_, sAgo_, ROR #16                  SEP
eor sAgi, tmp,  sAgi_, ROR #58                  SEP      xar_m1 $vAme_, $vAga, $vE0, 28
bic tmp, sAga_, sAgu_, ROR #31                  SEP      xar_m1 $vAbe_, $vAge, $vE1, 20
eor sAgo, tmp,  sAgo_, ROR #47                  SEP
bic tmp, sAge_, sAga_, ROR #56                  SEP      bcax_m1 $vAga, $vAga_, $vAgi_, $vAge_
eor sAgu, tmp,  sAgu_, ROR #23                  SEP      bcax_m1 $vAge, $vAge_, $vAgo_, $vAgi_
bic tmp, sAki_, sAke_, ROR #19                  SEP
eor sAka, tmp,  sAka_, ROR #24                  SEP      bcax_m1 $vAgi, $vAgi_, $vAgu_, $vAgo_
bic tmp, sAko_, sAki_, ROR #47                  SEP      bcax_m1 $vAgo, $vAgo_, $vAga_, $vAgu_
eor sAke, tmp,  sAke_, ROR #2                   SEP
bic tmp, sAku_, sAko_, ROR #10                  SEP      bcax_m1 $vAgu, $vAgu_, $vAge_, $vAga_
eor sAki, tmp,  sAki_, ROR #57                  SEP
bic tmp, sAka_, sAku_, ROR #47                  SEP      bcax_m1 $vAka, $vAka_, $vAki_, $vAke_
eor sAko, tmp,  sAko_, ROR #57                  SEP      bcax_m1 $vAke, $vAke_, $vAko_, $vAki_
bic tmp, sAke_, sAka_, ROR #5                   SEP
eor sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m1 $vAki, $vAki_, $vAku_, $vAko_
bic tmp, sAmi_, sAme_, ROR #38                  SEP      bcax_m1 $vAko, $vAko_, $vAka_, $vAku_
eor sAma, tmp,  sAma_, ROR #47                  SEP
bic tmp, sAmo_, sAmi_, ROR #5                   SEP      bcax_m1 $vAku, $vAku_, $vAke_, $vAka_
eor sAme, tmp,  sAme_, ROR #43                  SEP      bcax_m1 $vAma, $vAma_, $vAmi_, $vAme_
bic tmp, sAmu_, sAmo_, ROR #41                  SEP      restore x26, STACK_OFFSET_CONST
eor sAmi, tmp,  sAmi_, ROR #46                  SEP      ld1r {v28.2d}, [x26], #8
bic tmp, sAma_, sAmu_, ROR #35                  SEP      save x26, STACK_OFFSET_CONST
ldr cur_const, [const_addr, count, UXTW #3]     SEP
add count, count, #1                            SEP
eor sAmo, tmp,  sAmo_, ROR #12                  SEP      bcax_m1 $vAme, $vAme_, $vAmo_, $vAmi_
bic tmp, sAme_, sAma_, ROR #9                   SEP      bcax_m1 $vAmi, $vAmi_, $vAmu_, $vAmo_
eor sAmu, tmp,  sAmu_, ROR #44                  SEP
bic tmp, sAsi_, sAse_, ROR #48                  SEP
eor sAsa, tmp,  sAsa_, ROR #41                  SEP      bcax_m1 $vAmo, $vAmo_, $vAma_, $vAmu_
bic tmp, sAso_, sAsi_, ROR #2                   SEP
eor sAse, tmp,  sAse_, ROR #50                  SEP      bcax_m1 $vAmu, $vAmu_, $vAme_, $vAma_
bic tmp, sAsu_, sAso_, ROR #25                  SEP      bcax_m1 $vAsa, $vAsa_, $vAsi_, $vAse_
eor sAsi, tmp,  sAsi_, ROR #27                  SEP
bic tmp, sAsa_, sAsu_, ROR #60                  SEP      bcax_m1 $vAse, $vAse_, $vAso_, $vAsi_
eor sAso, tmp,  sAso_, ROR #21                  SEP      bcax_m1 $vAsi, $vAsi_, $vAsu_, $vAso_
bic tmp, sAse_, sAsa_, ROR #57                  SEP
eor sAsu, tmp,  sAsu_, ROR #53                  SEP      bcax_m1 $vAso, $vAso_, $vAsa_, $vAsu_
bic tmp, sAbi_, sAbe_, ROR #63                  SEP      bcax_m1 $vAsu, $vAsu_, $vAse_, $vAsa_
eor s_Aba, s_Aba_, tmp,  ROR #21                SEP
bic tmp, sAbo_, sAbi_, ROR #42                  SEP      bcax_m1 $vAba, $vAba_, $vAbi_, $vAbe_
eor sAbe, tmp,  sAbe_, ROR #41                  SEP
bic tmp, sAbu_, sAbo_, ROR #57                  SEP      bcax_m1 $vAbe, $vAbe_, $vAbo_, $vAbi_
eor sAbi, tmp,  sAbi_, ROR #35                  SEP      bcax_m1 $vAbi, $vAbi_, $vAbu_, $vAbo_
bic tmp, s_Aba_, sAbu_, ROR #50                 SEP
eor sAbo, tmp,  sAbo_, ROR #43                  SEP      bcax_m1 $vAbo, $vAbo_, $vAba_, $vAbu_
bic tmp, sAbe_, s_Aba_, ROR #44                 SEP      bcax_m1 $vAbu, $vAbu_, $vAbe_, $vAba_
eor sAbu, tmp,  sAbu_, ROR #30                  SEP
eor s_Aba, s_Aba, cur_const                     SEP      eor $vAba.16b, $vAba.16b, v28.16b
save count, STACK_OFFSET_COUNT                  SEP
eor sC0, sAka, sAsa, ROR #50                    SEP      eor3_m1 $vC0, $vAba, $vAga, $vAka
eor sC1, sAse, sAge, ROR #60                    SEP      eor3_m1 $vC0, $vC0, $vAma,  $vAsa
eor sC2, sAmi, sAgi, ROR #59                    SEP
eor sC3, sAgo, sAso, ROR #30                    SEP      eor3_m1 $vC1, $vAbe, $vAge, $vAke
eor sC4, sAbu, sAsu, ROR #53                    SEP      eor3_m1 $vC1, $vC1, $vAme,  $vAse
eor sC0, sAma, sC0, ROR #49                     SEP
eor sC1, sAbe, sC1, ROR #44                     SEP      eor3_m1 $vC2, $vAbi, $vAgi, $vAki
eor sC2, sAki, sC2, ROR #26                     SEP      eor3_m1 $vC2, $vC2, $vAmi,  $vAsi
eor sC3, sAmo, sC3, ROR #63                     SEP
eor sC4, sAmu, sC4, ROR #56                     SEP      eor3_m1 $vC3, $vAbo, $vAgo, $vAko
eor sC0, sAga, sC0, ROR #57                     SEP
eor sC1, sAme, sC1, ROR #58                     SEP      eor3_m1 $vC3, $vC3, $vAmo,  $vAso
eor sC2, sAbi, sC2, ROR #60                     SEP      eor3_m1 $vC4, $vAbu, $vAgu, $vAku
eor sC3, sAko, sC3, ROR #38                     SEP
eor sC4, sAgu, sC4, ROR #48                     SEP      eor3_m1 $vC4, $vC4, $vAmu,  $vAsu
eor sC0, s_Aba, sC0, ROR #61                    SEP      rax1_m1 $vE1, $vC0, $vC2
eor sC1, sAke, sC1, ROR #57                     SEP
eor sC2, sAsi, sC2, ROR #52                     SEP      rax1_m1 $vE3, $vC2, $vC4
eor sC3, sAbo, sC3, ROR #63                     SEP      rax1_m1 $vE0, $vC4, $vC1
eor sC4, sAku, sC4, ROR #50                     SEP
ror sC1, sC1, 56                                SEP      rax1_m1 $vE2, $vC1, $vC3
ror sC4, sC4, 58                                SEP
ror sC2, sC2, 62                                SEP      rax1_m1 $vE4, $vC3, $vC0
eor sE1, sC0, sC2, ROR #63                      SEP      eor $vAba_.16b, $vAba.16b, $vE0.16b
eor sE3, sC2, sC4, ROR #63                      SEP
eor sE0, sC4, sC1, ROR #63                      SEP      xar_m1 $vAsa_, $vAbi, $vE2, 2
eor sE2, sC1, sC3, ROR #63                      SEP      xar_m1 $vAbi_, $vAki, $vE2, 21
eor sE4, sC3, sC0, ROR #63                      SEP
eor s_Aba_, sE0, s_Aba                          SEP      xar_m1 $vAki_, $vAko, $vE3, 39
eor sAsa_, sE2, sAbi, ROR #50                   SEP
eor sAbi_, sE2, sAki, ROR #46                   SEP      xar_m1 $vAko_, $vAmu, $vE4, 56
eor sAki_, sE3, sAko, ROR #63                   SEP      xar_m1 $vAmu_, $vAso, $vE3, 8
eor sAko_, sE4, sAmu, ROR #28                   SEP
eor sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 $vAso_, $vAma, $vE0, 23
eor sAso_, sE0, sAma, ROR #54                   SEP      xar_m1 $vAka_, $vAbe, $vE1, 63
eor sAka_, sE1, sAbe, ROR #43                   SEP
eor sAse_, sE3, sAgo, ROR #36                   SEP      xar_m1 $vAse_, $vAgo, $vE3, 9
eor sAgo_, sE1, sAme, ROR #49                   SEP      xar_m1 $vAgo_, $vAme, $vE1, 19
eor sAke_, sE2, sAgi, ROR #3                    SEP
eor sAgi_, sE0, sAka, ROR #39                   SEP      xar_m1 $vAke_, $vAgi, $vE2, 58
eor sAga_, sE3, sAbo                            SEP
eor sAbo_, sE3, sAmo, ROR #37                   SEP      xar_m1 $vAgi_, $vAka, $vE0, 61
eor sAmo_, sE2, sAmi, ROR #8                    SEP      xar_m1 $vAga_, $vAbo, $vE3, 36
eor sAmi_, sE1, sAke, ROR #56                   SEP
eor sAge_, sE4, sAgu, ROR #44                   SEP      xar_m1 $vAbo_, $vAmo, $vE3, 43
eor sAgu_, sE2, sAsi, ROR #62                   SEP      xar_m1 $vAmo_, $vAmi, $vE2, 49
eor sAsi_, sE4, sAku, ROR #58                   SEP
eor sAku_, sE0, sAsa, ROR #25                   SEP      xar_m1 $vAmi_, $vAke, $vE1, 54
eor sAma_, sE4, sAbu, ROR #20                   SEP      xar_m1 $vAge_, $vAgu, $vE4, 44
eor sAbu_, sE4, sAsu, ROR #9                    SEP
eor sAsu_, sE1, sAse, ROR #23                   SEP      xar_m1 $vAgu_, $vAsi, $vE2, 3
eor sAme_, sE0, sAga, ROR #61                   SEP
eor sAbe_, sE1, sAge, ROR #19                   SEP      xar_m1 $vAsi_, $vAku, $vE4, 25
load_constant_ptr                               SEP      xar_m1 $vAku_, $vAsa, $vE0, 46
restore count, STACK_OFFSET_COUNT               SEP
bic tmp, sAgi_, sAge_, ROR #47                  SEP      xar_m1 $vAma_, $vAbu, $vE4, 37
eor sAga, tmp,  sAga_, ROR #39                  SEP      xar_m1 $vAbu_, $vAsu, $vE4, 50
bic tmp, sAgo_, sAgi_, ROR #42                  SEP
eor sAge, tmp,  sAge_, ROR #25                  SEP      xar_m1 $vAsu_, $vAse, $vE1, 62
bic tmp, sAgu_, sAgo_, ROR #16                  SEP
eor sAgi, tmp,  sAgi_, ROR #58                  SEP      xar_m1 $vAme_, $vAga, $vE0, 28
bic tmp, sAga_, sAgu_, ROR #31                  SEP      xar_m1 $vAbe_, $vAge, $vE1, 20
eor sAgo, tmp,  sAgo_, ROR #47                  SEP
bic tmp, sAge_, sAga_, ROR #56                  SEP      bcax_m1 $vAga, $vAga_, $vAgi_, $vAge_
eor sAgu, tmp,  sAgu_, ROR #23                  SEP      bcax_m1 $vAge, $vAge_, $vAgo_, $vAgi_
bic tmp, sAki_, sAke_, ROR #19                  SEP
eor sAka, tmp,  sAka_, ROR #24                  SEP      bcax_m1 $vAgi, $vAgi_, $vAgu_, $vAgo_
bic tmp, sAko_, sAki_, ROR #47                  SEP      bcax_m1 $vAgo, $vAgo_, $vAga_, $vAgu_
eor sAke, tmp,  sAke_, ROR #2                   SEP
bic tmp, sAku_, sAko_, ROR #10                  SEP      bcax_m1 $vAgu, $vAgu_, $vAge_, $vAga_
eor sAki, tmp,  sAki_, ROR #57                  SEP
bic tmp, sAka_, sAku_, ROR #47                  SEP      bcax_m1 $vAka, $vAka_, $vAki_, $vAke_
eor sAko, tmp,  sAko_, ROR #57                  SEP      bcax_m1 $vAke, $vAke_, $vAko_, $vAki_
bic tmp, sAke_, sAka_, ROR #5                   SEP
eor sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m1 $vAki, $vAki_, $vAku_, $vAko_
bic tmp, sAmi_, sAme_, ROR #38                  SEP      bcax_m1 $vAko, $vAko_, $vAka_, $vAku_
eor sAma, tmp,  sAma_, ROR #47                  SEP
bic tmp, sAmo_, sAmi_, ROR #5                   SEP      bcax_m1 $vAku, $vAku_, $vAke_, $vAka_
eor sAme, tmp,  sAme_, ROR #43                  SEP      bcax_m1 $vAma, $vAma_, $vAmi_, $vAme_
bic tmp, sAmu_, sAmo_, ROR #41                  SEP      restore x26, STACK_OFFSET_CONST
eor sAmi, tmp,  sAmi_, ROR #46                  SEP      ld1r {v28.2d}, [x26], #8
bic tmp, sAma_, sAmu_, ROR #35                  SEP      save x26, STACK_OFFSET_CONST
ldr cur_const, [const_addr, count, UXTW #3]     SEP
add count, count, #1                            SEP      bcax_m1 $vAme, $vAme_, $vAmo_, $vAmi_
eor sAmo, tmp,  sAmo_, ROR #12                  SEP
bic tmp, sAme_, sAma_, ROR #9                   SEP      bcax_m1 $vAmi, $vAmi_, $vAmu_, $vAmo_
eor sAmu, tmp,  sAmu_, ROR #44                  SEP
bic tmp, sAsi_, sAse_, ROR #48                  SEP
eor sAsa, tmp,  sAsa_, ROR #41                  SEP      bcax_m1 $vAmo, $vAmo_, $vAma_, $vAmu_
bic tmp, sAso_, sAsi_, ROR #2                   SEP
eor sAse, tmp,  sAse_, ROR #50                  SEP      bcax_m1 $vAmu, $vAmu_, $vAme_, $vAma_
bic tmp, sAsu_, sAso_, ROR #25                  SEP      bcax_m1 $vAsa, $vAsa_, $vAsi_, $vAse_
eor sAsi, tmp,  sAsi_, ROR #27                  SEP
bic tmp, sAsa_, sAsu_, ROR #60                  SEP      bcax_m1 $vAse, $vAse_, $vAso_, $vAsi_
eor sAso, tmp,  sAso_, ROR #21                  SEP      bcax_m1 $vAsi, $vAsi_, $vAsu_, $vAso_
bic tmp, sAse_, sAsa_, ROR #57                  SEP
eor sAsu, tmp,  sAsu_, ROR #53                  SEP      bcax_m1 $vAso, $vAso_, $vAsa_, $vAsu_
bic tmp, sAbi_, sAbe_, ROR #63                  SEP      bcax_m1 $vAsu, $vAsu_, $vAse_, $vAsa_
eor s_Aba, s_Aba_, tmp,  ROR #21                SEP
bic tmp, sAbo_, sAbi_, ROR #42                  SEP      bcax_m1 $vAba, $vAba_, $vAbi_, $vAbe_
eor sAbe, tmp,  sAbe_, ROR #41                  SEP
bic tmp, sAbu_, sAbo_, ROR #57                  SEP      bcax_m1 $vAbe, $vAbe_, $vAbo_, $vAbi_
eor sAbi, tmp,  sAbi_, ROR #35                  SEP      bcax_m1 $vAbi, $vAbi_, $vAbu_, $vAbo_
bic tmp, s_Aba_, sAbu_, ROR #50                 SEP
eor sAbo, tmp,  sAbo_, ROR #43                  SEP      bcax_m1 $vAbo, $vAbo_, $vAba_, $vAbu_
bic tmp, sAbe_, s_Aba_, ROR #44                 SEP      bcax_m1 $vAbu, $vAbu_, $vAbe_, $vAba_
eor sAbu, tmp,  sAbu_, ROR #30                  SEP
eor s_Aba, s_Aba, cur_const                     SEP      eor $vAba.16b, $vAba.16b, v28.16b
.endm

.macro final_rotate
    ror sAga, sAga,#(64-3)
    ror sAka, sAka,#(64-25)
    ror sAma, sAma,#(64-10)
    ror sAsa, sAsa,#(64-39)
    ror sAbe, sAbe,#(64-21)
    ror sAge, sAge,#(64-45)
    ror sAke, sAke,#(64-8)
    ror sAme, sAme,#(64-15)
    ror sAse, sAse,#(64-41)
    ror sAbi, sAbi,#(64-14)
    ror sAgi, sAgi,#(64-61)
    ror sAki, sAki,#(64-18)
    ror sAmi, sAmi,#(64-56)
    ror sAsi, sAsi,#(64-2)
    ror sAgo, sAgo,#(64-28)
    ror sAko, sAko,#(64-1)
    ror sAmo, sAmo,#(64-27)
    ror sAso, sAso,#(64-62)
    ror sAbu, sAbu,#(64-44)
    ror sAgu, sAgu,#(64-20)
    ror sAku, sAku,#(64-6)
    ror sAmu, sAmu,#(64-36)
    ror sAsu, sAsu,#(64-55)
.endm

#define KECCAK_F1600_ROUNDS 24


.global keccak_f1600_x3_hybrid_asm_v3p
.global _keccak_f1600_x3_hybrid_asm_v3p
.text
.align 4

keccak_f1600_x3_hybrid_asm_v3p:
_keccak_f1600_x3_hybrid_asm_v3p:
    alloc_stack
    save_gprs
    save_vregs
    save input_addr, STACK_OFFSET_INPUT

     load_input_vector 1,0

     load_constant_ptr

     save const_addr, STACK_OFFSET_CONST

     add input_addr, input_addr, #16
     load_input_scalar 1,0
     hybrid_round_initial
 loop_0:
     hybrid_round_noninitial
     cmp count, #(KECCAK_F1600_ROUNDS)
     blt loop_0
     final_rotate
     restore input_addr, STACK_OFFSET_INPUT
     store_input_vector 1,0
     add input_addr, input_addr, #16
     store_input_scalar 1,0

    restore_vregs
    restore_gprs
    free_stack
    ret
___
					}}}
					
$code.=<<___;
.asciz	"Keccak-1600 absorb and squeeze for ARMv8, CRYPTOGAMS by <appro\@openssl.org>"
___

{
    my  %opcode = (
    "rax1_m0"    => 0xce608c00,    "eor3_m0"    => 0xce000000,
    "bcax_m0"    => 0xce200000,    "xar_m0"    => 0xce800000,    "xar"    => 0xce800000    );

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
        s/\b(eor3_m0|xar_m0|xar|rax1_m0|bcax_m0)\s+(v.*)/unsha3($1,$2)/ge;
        print $_,"\n";
     }
}
close STDOUT or die "error closing STDOUT: $!";