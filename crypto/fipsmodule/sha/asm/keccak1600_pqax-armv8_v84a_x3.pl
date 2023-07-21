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

    $vC0 = "v27";
    $vC1 = "v28";
    $vC2 = "v29";
    $vC3 = "v30";
    $vC4 = "v31";
    
    $vBba = "v25";
    $vBbe = "v26";
    $vBbi = "v2"; 
    $vBbo = "v3";
    $vBbu = "v4";
    $vBga = "v10";
    $vBge = "v11";
    $vBgi = "v7";
    $vBgo = "v8";
    $vBgu = "v9";
    $vBka = "v15";
    $vBke = "v16";
    $vBki = "v12";
    $vBko = "v13";
    $vBku = "v14";
    $vBma = "v20";
    $vBme = "v21";
    $vBmi = "v17";
    $vBmo = "v18";
    $vBmu = "v19";
    $vBsa = "v0";
    $vBse = "v1";
    $vBsi = "v22";
    $vBso = "v23";
    $vBsu = "v24";

    $vE0 = "v31";
    $vE1 = "v27";
    $vE2 = "v26";
    $vE3 = "v29";
    $vE4 = "v30";


    $vAbaq    =  "q0";
    $vAbeq    =  "q1";
    $vAbiq    =  "q2";
    $vAboq    =  "q3";
    $vAbuq    =  "q4";
    $vAgaq    =  "q5";
    $vAgeq    =  "q6";
    $vAgiq    =  "q7";
    $vAgoq    =  "q8";
    $vAguq    =  "q9";
    $vAkaq    =  "q10";
    $vAkeq    =  "q11";
    $vAkiq    =  "q12";
    $vAkoq    =  "q13";
    $vAkuq    =  "q14";
    $vAmaq    =  "q15";
    $vAmeq    =  "q16";
    $vAmiq    =  "q17";
    $vAmoq    =  "q18";
    $vAmuq    =  "q19";
    $vAsaq    =  "q20";
    $vAseq    =  "q21";
    $vAsiq    =  "q22";
    $vAsoq    =  "q23";
    $vAsuq    =  "q24";

    $C0q =  "q27";
    $C1q =  "q28";
    $C2q =  "q29";
    $C3q =  "q30";
    $C4q =  "q31";

    $vBbaq =  "q25"; 
    $vBbeq =  "q26";
    $vBbiq =  "q2";
    $vBboq =  "q3";
    $vBbuq =  "q4";
    $vBgaq =  "q10";
    $vBgeq =  "q11";
    $vBgiq =  "q7";
    $vBgoq =  "q8";
    $vBguq =  "q9";
    $vBkaq =  "q15";
    $vBkeq =  "q16";
    $vBkiq =  "q12";
    $vBkoq =  "q13";
    $vBkuq =  "q14";
    $vBmaq =  "q20";
    $vBmeq =  "q21";
    $vBmiq =  "q17";
    $vBmoq =  "q18";
    $vBmuq =  "q19";
    $vBsaq =  "q0";
    $vBseq =  "q1";
    $vBsiq =  "q22";
    $vBsoq =  "q23";
    $vBsuq =  "q24";

    $E0q =  "q31";
    $E1q =  "q27";
    $E2q =  "q26"; 
    $E3q =  "q29";
    $E4q =  "q30";


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

    // Mapping of Kecck-f1600 SIMD state to vector registers at the beginning and end of each round. */

    // Mapping of Kecck-f1600 state to vector registers at the beginning and end of each round. */

    /* q-form of the above mapping */
   
    /* Mapping of Kecck-f1600 state to scalar registers
     * at the beginning and end of each round. */
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

.macro save reg, offset
    str \\reg, [sp, #\\offset]
.endm

.macro restore reg, offset
    ldr \\reg, [sp, #\\offset]
.endm

.macro load_constant_ptr
	adr const_addr, round_constants
.endm

.macro hybrid_round_initial
eor sC0, sAma, sAsa                             SEP
eor sC1, sAme, sAse                             SEP      eor3_m0 $vC1,$vAbe,$vAge,$vAke                                                                           
eor sC2, sAmi, sAsi                             SEP      eor3_m1 $vC3,$vAbo,$vAgo,$vAko                                                                            
eor sC3, sAmo, sAso                             SEP      eor3_m0 $vC0,$vAba,$vAga,$vAka                                                                                
eor sC4, sAmu, sAsu                             SEP      eor3_m1 $vC2,$vAbi,$vAgi,$vAki                                                                           
eor sC0, sAka, sC0                              SEP      eor3_m0 $vC4,$vAbu,$vAgu,$vAku                                                                            
eor sC1, sAke, sC1                              SEP      eor3_m1 $vC1, $vC1,$vAme, $vAse                                                                           
eor sC2, sAki, sC2                              SEP      eor3_m0 $vC3, $vC3,$vAmo, $vAso                                                                           
eor sC3, sAko, sC3                              SEP      eor3_m1 $vC0, $vC0,$vAma, $vAsa                                                                           
eor sC4, sAku, sC4                              SEP      eor3_m0 $vC2, $vC2,$vAmi, $vAsi                                                                           
eor sC0, sAga, sC0                              SEP      eor3_m1 $vC4, $vC4,$vAmu, $vAsu                                                                            
eor sC1, sAge, sC1                              SEP      vvtmp .req $vBba                                                                           
eor sC2, sAgi, sC2                              SEP                                                                           
eor sC3, sAgo, sC3                              SEP      rax1_m0 $vE2, $vC1, $vC3                                                                           
eor sC4, sAgu, sC4                              SEP      rax1_m1 $vE4, $vC3, $vC0                                                                            
eor sC0, s_Aba, sC0                             SEP      rax1_m0 $vE1, $vC0, $vC2                                                                           
eor sC1, sAbe, sC1                              SEP      rax1_m1 $vE3, $vC2, $vC4                                                                           
eor sC2, sAbi, sC2                              SEP      rax1_m0 $vE0, $vC4, $vC1                                                                           
eor sC3, sAbo, sC3                              SEP      .unreq vvtmp                                                                           
eor sC4, sAbu, sC4                              SEP      vvtmp .req $vC1                                                                           
eor sE1, sC0, sC2, ROR #63                      SEP      vvtmpq .req $C1q                                                                           
eor sE3, sC2, sC4, ROR #63                      SEP      eor $vBba.16b, $vAba.16b, $vE0.16b                                                                           
eor sE0, sC4, sC1, ROR #63                      SEP      xar_m1 $vBsa, $vAbi, $vE2, 2                                                                            
eor sE2, sC1, sC3, ROR #63                      SEP                                                                           
eor sE4, sC3, sC0, ROR #63                      SEP      xar_m1 $vBbi, $vAki, $vE2, 21                                                                           
eor s_Aba_, s_Aba, sE0                          SEP      xar_m1 $vBki, $vAko, $vE3, 39                                                                           
eor sAsa_, sAbi, sE2                            SEP      xar_m1 $vBko, $vAmu, $vE4, 56                                                                           
eor sAbi_, sAki, sE2                            SEP      xar_m1 $vBmu, $vAso, $vE3, 8                                                                            
eor sAki_, sAko, sE3                            SEP      xar_m1 $vBso, $vAma, $vE0, 23                                                                           
eor sAko_, sAmu, sE4                            SEP      xar_m1 $vBka, $vAbe, $vE1, 63                                                                           
eor sAmu_, sAso, sE3                            SEP      xar_m1 $vBse, $vAgo, $vE3, 9                                                                            
eor sAso_, sAma, sE0                            SEP      xar_m1 $vBgo, $vAme, $vE1, 19                                                                           
eor sAka_, sAbe, sE1                            SEP      xar_m1 $vBke, $vAgi, $vE2, 58                                                                           
eor sAse_, sAgo, sE3                            SEP      xar_m1 $vBgi, $vAka, $vE0, 61                                                                             
eor sAgo_, sAme, sE1                            SEP                                                                           
eor sAke_, sAgi, sE2                            SEP      xar_m1 $vBga, $vAbo, $vE3, 36                                                                           
eor sAgi_, sAka, sE0                            SEP      xar_m1 $vBbo, $vAmo, $vE3, 43                                                                           
eor sAga_, sAbo, sE3                            SEP      xar_m1 $vBmo, $vAmi, $vE2, 49                                                                           
eor sAbo_, sAmo, sE3                            SEP      xar_m1 $vBmi, $vAke, $vE1, 54                                                                           
eor sAmo_, sAmi, sE2                            SEP      xar_m1 $vBge, $vAgu, $vE4, 44                                                                           
eor sAmi_, sAke, sE1                            SEP      mov $vE3.16b, $vAga.16b                                                                                       
eor sAge_, sAgu, sE4                            SEP      bcax_m1 $vAga, $vBga, $vBgi, $vBge                                                                           
eor sAgu_, sAsi, sE2                            SEP      xar_m1 $vBgu, $vAsi, $vE2, 3                                                                            
eor sAsi_, sAku, sE4                            SEP      xar_m1 $vBsi, $vAku, $vE4, 25                                                                           
eor sAku_, sAsa, sE0                            SEP      xar_m1 $vBku, $vAsa, $vE0, 46                                                                           
eor sAma_, sAbu, sE4                            SEP                                                                                                               
eor sAbu_, sAsu, sE4                            SEP      xar_m1 $vBma, $vAbu, $vE4, 37                                                                           
eor sAsu_, sAse, sE1                            SEP      xar_m1 $vBbu, $vAsu, $vE4, 50                                                                           
eor sAme_, sAga, sE0                            SEP      xar_m1 $vBsu, $vAse, $vE1, 62                                                                           
eor sAbe_, sAge, sE1                            SEP      xar_m1 $vBme, $vE3, $vE0, 28                                                                             
load_constant_ptr                               SEP      xar_m1 $vBbe, $vAge, $vE1, 20                                                                           
bic tmp, sAgi_, sAge_, ROR #47                  SEP      bcax_m1 $vAge, $vBge, $vBgo, $vBgi                                                                           
eor sAga, tmp,  sAga_, ROR #39                  SEP      bcax_m0 $vAgi, $vBgi, $vBgu, $vBgo                                                                           
bic tmp, sAgo_, sAgi_, ROR #42                  SEP      bcax_m1 $vAgo, $vBgo, $vBga, $vBgu                                                                           
eor sAge, tmp,  sAge_, ROR #25                  SEP      bcax_m0 $vAgu, $vBgu, $vBge, $vBga                                                                           
bic tmp, sAgu_, sAgo_, ROR #16                  SEP      bcax_m1 $vAka, $vBka, $vBki, $vBke                                                                           
eor sAgi, tmp,  sAgi_, ROR #58                  SEP      bcax_m0 $vAke, $vBke, $vBko, $vBki                                                                           
bic tmp, sAga_, sAgu_, ROR #31                  SEP                                                                           
eor sAgo, tmp,  sAgo_, ROR #47                  SEP      .unreq vvtmp                                                                                               
bic tmp, sAge_, sAga_, ROR #56                  SEP      .unreq vvtmpq                                                                                               
eor sAgu, tmp,  sAgu_, ROR #23                  SEP      eor2    $vC0,  $vAka, $vAga                                                                                    
bic tmp, sAki_, sAke_, ROR #19                  SEP      str $vAgaq, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]                                                                                                    
eor sAka, tmp,  sAka_, ROR #24                  SEP      vvtmp .req $vAga                                                                                                   
bic tmp, sAko_, sAki_, ROR #47                  SEP      vvtmpq .req $vAgaq                                                                                                    
eor sAke, tmp,  sAke_, ROR #2                   SEP      bcax_m0 $vAki, $vBki, $vBku, $vBko                                                                                  
bic tmp, sAku_, sAko_, ROR #10                  SEP      bcax_m1 $vAko, $vBko, $vBka, $vBku                                                                                 
eor sAki, tmp,  sAki_, ROR #57                  SEP      eor2    $vC1,  $vAke, $vAge                                                                                             
bic tmp, sAka_, sAku_, ROR #47                  SEP      bcax_m0 $vAku, $vBku, $vBke, $vBka                                                                                    
eor sAko, tmp,  sAko_, ROR #57                  SEP                                                                                 
bic tmp, sAke_, sAka_, ROR #5                   SEP      eor2    $vC2,  $vAki, $vAgi                                                                                     
eor sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m1 $vAma, $vBma, $vBmi, $vBme                                                                            
bic tmp, sAmi_, sAme_, ROR #38                  SEP      eor2    $vC3,  $vAko, $vAgo                                                                                      
eor sAma, tmp,  sAma_, ROR #47                  SEP      bcax_m0 $vAme, $vBme, $vBmo, $vBmi                                                                           
bic tmp, sAmo_, sAmi_, ROR #5                   SEP      eor2    $vC4,  $vAku, $vAgu                                                                                       
eor sAme, tmp,  sAme_, ROR #43                  SEP      bcax_m1 $vAmi, $vBmi, $vBmu, $vBmo                                                                           
bic tmp, sAmu_, sAmo_, ROR #41                  SEP      eor2    $vC0,  $vC0,  $vAma                                                                                     
eor sAmi, tmp,  sAmi_, ROR #46                  SEP      bcax_m0 $vAmo, $vBmo, $vBma, $vBmu                                                                           
ldr cur_const, [const_addr]                     SEP      eor2    $vC1,  $vC1,  $vAme                                                                                     
mov count, #1                                   SEP      bcax_m1 $vAmu, $vBmu, $vBme, $vBma                                                                           
bic tmp, sAma_, sAmu_, ROR #35                  SEP                                                                           
eor sAmo, tmp,  sAmo_, ROR #12                  SEP      eor2    $vC2,  $vC2,  $vAmi                                                                                        
bic tmp, sAme_, sAma_, ROR #9                   SEP      bcax_m0 $vAsa, $vBsa, $vBsi, $vBse                                                                           
eor sAmu, tmp,  sAmu_, ROR #44                  SEP      eor2    $vC3,  $vC3,  $vAmo                                                                                       
bic tmp, sAsi_, sAse_, ROR #48                  SEP      bcax_m1 $vAse, $vBse, $vBso, $vBsi                                                                           
eor sAsa, tmp,  sAsa_, ROR #41                  SEP      eor2    $vC4,  $vC4,  $vAmu                                                                                       
bic tmp, sAso_, sAsi_, ROR #2                   SEP      bcax_m0 $vAsi, $vBsi, $vBsu, $vBso                                                                           
eor sAse, tmp,  sAse_, ROR #50                  SEP      eor2    $vC0,  $vC0,  $vAsa                                                                                      
bic tmp, sAsu_, sAso_, ROR #25                  SEP      bcax_m1 $vAso, $vBso, $vBsa, $vBsu                                                                           
eor sAsi, tmp,  sAsi_, ROR #27                  SEP      eor2    $vC1,  $vC1,  $vAse                                                                                     
bic tmp, sAsa_, sAsu_, ROR #60                  SEP      bcax_m0 $vAsu, $vBsu, $vBse, $vBsa                                                                           
eor sAso, tmp,  sAso_, ROR #21                  SEP                                                                           
save count, STACK_OFFSET_COUNT                  SEP                                                                           
bic tmp, sAse_, sAsa_, ROR #57                  SEP      eor2    $vC2,  $vC2,  $vAsi                                                                           
eor sAsu, tmp,  sAsu_, ROR #53                  SEP      eor2    $vC3,  $vC3,  $vAso                                                                           
bic tmp, sAbi_, sAbe_, ROR #63                  SEP      bcax_m1 $vAba, $vBba, $vBbi, $vBbe                                                                           
eor s_Aba, s_Aba_, tmp,  ROR #21                SEP      bcax_m0 $vAbe, $vBbe, $vBbo, $vBbi                                                                           
bic tmp, sAbo_, sAbi_, ROR #42                  SEP      eor2    $vC1,  $vC1,  $vAbe                                                                           
eor sAbe, tmp,  sAbe_, ROR #41                  SEP      restore x27, STACK_OFFSET_CONST                                                                           
bic tmp, sAbu_, sAbo_, ROR #57                  SEP      ldr vvtmpq, [x27], #16                                                                           
eor sAbi, tmp,  sAbi_, ROR #35                  SEP      save x27, STACK_OFFSET_CONST                                                                           
bic tmp, s_Aba_, sAbu_, ROR #50                 SEP      eor $vAba.16b, $vAba.16b, vvtmp.16b                                                                           
eor sAbo, tmp,  sAbo_, ROR #43                  SEP      eor2    $vC4,  $vC4,  $vAsu                                                                           
bic tmp, sAbe_, s_Aba_, ROR #44                 SEP                                                                           
eor sAbu, tmp,  sAbu_, ROR #30                  SEP      bcax_m0 $vAbi, $vBbi, $vBbu, $vBbo                                                                           
eor s_Aba, s_Aba, cur_const                     SEP      bcax_m1 $vAbo, $vBbo, $vBba, $vBbu                                                                           
                                                SEP      eor2    $vC3,  $vC3,  $vAbo                                                                           
eor sC0, sAka, sAsa, ROR #50                    SEP      eor2    $vC2,  $vC2,  $vAbi                                                                           
eor sC1, sAse, sAge, ROR #60                    SEP      eor2    $vC0,  $vC0,  $vAba                                                                           
eor sC2, sAmi, sAgi, ROR #59                    SEP      bcax_m0 $vAbu, $vBbu, $vBbe, $vBba                                                                           
eor sC3, sAgo, sAso, ROR #30                    SEP      eor2    $vC4,  $vC4,  $vAbu                                                                           
eor sC4, sAbu, sAsu, ROR #53                    SEP      ldr $vAgaq, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]                                                                          
eor sC0, sAma, sC0, ROR #49                     SEP      .unreq vvtmp                                                                           
eor sC1, sAbe, sC1, ROR #44                     SEP      .unreq vvtmpq                                                                           
eor sC2, sAki, sC2, ROR #26                     SEP      vvtmp .req $vBba                                                                            
eor sC3, sAmo, sC3, ROR #63                     SEP                                                                           
eor sC4, sAmu, sC4, ROR #56                     SEP      rax1_m0 $vE2, $vC1, $vC3                                                                           
eor sC0, sAga, sC0, ROR #57                     SEP      rax1_m1 $vE4, $vC3, $vC0                                                                           
eor sC1, sAme, sC1, ROR #58                     SEP      rax1_m0 $vE1, $vC0, $vC2                                                                           
eor sC2, sAbi, sC2, ROR #60                     SEP      rax1_m1 $vE3, $vC2, $vC4                                                                           
eor sC3, sAko, sC3, ROR #38                     SEP      rax1_m0 $vE0, $vC4, $vC1                                                                           
eor sC4, sAgu, sC4, ROR #48                     SEP      .unreq vvtmp                                                                           
eor sC0, s_Aba, sC0, ROR #61                    SEP      vvtmp .req $vC1                                                                           
eor sC1, sAke, sC1, ROR #57                     SEP      vvtmpq .req $C1q                                                                           
eor sC2, sAsi, sC2, ROR #52                     SEP      eor $vBba.16b, $vAba.16b, $vE0.16b                                                                           
eor sC3, sAbo, sC3, ROR #63                     SEP      xar_m1 $vBsa, $vAbi, $vE2, 2                                                                             
eor sC4, sAku, sC4, ROR #50                     SEP                                                                           
ror sC1, sC1, 56                                SEP      xar_m1 $vBbi, $vAki, $vE2, 21                                                                           
ror sC4, sC4, 58                                SEP      xar_m1 $vBki, $vAko, $vE3, 39                                                                           
ror sC2, sC2, 62                                SEP      xar_m1 $vBko, $vAmu, $vE4, 56                                                                           
eor sE1, sC0, sC2, ROR #63                      SEP      xar_m1 $vBmu, $vAso, $vE3, 8                                                                            
eor sE3, sC2, sC4, ROR #63                      SEP      xar_m1 $vBso, $vAma, $vE0, 23                                                                           
eor sE0, sC4, sC1, ROR #63                      SEP      xar_m1 $vBka, $vAbe, $vE1, 63                                                                           
eor sE2, sC1, sC3, ROR #63                      SEP      xar_m1 $vBse, $vAgo, $vE3, 9                                                                            
eor sE4, sC3, sC0, ROR #63                      SEP      xar_m1 $vBgo, $vAme, $vE1, 19                                                                           
eor s_Aba_, sE0, s_Aba                          SEP      xar_m1 $vBke, $vAgi, $vE2, 58                                                                           
eor sAsa_, sE2, sAbi, ROR #50                   SEP      xar_m1 $vBgi, $vAka, $vE0, 61                                                                           
eor sAbi_, sE2, sAki, ROR #46                   SEP                                                                           
eor sAki_, sE3, sAko, ROR #63                   SEP      xar_m1 $vBga, $vAbo, $vE3, 36                                                                           
eor sAko_, sE4, sAmu, ROR #28                   SEP      xar_m1 $vBbo, $vAmo, $vE3, 43                                                                           
eor sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 $vBmo, $vAmi, $vE2, 49                                                                           
eor sAso_, sE0, sAma, ROR #54                   SEP      xar_m1 $vBmi, $vAke, $vE1, 54                                                                           
eor sAka_, sE1, sAbe, ROR #43                   SEP      xar_m1 $vBge, $vAgu, $vE4, 44                                                                           
eor sAse_, sE3, sAgo, ROR #36                   SEP      mov $vE3.16b, $vAga.16b                                                                           
eor sAgo_, sE1, sAme, ROR #49                   SEP      bcax_m1 $vAga, $vBga, $vBgi, $vBge                                                                           
eor sAke_, sE2, sAgi, ROR #3                    SEP      xar_m1 $vBgu, $vAsi, $vE2, 3                                                                           
eor sAgi_, sE0, sAka, ROR #39                   SEP      xar_m1 $vBsi, $vAku, $vE4, 25                                                                           
eor sAga_, sE3, sAbo                            SEP      xar_m1 $vBku, $vAsa, $vE0, 46                                                                           
eor sAbo_, sE3, sAmo, ROR #37                   SEP                                                                           
eor sAmo_, sE2, sAmi, ROR #8                    SEP      xar_m1 $vBma, $vAbu, $vE4, 37                                                                           
eor sAmi_, sE1, sAke, ROR #56                   SEP      xar_m1 $vBbu, $vAsu, $vE4, 50                                                                           
eor sAge_, sE4, sAgu, ROR #44                   SEP      xar_m1 $vBsu, $vAse, $vE1, 62                                                                           
eor sAgu_, sE2, sAsi, ROR #62                   SEP      xar_m1 $vBme, $vE3, $vE0, 28                                                                           
eor sAsi_, sE4, sAku, ROR #58                   SEP      xar_m1 $vBbe, $vAge, $vE1, 20                                                                           
eor sAku_, sE0, sAsa, ROR #25                   SEP      bcax_m1 $vAge, $vBge, $vBgo, $vBgi                                                                           
eor sAma_, sE4, sAbu, ROR #20                   SEP      bcax_m0 $vAgi, $vBgi, $vBgu, $vBgo                                                                           
eor sAbu_, sE4, sAsu, ROR #9                    SEP      bcax_m1 $vAgo, $vBgo, $vBga, $vBgu                                                                           
eor sAsu_, sE1, sAse, ROR #23                   SEP      bcax_m0 $vAgu, $vBgu, $vBge, $vBga                                                                           
eor sAme_, sE0, sAga, ROR #61                   SEP      bcax_m1 $vAka, $vBka, $vBki, $vBke                                                                           
eor sAbe_, sE1, sAge, ROR #19                   SEP                                                                           
load_constant_ptr                               SEP      bcax_m0 $vAke, $vBke, $vBko, $vBki                                                                           
restore count, STACK_OFFSET_COUNT               SEP      .unreq vvtmp                                                                           
bic tmp, sAgi_, sAge_, ROR #47                  SEP      .unreq vvtmpq                                                                           
eor sAga, tmp,  sAga_, ROR #39                  SEP      eor2    $vC0,  $vAka, $vAga                                                                           
bic tmp, sAgo_, sAgi_, ROR #42                  SEP      str $vAgaq, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]                                                                        
eor sAge, tmp,  sAge_, ROR #25                  SEP      vvtmp .req $vAga                                                                           
bic tmp, sAgu_, sAgo_, ROR #16                  SEP      vvtmpq .req $vAgaq                                                                           
eor sAgi, tmp,  sAgi_, ROR #58                  SEP      bcax_m0 $vAki, $vBki, $vBku, $vBko                                                                           
bic tmp, sAga_, sAgu_, ROR #31                  SEP      bcax_m1 $vAko, $vBko, $vBka, $vBku                                                                           
eor sAgo, tmp,  sAgo_, ROR #47                  SEP      eor2    $vC1,  $vAke, $vAge                                                                           
bic tmp, sAge_, sAga_, ROR #56                  SEP      bcax_m0 $vAku, $vBku, $vBke, $vBka                                                                           
eor sAgu, tmp,  sAgu_, ROR #23                  SEP                                                                           
bic tmp, sAki_, sAke_, ROR #19                  SEP      eor2    $vC2,  $vAki, $vAgi                                                                           
eor sAka, tmp,  sAka_, ROR #24                  SEP      bcax_m1 $vAma, $vBma, $vBmi, $vBme                                                                           
bic tmp, sAko_, sAki_, ROR #47                  SEP      eor2    $vC3,  $vAko, $vAgo                                                                           
eor sAke, tmp,  sAke_, ROR #2                   SEP      bcax_m0 $vAme, $vBme, $vBmo, $vBmi                                                                           
bic tmp, sAku_, sAko_, ROR #10                  SEP      eor2    $vC4,  $vAku, $vAgu                                                                           
eor sAki, tmp,  sAki_, ROR #57                  SEP      bcax_m1 $vAmi, $vBmi, $vBmu, $vBmo                                                                           
bic tmp, sAka_, sAku_, ROR #47                  SEP      eor2    $vC0,  $vC0,  $vAma                                                                           
eor sAko, tmp,  sAko_, ROR #57                  SEP      bcax_m0 $vAmo, $vBmo, $vBma, $vBmu                                                                           
bic tmp, sAke_, sAka_, ROR #5                   SEP      eor2    $vC1,  $vC1,  $vAme                                                                           
eor sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m1 $vAmu, $vBmu, $vBme, $vBma                                                                           
bic tmp, sAmi_, sAme_, ROR #38                  SEP                                                                           
eor sAma, tmp,  sAma_, ROR #47                  SEP      eor2    $vC2,  $vC2,  $vAmi                                                                           
bic tmp, sAmo_, sAmi_, ROR #5                   SEP      bcax_m0 $vAsa, $vBsa, $vBsi, $vBse                                                                           
eor sAme, tmp,  sAme_, ROR #43                  SEP      eor2    $vC3,  $vC3,  $vAmo                                                                           
bic tmp, sAmu_, sAmo_, ROR #41                  SEP      bcax_m1 $vAse, $vBse, $vBso, $vBsi                                                                           
eor sAmi, tmp,  sAmi_, ROR #46                  SEP      eor2    $vC4,  $vC4,  $vAmu                                                                           
bic tmp, sAma_, sAmu_, ROR #35                  SEP      bcax_m0 $vAsi, $vBsi, $vBsu, $vBso                                                                           
eor sAmo, tmp,  sAmo_, ROR #12                  SEP      eor2    $vC0,  $vC0,  $vAsa                                                                           
bic tmp, sAme_, sAma_, ROR #9                   SEP      bcax_m1 $vAso, $vBso, $vBsa, $vBsu                                                                           
eor sAmu, tmp,  sAmu_, ROR #44                  SEP      eor2    $vC1,  $vC1,  $vAse                                                                           
bic tmp, sAsi_, sAse_, ROR #48                  SEP      bcax_m0 $vAsu, $vBsu, $vBse, $vBsa                                                                           
eor sAsa, tmp,  sAsa_, ROR #41                  SEP      eor2    $vC2,  $vC2,  $vAsi                                                                           
bic tmp, sAso_, sAsi_, ROR #2                   SEP      eor2    $vC3,  $vC3,  $vAso                                                                           
eor sAse, tmp,  sAse_, ROR #50                  SEP      bcax_m1 $vAba, $vBba, $vBbi, $vBbe                                                                           
bic tmp, sAsu_, sAso_, ROR #25                  SEP      bcax_m0 $vAbe, $vBbe, $vBbo, $vBbi                                                                           
eor sAsi, tmp,  sAsi_, ROR #27                  SEP      eor2    $vC1,  $vC1,  $vAbe                                                                           
bic tmp, sAsa_, sAsu_, ROR #60                  SEP      restore x26, STACK_OFFSET_CONST                                                                           
eor sAso, tmp,  sAso_, ROR #21                  SEP      ldr vvtmpq, [x26], #16                                                                           
bic tmp, sAse_, sAsa_, ROR #57                  SEP      save x26, STACK_OFFSET_CONST                                                                           
eor sAsu, tmp,  sAsu_, ROR #53                  SEP      eor $vAba.16b, $vAba.16b, vvtmp.16b                                                                           
bic tmp, sAbi_, sAbe_, ROR #63                  SEP      eor2    $vC4,  $vC4,  $vAsu                                                                           
eor s_Aba, s_Aba_, tmp,  ROR #21                SEP                                                                           
ldr cur_const, [const_addr, count, UXTW #3]     SEP                                                                           
bic tmp, sAbo_, sAbi_, ROR #42                  SEP      bcax_m0 $vAbi, $vBbi, $vBbu, $vBbo                                                                           
eor sAbe, tmp,  sAbe_, ROR #41                  SEP      bcax_m1 $vAbo, $vBbo, $vBba, $vBbu                                                                           
bic tmp, sAbu_, sAbo_, ROR #57                  SEP      eor2    $vC3,  $vC3,  $vAbo                                                                           
eor sAbi, tmp,  sAbi_, ROR #35                  SEP      eor2    $vC2,  $vC2,  $vAbi                                                                           
bic tmp, s_Aba_, sAbu_, ROR #50                 SEP      eor2    $vC0,  $vC0,  $vAba                                                                           
eor sAbo, tmp,  sAbo_, ROR #43                  SEP      bcax_m0 $vAbu, $vBbu, $vBbe, $vBba                                                                           
bic tmp, sAbe_, s_Aba_, ROR #44                 SEP      eor2    $vC4,  $vC4,  $vAbu                                                                           
eor sAbu, tmp,  sAbu_, ROR #30                  SEP      ldr $vAgaq, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]                                                                          
add count, count, #1                            SEP      .unreq vvtmp                                                                           
eor s_Aba, s_Aba, cur_const                     SEP      .unreq vvtmpq                                                                           
.endm

.macro  hybrid_round_noninitial
save count, STACK_OFFSET_COUNT                  SEP
eor sC0, sAka, sAsa, ROR #50                    SEP      vvtmp .req $vBba
eor sC1, sAse, sAge, ROR #60                    SEP      rax1_m0 $vE2, $vC1, $vC3
eor sC2, sAmi, sAgi, ROR #59                    SEP      rax1_m1 $vE4, $vC3, $vC0
eor sC3, sAgo, sAso, ROR #30                    SEP      rax1_m0 $vE1, $vC0, $vC2
eor sC4, sAbu, sAsu, ROR #53                    SEP      rax1_m1 $vE3, $vC2, $vC4
eor sC0, sAma, sC0, ROR #49                     SEP      rax1_m0 $vE0, $vC4, $vC1
eor sC1, sAbe, sC1, ROR #44                     SEP
eor sC2, sAki, sC2, ROR #26                     SEP      .unreq vvtmp
eor sC3, sAmo, sC3, ROR #63                     SEP      vvtmp .req $vC1
eor sC4, sAmu, sC4, ROR #56                     SEP      vvtmpq .req  $C1q
eor sC0, sAga, sC0, ROR #57                     SEP      eor $vBba.16b, $vAba.16b, $vE0.16b
eor sC1, sAme, sC1, ROR #58                     SEP      xar_m1 $vBsa, $vAbi, $vE2, 2
eor sC2, sAbi, sC2, ROR #60                     SEP
eor sC3, sAko, sC3, ROR #38                     SEP      xar_m1 $vBbi, $vAki, $vE2, 21
eor sC4, sAgu, sC4, ROR #48                     SEP      xar_m1 $vBki, $vAko, $vE3, 39
eor sC0, s_Aba, sC0, ROR #61                    SEP      xar_m1 $vBko, $vAmu, $vE4, 56
eor sC1, sAke, sC1, ROR #57                     SEP      xar_m1 $vBmu, $vAso, $vE3, 8
eor sC2, sAsi, sC2, ROR #52                     SEP      xar_m1 $vBso, $vAma, $vE0, 23
eor sC3, sAbo, sC3, ROR #63                     SEP      xar_m1 $vBka, $vAbe, $vE1, 63
eor sC4, sAku, sC4, ROR #50                     SEP
ror sC1, sC1, 56                                SEP      xar_m1 $vBse, $vAgo, $vE3, 9
ror sC4, sC4, 58                                SEP      xar_m1 $vBgo, $vAme, $vE1, 19
ror sC2, sC2, 62                                SEP      xar_m1 $vBke, $vAgi, $vE2, 58
eor sE1, sC0, sC2, ROR #63                      SEP      xar_m1 $vBgi, $vAka, $vE0, 61
eor sE3, sC2, sC4, ROR #63                      SEP      xar_m1 $vBga, $vAbo, $vE3, 36
eor sE0, sC4, sC1, ROR #63                      SEP
eor sE2, sC1, sC3, ROR #63                      SEP      xar_m1 $vBbo, $vAmo, $vE3, 43
eor sE4, sC3, sC0, ROR #63                      SEP      xar_m1 $vBmo, $vAmi, $vE2, 49
eor s_Aba_, sE0, s_Aba                          SEP      xar_m1 $vBmi, $vAke, $vE1, 54
eor sAsa_, sE2, sAbi, ROR #50                   SEP      xar_m1 $vBge, $vAgu, $vE4, 44
eor sAbi_, sE2, sAki, ROR #46                   SEP      mov $vE3.16b, $vAga.16b
eor sAki_, sE3, sAko, ROR #63                   SEP      bcax_m1 $vAga, $vBga, $vBgi, $vBge
eor sAko_, sE4, sAmu, ROR #28                   SEP
eor sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 $vBgu, $vAsi, $vE2, 3
eor sAso_, sE0, sAma, ROR #54                   SEP      xar_m1 $vBsi, $vAku, $vE4, 25
eor sAka_, sE1, sAbe, ROR #43                   SEP      xar_m1 $vBku, $vAsa, $vE0, 46
eor sAse_, sE3, sAgo, ROR #36                   SEP      xar_m1 $vBma, $vAbu, $vE4, 37
eor sAgo_, sE1, sAme, ROR #49                   SEP      xar_m1 $vBbu, $vAsu, $vE4, 50
eor sAke_, sE2, sAgi, ROR #3                    SEP
eor sAgi_, sE0, sAka, ROR #39                   SEP      xar_m1 $vBsu, $vAse, $vE1, 62
eor sAga_, sE3, sAbo                            SEP      xar_m1 $vBme, $vE3, $vE0, 28
eor sAbo_, sE3, sAmo, ROR #37                   SEP      xar_m1 $vBbe, $vAge, $vE1, 20
eor sAmo_, sE2, sAmi, ROR #8                    SEP      bcax_m1 $vAge, $vBge, $vBgo, $vBgi
eor sAmi_, sE1, sAke, ROR #56                   SEP      bcax_m0 $vAgi, $vBgi, $vBgu, $vBgo
eor sAge_, sE4, sAgu, ROR #44                   SEP
eor sAgu_, sE2, sAsi, ROR #62                   SEP      bcax_m1 $vAgo, $vBgo, $vBga, $vBgu
eor sAsi_, sE4, sAku, ROR #58                   SEP      bcax_m0 $vAgu, $vBgu, $vBge, $vBga
eor sAku_, sE0, sAsa, ROR #25                   SEP      bcax_m1 $vAka, $vBka, $vBki, $vBke
eor sAma_, sE4, sAbu, ROR #20                   SEP      bcax_m0 $vAke, $vBke, $vBko, $vBki
eor sAbu_, sE4, sAsu, ROR #9                    SEP      .unreq vvtmp
eor sAsu_, sE1, sAse, ROR #23                   SEP      .unreq vvtmpq
eor sAme_, sE0, sAga, ROR #61                   SEP
eor sAbe_, sE1, sAge, ROR #19                   SEP      eor2    $vC0,  $vAka, $vAga
load_constant_ptr                               SEP      str $vAgaq, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
restore count, STACK_OFFSET_COUNT               SEP      vvtmp .req $vAga
bic tmp, sAgi_, sAge_, ROR #47                  SEP      vvtmpq .req $vAgaq
eor sAga, tmp,  sAga_, ROR #39                  SEP      bcax_m0 $vAki, $vBki, $vBku, $vBko
bic tmp, sAgo_, sAgi_, ROR #42                  SEP
eor sAge, tmp,  sAge_, ROR #25                  SEP      bcax_m1 $vAko, $vBko, $vBka, $vBku
bic tmp, sAgu_, sAgo_, ROR #16                  SEP      eor2    $vC1,  $vAke, $vAge
eor sAgi, tmp,  sAgi_, ROR #58                  SEP      bcax_m0 $vAku, $vBku, $vBke, $vBka
bic tmp, sAga_, sAgu_, ROR #31                  SEP      eor2    $vC2,  $vAki, $vAgi
eor sAgo, tmp,  sAgo_, ROR #47                  SEP      bcax_m1 $vAma, $vBma, $vBmi, $vBme
bic tmp, sAge_, sAga_, ROR #56                  SEP      eor2    $vC3,  $vAko, $vAgo
eor sAgu, tmp,  sAgu_, ROR #23                  SEP
bic tmp, sAki_, sAke_, ROR #19                  SEP      bcax_m0 $vAme, $vBme, $vBmo, $vBmi
eor sAka, tmp,  sAka_, ROR #24                  SEP      eor2    $vC4,  $vAku, $vAgu
bic tmp, sAko_, sAki_, ROR #47                  SEP      bcax_m1 $vAmi, $vBmi, $vBmu, $vBmo
eor sAke, tmp,  sAke_, ROR #2                   SEP      eor2    $vC0,  $vC0,  $vAma
bic tmp, sAku_, sAko_, ROR #10                  SEP      bcax_m0 $vAmo, $vBmo, $vBma, $vBmu
eor sAki, tmp,  sAki_, ROR #57                  SEP
bic tmp, sAka_, sAku_, ROR #47                  SEP      eor2    $vC1,  $vC1,  $vAme
eor sAko, tmp,  sAko_, ROR #57                  SEP      bcax_m1 $vAmu, $vBmu, $vBme, $vBma
bic tmp, sAke_, sAka_, ROR #5                   SEP      eor2    $vC2,  $vC2,  $vAmi
eor sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m0 $vAsa, $vBsa, $vBsi, $vBse
bic tmp, sAmi_, sAme_, ROR #38                  SEP      eor2    $vC3,  $vC3,  $vAmo
eor sAma, tmp,  sAma_, ROR #47                  SEP
bic tmp, sAmo_, sAmi_, ROR #5                   SEP      bcax_m1 $vAse, $vBse, $vBso, $vBsi
eor sAme, tmp,  sAme_, ROR #43                  SEP      eor2    $vC4,  $vC4,  $vAmu
bic tmp, sAmu_, sAmo_, ROR #41                  SEP      bcax_m0 $vAsi, $vBsi, $vBsu, $vBso
eor sAmi, tmp,  sAmi_, ROR #46                  SEP      eor2    $vC0,  $vC0,  $vAsa
bic tmp, sAma_, sAmu_, ROR #35                  SEP      bcax_m1 $vAso, $vBso, $vBsa, $vBsu
ldr cur_const, [const_addr, count, UXTW #3]     SEP      eor2    $vC1,  $vC1,  $vAse
add count, count, #1                            SEP
eor sAmo, tmp,  sAmo_, ROR #12                  SEP      bcax_m0 $vAsu, $vBsu, $vBse, $vBsa
bic tmp, sAme_, sAma_, ROR #9                   SEP      eor2    $vC2,  $vC2,  $vAsi
eor sAmu, tmp,  sAmu_, ROR #44                  SEP      eor2    $vC3,  $vC3,  $vAso
bic tmp, sAsi_, sAse_, ROR #48                  SEP      bcax_m1 $vAba, $vBba, $vBbi, $vBbe
eor sAsa, tmp,  sAsa_, ROR #41                  SEP      bcax_m0 $vAbe, $vBbe, $vBbo, $vBbi
bic tmp, sAso_, sAsi_, ROR #2                   SEP
save count, STACK_OFFSET_COUNT                  SEP
eor sAse, tmp,  sAse_, ROR #50                  SEP      eor2    $vC1,  $vC1,  $vAbe
bic tmp, sAsu_, sAso_, ROR #25                  SEP      restore x27, STACK_OFFSET_CONST
eor sAsi, tmp,  sAsi_, ROR #27                  SEP      ldr vvtmpq, [x27], #16
bic tmp, sAsa_, sAsu_, ROR #60                  SEP      save x27, STACK_OFFSET_CONST
eor sAso, tmp,  sAso_, ROR #21                  SEP      eor $vAba.16b, $vAba.16b, vvtmp.16b
bic tmp, sAse_, sAsa_, ROR #57                  SEP      eor2    $vC4,  $vC4,  $vAsu
eor sAsu, tmp,  sAsu_, ROR #53                  SEP
bic tmp, sAbi_, sAbe_, ROR #63                  SEP      bcax_m0 $vAbi, $vBbi, $vBbu, $vBbo
eor s_Aba, s_Aba_, tmp,  ROR #21                SEP      bcax_m1 $vAbo, $vBbo, $vBba, $vBbu
bic tmp, sAbo_, sAbi_, ROR #42                  SEP      eor2    $vC3,  $vC3,  $vAbo
eor sAbe, tmp,  sAbe_, ROR #41                  SEP      eor2    $vC2,  $vC2,  $vAbi
bic tmp, sAbu_, sAbo_, ROR #57                  SEP      eor2    $vC0,  $vC0,  $vAba
eor sAbi, tmp,  sAbi_, ROR #35                  SEP
bic tmp, s_Aba_, sAbu_, ROR #50                 SEP      bcax_m0 $vAbu, $vBbu, $vBbe, $vBba
eor sAbo, tmp,  sAbo_, ROR #43                  SEP      eor2    $vC4,  $vC4,  $vAbu
bic tmp, sAbe_, s_Aba_, ROR #44                 SEP      ldr $vAgaq, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
eor sAbu, tmp,  sAbu_, ROR #30                  SEP      .unreq vvtmp
eor s_Aba, s_Aba, cur_const                     SEP      .unreq vvtmpq
eor sC0, sAka, sAsa, ROR #50                    SEP      vvtmp .req $vBba
eor sC1, sAse, sAge, ROR #60                    SEP      rax1_m0 $vE2, $vC1, $vC3
eor sC2, sAmi, sAgi, ROR #59                    SEP      rax1_m1 $vE4, $vC3, $vC0
eor sC3, sAgo, sAso, ROR #30                    SEP      rax1_m0 $vE1, $vC0, $vC2
eor sC4, sAbu, sAsu, ROR #53                    SEP      rax1_m1 $vE3, $vC2, $vC4
eor sC0, sAma, sC0, ROR #49                     SEP      rax1_m0 $vE0, $vC4, $vC1
eor sC1, sAbe, sC1, ROR #44                     SEP
eor sC2, sAki, sC2, ROR #26                     SEP      .unreq vvtmp
eor sC3, sAmo, sC3, ROR #63                     SEP      vvtmp .req $vC1
eor sC4, sAmu, sC4, ROR #56                     SEP      vvtmpq .req  $C1q
eor sC0, sAga, sC0, ROR #57                     SEP      eor $vBba.16b, $vAba.16b, $vE0.16b
eor sC1, sAme, sC1, ROR #58                     SEP      xar_m1 $vBsa, $vAbi, $vE2, 2
eor sC2, sAbi, sC2, ROR #60                     SEP
eor sC3, sAko, sC3, ROR #38                     SEP      xar_m1 $vBbi, $vAki, $vE2, 21
eor sC4, sAgu, sC4, ROR #48                     SEP      xar_m1 $vBki, $vAko, $vE3, 39
eor sC0, s_Aba, sC0, ROR #61                    SEP      xar_m1 $vBko, $vAmu, $vE4, 56
eor sC1, sAke, sC1, ROR #57                     SEP      xar_m1 $vBmu, $vAso, $vE3, 8
eor sC2, sAsi, sC2, ROR #52                     SEP      xar_m1 $vBso, $vAma, $vE0, 23
eor sC3, sAbo, sC3, ROR #63                     SEP      xar_m1 $vBka, $vAbe, $vE1, 63
eor sC4, sAku, sC4, ROR #50                     SEP
ror sC1, sC1, 56                                SEP      xar_m1 $vBse, $vAgo, $vE3, 9
ror sC4, sC4, 58                                SEP      xar_m1 $vBgo, $vAme, $vE1, 19
ror sC2, sC2, 62                                SEP      xar_m1 $vBke, $vAgi, $vE2, 58
eor sE1, sC0, sC2, ROR #63                      SEP      xar_m1 $vBgi, $vAka, $vE0, 61
eor sE3, sC2, sC4, ROR #63                      SEP      xar_m1 $vBga, $vAbo, $vE3, 36
eor sE0, sC4, sC1, ROR #63                      SEP 
eor sE2, sC1, sC3, ROR #63                      SEP      xar_m1 $vBbo, $vAmo, $vE3, 43
eor sE4, sC3, sC0, ROR #63                      SEP      xar_m1 $vBmo, $vAmi, $vE2, 49
eor s_Aba_, sE0, s_Aba                          SEP      xar_m1 $vBmi, $vAke, $vE1, 54
eor sAsa_, sE2, sAbi, ROR #50                   SEP      xar_m1 $vBge, $vAgu, $vE4, 44
eor sAbi_, sE2, sAki, ROR #46                   SEP      mov $vE3.16b, $vAga.16b
eor sAki_, sE3, sAko, ROR #63                   SEP      bcax_m1 $vAga, $vBga, $vBgi, $vBge
eor sAko_, sE4, sAmu, ROR #28                   SEP
eor sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 $vBgu, $vAsi, $vE2, 3
eor sAso_, sE0, sAma, ROR #54                   SEP      xar_m1 $vBsi, $vAku, $vE4, 25
eor sAka_, sE1, sAbe, ROR #43                   SEP      xar_m1 $vBku, $vAsa, $vE0, 46
eor sAse_, sE3, sAgo, ROR #36                   SEP      xar_m1 $vBma, $vAbu, $vE4, 37
eor sAgo_, sE1, sAme, ROR #49                   SEP      xar_m1 $vBbu, $vAsu, $vE4, 50
eor sAke_, sE2, sAgi, ROR #3                    SEP
eor sAgi_, sE0, sAka, ROR #39                   SEP      xar_m1 $vBsu, $vAse, $vE1, 62
eor sAga_, sE3, sAbo                            SEP      xar_m1 $vBme, $vE3, $vE0, 28
eor sAbo_, sE3, sAmo, ROR #37                   SEP      xar_m1 $vBbe, $vAge, $vE1, 20
eor sAmo_, sE2, sAmi, ROR #8                    SEP      bcax_m1 $vAge, $vBge, $vBgo, $vBgi
eor sAmi_, sE1, sAke, ROR #56                   SEP      bcax_m0 $vAgi, $vBgi, $vBgu, $vBgo
eor sAge_, sE4, sAgu, ROR #44                   SEP
eor sAgu_, sE2, sAsi, ROR #62                   SEP      bcax_m1 $vAgo, $vBgo, $vBga, $vBgu
eor sAsi_, sE4, sAku, ROR #58                   SEP      bcax_m0 $vAgu, $vBgu, $vBge, $vBga
eor sAku_, sE0, sAsa, ROR #25                   SEP      bcax_m1 $vAka, $vBka, $vBki, $vBke
eor sAma_, sE4, sAbu, ROR #20                   SEP      bcax_m0 $vAke, $vBke, $vBko, $vBki
eor sAbu_, sE4, sAsu, ROR #9                    SEP      .unreq vvtmp
eor sAsu_, sE1, sAse, ROR #23                   SEP      .unreq vvtmpq
eor sAme_, sE0, sAga, ROR #61                   SEP
eor sAbe_, sE1, sAge, ROR #19                   SEP      eor2    $vC0,  $vAka, $vAga
load_constant_ptr                               SEP      str $vAgaq, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
restore count, STACK_OFFSET_COUNT               SEP      vvtmp .req $vAga
bic tmp, sAgi_, sAge_, ROR #47                  SEP      vvtmpq .req $vAgaq
eor sAga, tmp,  sAga_, ROR #39                  SEP      bcax_m1 $vAki, $vBki, $vBku, $vBko
bic tmp, sAgo_, sAgi_, ROR #42                  SEP
eor sAge, tmp,  sAge_, ROR #25                  SEP      bcax_m1 $vAko, $vBko, $vBka, $vBku
bic tmp, sAgu_, sAgo_, ROR #16                  SEP      eor2    $vC1,  $vAke, $vAge
eor sAgi, tmp,  sAgi_, ROR #58                  SEP      bcax_m0 $vAku, $vBku, $vBke, $vBka
bic tmp, sAga_, sAgu_, ROR #31                  SEP      eor2    $vC2,  $vAki, $vAgi
eor sAgo, tmp,  sAgo_, ROR #47                  SEP      bcax_m1 $vAma, $vBma, $vBmi, $vBme
bic tmp, sAge_, sAga_, ROR #56                  SEP      eor2    $vC3,  $vAko, $vAgo
eor sAgu, tmp,  sAgu_, ROR #23                  SEP
bic tmp, sAki_, sAke_, ROR #19                  SEP      bcax_m0 $vAme, $vBme, $vBmo, $vBmi
eor sAka, tmp,  sAka_, ROR #24                  SEP      eor2    $vC4,  $vAku, $vAgu
bic tmp, sAko_, sAki_, ROR #47                  SEP      bcax_m1 $vAmi, $vBmi, $vBmu, $vBmo
eor sAke, tmp,  sAke_, ROR #2                   SEP      eor2    $vC0,  $vC0,  $vAma
bic tmp, sAku_, sAko_, ROR #10                  SEP      bcax_m0 $vAmo, $vBmo, $vBma, $vBmu
eor sAki, tmp,  sAki_, ROR #57                  SEP
bic tmp, sAka_, sAku_, ROR #47                  SEP      eor2    $vC1,  $vC1,  $vAme
eor sAko, tmp,  sAko_, ROR #57                  SEP      bcax_m1 $vAmu, $vBmu, $vBme, $vBma
bic tmp, sAke_, sAka_, ROR #5                   SEP      eor2    $vC2,  $vC2,  $vAmi
eor sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m0 $vAsa, $vBsa, $vBsi, $vBse
bic tmp, sAmi_, sAme_, ROR #38                  SEP      eor2    $vC3,  $vC3,  $vAmo
eor sAma, tmp,  sAma_, ROR #47                  SEP
bic tmp, sAmo_, sAmi_, ROR #5                   SEP      bcax_m1 $vAse, $vBse, $vBso, $vBsi
eor sAme, tmp,  sAme_, ROR #43                  SEP      eor2    $vC4,  $vC4,  $vAmu
bic tmp, sAmu_, sAmo_, ROR #41                  SEP      bcax_m0 $vAsi, $vBsi, $vBsu, $vBso
eor sAmi, tmp,  sAmi_, ROR #46                  SEP      eor2    $vC0,  $vC0,  $vAsa
bic tmp, sAma_, sAmu_, ROR #35                  SEP      bcax_m1 $vAso, $vBso, $vBsa, $vBsu
                                                SEP      eor2    $vC1,  $vC1,  $vAse
eor sAmo, tmp,  sAmo_, ROR #12                  SEP      bcax_m0 $vAsu, $vBsu, $vBse, $vBsa
bic tmp, sAme_, sAma_, ROR #9                   SEP      eor2    $vC2,  $vC2,  $vAsi
eor sAmu, tmp,  sAmu_, ROR #44                  SEP      eor2    $vC3,  $vC3,  $vAso
bic tmp, sAsi_, sAse_, ROR #48                  SEP      bcax_m1 $vAba, $vBba, $vBbi, $vBbe
eor sAsa, tmp,  sAsa_, ROR #41                  SEP      bcax_m0 $vAbe, $vBbe, $vBbo, $vBbi
bic tmp, sAso_, sAsi_, ROR #2                   SEP
eor sAse, tmp,  sAse_, ROR #50                  SEP      eor2    $vC1,  $vC1,  $vAbe
bic tmp, sAsu_, sAso_, ROR #25                  SEP      restore x26, STACK_OFFSET_CONST
eor sAsi, tmp,  sAsi_, ROR #27                  SEP      ldr vvtmpq, [x26], #16
bic tmp, sAsa_, sAsu_, ROR #60                  SEP      save x26, STACK_OFFSET_CONST
eor sAso, tmp,  sAso_, ROR #21                  SEP      eor $vAba.16b, $vAba.16b, vvtmp.16b
bic tmp, sAse_, sAsa_, ROR #57                  SEP      eor2    $vC4,  $vC4,  $vAsu
eor sAsu, tmp,  sAsu_, ROR #53                  SEP
ldr cur_const, [const_addr, count, UXTW #3]     SEP
add count, count, #1                            SEP
bic tmp, sAbi_, sAbe_, ROR #63                  SEP      bcax_m0 $vAbi, $vBbi, $vBbu, $vBbo
eor s_Aba, s_Aba_, tmp,  ROR #21                SEP      bcax_m1 $vAbo, $vBbo, $vBba, $vBbu
bic tmp, sAbo_, sAbi_, ROR #42                  SEP      eor2    $vC3,  $vC3,  $vAbo
eor sAbe, tmp,  sAbe_, ROR #41                  SEP      eor2    $vC2,  $vC2,  $vAbi
bic tmp, sAbu_, sAbo_, ROR #57                  SEP      eor2    $vC0,  $vC0,  $vAba
eor sAbi, tmp,  sAbi_, ROR #35                  SEP
bic tmp, s_Aba_, sAbu_, ROR #50                 SEP      bcax_m0 $vAbu, $vBbu, $vBbe, $vBba
eor sAbo, tmp,  sAbo_, ROR #43                  SEP      eor2    $vC4,  $vC4,  $vAbu
bic tmp, sAbe_, s_Aba_, ROR #44                 SEP      ldr $vAgaq, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
eor sAbu, tmp,  sAbu_, ROR #30                  SEP      .unreq vvtmp
eor s_Aba, s_Aba, cur_const                     SEP      .unreq vvtmpq
.endm


.macro  hybrid_round_final
save count, STACK_OFFSET_COUNT                  SEP
eor sC0, sAka, sAsa, ROR #50                    SEP      vvtmp .req $vBba
eor sC1, sAse, sAge, ROR #60                    SEP      rax1_m0 $vE2, $vC1, $vC3
eor sC2, sAmi, sAgi, ROR #59                    SEP
eor sC3, sAgo, sAso, ROR #30                    SEP      rax1_m1 $vE4, $vC3, $vC0
eor sC4, sAbu, sAsu, ROR #53                    SEP      rax1_m0 $vE1, $vC0, $vC2
eor sC0, sAma, sC0, ROR #49                     SEP
eor sC1, sAbe, sC1, ROR #44                     SEP      rax1_m1 $vE3, $vC2, $vC4
eor sC2, sAki, sC2, ROR #26                     SEP      rax1_m0 $vE0, $vC4, $vC1
eor sC3, sAmo, sC3, ROR #63                     SEP
eor sC4, sAmu, sC4, ROR #56                     SEP      .unreq vvtmp
eor sC0, sAga, sC0, ROR #57                     SEP      vvtmp .req $vC1
eor sC1, sAme, sC1, ROR #58                     SEP
eor sC2, sAbi, sC2, ROR #60                     SEP      vvtmpq .req  $C1q
eor sC3, sAko, sC3, ROR #38                     SEP      eor $vBba.16b, $vAba.16b, $vE0.16b
eor sC4, sAgu, sC4, ROR #48                     SEP
eor sC0, s_Aba, sC0, ROR #61                    SEP      xar_m1 $vBsa, $vAbi, $vE2, 2
eor sC1, sAke, sC1, ROR #57                     SEP      xar_m1 $vBbi, $vAki, $vE2, 21
eor sC2, sAsi, sC2, ROR #52                     SEP
eor sC3, sAbo, sC3, ROR #63                     SEP      xar_m1 $vBki, $vAko, $vE3, 39
eor sC4, sAku, sC4, ROR #50                     SEP      xar_m1 $vBko, $vAmu, $vE4, 56
ror sC1, sC1, 56                                SEP
ror sC4, sC4, 58                                SEP      xar_m1 $vBmu, $vAso, $vE3, 8
ror sC2, sC2, 62                                SEP      xar_m1 $vBso, $vAma, $vE0, 23
eor sE1, sC0, sC2, ROR #63                      SEP
eor sE3, sC2, sC4, ROR #63                      SEP      xar_m1 $vBka, $vAbe, $vE1, 63
eor sE0, sC4, sC1, ROR #63                      SEP      xar_m1 $vBse, $vAgo, $vE3, 9
eor sE2, sC1, sC3, ROR #63                      SEP
eor sE4, sC3, sC0, ROR #63                      SEP      xar_m1 $vBgo, $vAme, $vE1, 19
eor s_Aba_, sE0, s_Aba                          SEP      xar_m1 $vBke, $vAgi, $vE2, 58
eor sAsa_, sE2, sAbi, ROR #50                   SEP
eor sAbi_, sE2, sAki, ROR #46                   SEP      xar_m1 $vBgi, $vAka, $vE0, 61
eor sAki_, sE3, sAko, ROR #63                   SEP
eor sAko_, sE4, sAmu, ROR #28                   SEP      xar_m1 $vBga, $vAbo, $vE3, 36
eor sAmu_, sE3, sAso, ROR #2                    SEP      xar_m1 $vBbo, $vAmo, $vE3, 43
eor sAso_, sE0, sAma, ROR #54                   SEP
eor sAka_, sE1, sAbe, ROR #43                   SEP      xar_m1 $vBmo, $vAmi, $vE2, 49
eor sAse_, sE3, sAgo, ROR #36                   SEP      xar_m1 $vBmi, $vAke, $vE1, 54
eor sAgo_, sE1, sAme, ROR #49                   SEP
eor sAke_, sE2, sAgi, ROR #3                    SEP      xar_m1 $vBge, $vAgu, $vE4, 44
eor sAgi_, sE0, sAka, ROR #39                   SEP      mov $vE3.16b, $vAga.16b
eor sAga_, sE3, sAbo                            SEP
eor sAbo_, sE3, sAmo, ROR #37                   SEP      bcax_m1 $vAga, $vBga, $vBgi, $vBge
eor sAmo_, sE2, sAmi, ROR #8                    SEP      xar_m1 $vBgu, $vAsi, $vE2, 3
eor sAmi_, sE1, sAke, ROR #56                   SEP
eor sAge_, sE4, sAgu, ROR #44                   SEP      xar_m1 $vBsi, $vAku, $vE4, 25
eor sAgu_, sE2, sAsi, ROR #62                   SEP      xar_m1 $vBku, $vAsa, $vE0, 46
eor sAsi_, sE4, sAku, ROR #58                   SEP
eor sAku_, sE0, sAsa, ROR #25                   SEP      xar_m1 $vBma, $vAbu, $vE4, 37
eor sAma_, sE4, sAbu, ROR #20                   SEP      xar_m1 $vBbu, $vAsu, $vE4, 50
eor sAbu_, sE4, sAsu, ROR #9                    SEP
eor sAsu_, sE1, sAse, ROR #23                   SEP      xar_m1 $vBsu, $vAse, $vE1, 62
eor sAme_, sE0, sAga, ROR #61                   SEP      xar_m1 $vBme, $vE3, $vE0, 28
eor sAbe_, sE1, sAge, ROR #19                   SEP
load_constant_ptr                               SEP      xar_m1 $vBbe, $vAge, $vE1, 20
restore count, STACK_OFFSET_COUNT               SEP      bcax_m1 $vAge, $vBge, $vBgo, $vBgi
bic tmp, sAgi_, sAge_, ROR #47                  SEP
eor sAga, tmp,  sAga_, ROR #39                  SEP      bcax_m0 $vAgi, $vBgi, $vBgu, $vBgo
bic tmp, sAgo_, sAgi_, ROR #42                  SEP      bcax_m1 $vAgo, $vBgo, $vBga, $vBgu
eor sAge, tmp,  sAge_, ROR #25                  SEP
bic tmp, sAgu_, sAgo_, ROR #16                  SEP      bcax_m0 $vAgu, $vBgu, $vBge, $vBga
eor sAgi, tmp,  sAgi_, ROR #58                  SEP
bic tmp, sAga_, sAgu_, ROR #31                  SEP      bcax_m1 $vAka, $vBka, $vBki, $vBke
eor sAgo, tmp,  sAgo_, ROR #47                  SEP      bcax_m0 $vAke, $vBke, $vBko, $vBki
bic tmp, sAge_, sAga_, ROR #56                  SEP
eor sAgu, tmp,  sAgu_, ROR #23                  SEP      .unreq vvtmp
bic tmp, sAki_, sAke_, ROR #19                  SEP      .unreq vvtmpq
eor sAka, tmp,  sAka_, ROR #24                  SEP
bic tmp, sAko_, sAki_, ROR #47                  SEP      eor2    $vC0,  $vAka, $vAga
eor sAke, tmp,  sAke_, ROR #2                   SEP      str $vAgaq, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
bic tmp, sAku_, sAko_, ROR #10                  SEP
eor sAki, tmp,  sAki_, ROR #57                  SEP      vvtmp .req $vAga
bic tmp, sAka_, sAku_, ROR #47                  SEP      vvtmpq .req $vAgaq
eor sAko, tmp,  sAko_, ROR #57                  SEP
bic tmp, sAke_, sAka_, ROR #5                   SEP      bcax_m0 $vAki, $vBki, $vBku, $vBko
eor sAku, tmp,  sAku_, ROR #52                  SEP      bcax_m1 $vAko, $vBko, $vBka, $vBku
bic tmp, sAmi_, sAme_, ROR #38                  SEP
eor sAma, tmp,  sAma_, ROR #47                  SEP      eor2    $vC1,  $vAke, $vAge
bic tmp, sAmo_, sAmi_, ROR #5                   SEP      bcax_m0 $vAku, $vBku, $vBke, $vBka
eor sAme, tmp,  sAme_, ROR #43                  SEP
bic tmp, sAmu_, sAmo_, ROR #41                  SEP      eor2    $vC2,  $vAki, $vAgi
eor sAmi, tmp,  sAmi_, ROR #46                  SEP      bcax_m1 $vAma, $vBma, $vBmi, $vBme
bic tmp, sAma_, sAmu_, ROR #35                  SEP
ldr cur_const, [const_addr, count, UXTW #3]     SEP      eor2    $vC3,  $vAko, $vAgo
add count, count, #1                            SEP      bcax_m0 $vAme, $vBme, $vBmo, $vBmi
eor sAmo, tmp,  sAmo_, ROR #12                  SEP
bic tmp, sAme_, sAma_, ROR #9                   SEP      eor2    $vC4,  $vAku, $vAgu
eor sAmu, tmp,  sAmu_, ROR #44                  SEP      bcax_m1 $vAmi, $vBmi, $vBmu, $vBmo
bic tmp, sAsi_, sAse_, ROR #48                  SEP
eor sAsa, tmp,  sAsa_, ROR #41                  SEP      eor2    $vC0,  $vC0,  $vAma
bic tmp, sAso_, sAsi_, ROR #2                   SEP      bcax_m0 $vAmo, $vBmo, $vBma, $vBmu
eor sAse, tmp,  sAse_, ROR #50                  SEP
bic tmp, sAsu_, sAso_, ROR #25                  SEP      eor2    $vC1,  $vC1,  $vAme
eor sAsi, tmp,  sAsi_, ROR #27                  SEP
bic tmp, sAsa_, sAsu_, ROR #60                  SEP      bcax_m1 $vAmu, $vBmu, $vBme, $vBma
eor sAso, tmp,  sAso_, ROR #21                  SEP      eor2    $vC2,  $vC2,  $vAmi
bic tmp, sAse_, sAsa_, ROR #57                  SEP
eor sAsu, tmp,  sAsu_, ROR #53                  SEP      bcax_m0 $vAsa, $vBsa, $vBsi, $vBse
bic tmp, sAbi_, sAbe_, ROR #63                  SEP      eor2    $vC3,  $vC3,  $vAmo
eor s_Aba, s_Aba_, tmp,  ROR #21                SEP
bic tmp, sAbo_, sAbi_, ROR #42                  SEP      bcax_m1 $vAse, $vBse, $vBso, $vBsi
eor sAbe, tmp,  sAbe_, ROR #41                  SEP      eor2    $vC4,  $vC4,  $vAmu
bic tmp, sAbu_, sAbo_, ROR #57                  SEP
eor sAbi, tmp,  sAbi_, ROR #35                  SEP      bcax_m0 $vAsi, $vBsi, $vBsu, $vBso
bic tmp, s_Aba_, sAbu_, ROR #50                 SEP      eor2    $vC0,  $vC0,  $vAsa
eor sAbo, tmp,  sAbo_, ROR #43                  SEP
bic tmp, sAbe_, s_Aba_, ROR #44                 SEP      bcax_m1 $vAso, $vBso, $vBsa, $vBsu
eor sAbu, tmp,  sAbu_, ROR #30                  SEP      eor2    $vC1,  $vC1,  $vAse
eor s_Aba, s_Aba, cur_const                     SEP
save count, STACK_OFFSET_COUNT                  SEP      bcax_m0 $vAsu, $vBsu, $vBse, $vBsa
eor sC0, sAka, sAsa, ROR #50                    SEP      eor2    $vC2,  $vC2,  $vAsi
eor sC1, sAse, sAge, ROR #60                    SEP
eor sC2, sAmi, sAgi, ROR #59                    SEP      eor2    $vC3,  $vC3,  $vAso
eor sC3, sAgo, sAso, ROR #30                    SEP      bcax_m1 $vAba, $vBba, $vBbi, $vBbe
eor sC4, sAbu, sAsu, ROR #53                    SEP
eor sC0, sAma, sC0, ROR #49                     SEP      bcax_m0 $vAbe, $vBbe, $vBbo, $vBbi
eor sC1, sAbe, sC1, ROR #44                     SEP      eor2    $vC1,  $vC1,  $vAbe
eor sC2, sAki, sC2, ROR #26                     SEP
eor sC3, sAmo, sC3, ROR #63                     SEP      restore x30, STACK_OFFSET_CONST
eor sC4, sAmu, sC4, ROR #56                     SEP      ldr vvtmpq, [x30], #16
eor sC0, sAga, sC0, ROR #57                     SEP
eor sC1, sAme, sC1, ROR #58                     SEP      save x30, STACK_OFFSET_CONST
eor sC2, sAbi, sC2, ROR #60                     SEP
eor sC3, sAko, sC3, ROR #38                     SEP      eor $vAba.16b, $vAba.16b, vvtmp.16b
eor sC4, sAgu, sC4, ROR #48                     SEP      eor2    $vC4,  $vC4,  $vAsu
eor sC0, s_Aba, sC0, ROR #61                    SEP
eor sC1, sAke, sC1, ROR #57                     SEP      bcax_m0 $vAbi, $vBbi, $vBbu, $vBbo
eor sC2, sAsi, sC2, ROR #52                     SEP      bcax_m1 $vAbo, $vBbo, $vBba, $vBbu
eor sC3, sAbo, sC3, ROR #63                     SEP
eor sC4, sAku, sC4, ROR #50                     SEP      eor2    $vC3,  $vC3,  $vAbo
ror sC1, sC1, 56                                SEP      eor2    $vC2,  $vC2,  $vAbi
ror sC4, sC4, 58                                SEP
ror sC2, sC2, 62                                SEP      eor2    $vC0,  $vC0,  $vAba
eor sE1, sC0, sC2, ROR #63                      SEP      bcax_m0 $vAbu, $vBbu, $vBbe, $vBba
eor sE3, sC2, sC4, ROR #63                      SEP
eor sE0, sC4, sC1, ROR #63                      SEP      eor2    $vC4,  $vC4,  $vAbu
eor sE2, sC1, sC3, ROR #63                      SEP      ldr $vAgaq, [sp, #(STACK_BASE_TMP + 16 * vAga_offset)]
eor sE4, sC3, sC0, ROR #63                      SEP
eor s_Aba_, sE0, s_Aba                          SEP      .unreq vvtmp
eor sAsa_, sE2, sAbi, ROR #50                   SEP      .unreq vvtmpq
eor sAbi_, sE2, sAki, ROR #46                   SEP
eor sAki_, sE3, sAko, ROR #63                   SEP      vvtmp .req $vBba
eor sAko_, sE4, sAmu, ROR #28                   SEP      rax1_m0 $vE2, $vC1, $vC3
eor sAmu_, sE3, sAso, ROR #2                    SEP
eor sAso_, sE0, sAma, ROR #54                   SEP      rax1_m1 $vE4, $vC3, $vC0
eor sAka_, sE1, sAbe, ROR #43                   SEP      rax1_m0 $vE1, $vC0, $vC2
eor sAse_, sE3, sAgo, ROR #36                   SEP
eor sAgo_, sE1, sAme, ROR #49                   SEP      rax1_m1 $vE3, $vC2, $vC4
eor sAke_, sE2, sAgi, ROR #3                    SEP      rax1_m0 $vE0, $vC4, $vC1
eor sAgi_, sE0, sAka, ROR #39                   SEP
eor sAga_, sE3, sAbo                            SEP      .unreq vvtmp
eor sAbo_, sE3, sAmo, ROR #37                   SEP
eor sAmo_, sE2, sAmi, ROR #8                    SEP      vvtmp .req $vC1
eor sAmi_, sE1, sAke, ROR #56                   SEP      vvtmpq .req  $C1q
eor sAge_, sE4, sAgu, ROR #44                   SEP
eor sAgu_, sE2, sAsi, ROR #62                   SEP      eor $vBba.16b, $vAba.16b, $vE0.16b
eor sAsi_, sE4, sAku, ROR #58                   SEP      xar_m1 $vBsa, $vAbi, $vE2, 2
eor sAku_, sE0, sAsa, ROR #25                   SEP
eor sAma_, sE4, sAbu, ROR #20                   SEP      xar_m1 $vBbi, $vAki, $vE2, 21
eor sAbu_, sE4, sAsu, ROR #9                    SEP      xar_m1 $vBki, $vAko, $vE3, 39
eor sAsu_, sE1, sAse, ROR #23                   SEP
eor sAme_, sE0, sAga, ROR #61                   SEP      xar_m1 $vBko, $vAmu, $vE4, 56
eor sAbe_, sE1, sAge, ROR #19                   SEP      xar_m1 $vBmu, $vAso, $vE3, 8
load_constant_ptr                               SEP
restore count, STACK_OFFSET_COUNT               SEP      xar_m1 $vBso, $vAma, $vE0, 23
bic tmp, sAgi_, sAge_, ROR #47                  SEP      xar_m1 $vBka, $vAbe, $vE1, 63
eor sAga, tmp,  sAga_, ROR #39                  SEP
bic tmp, sAgo_, sAgi_, ROR #42                  SEP      xar_m1 $vBse, $vAgo, $vE3, 9
eor sAge, tmp,  sAge_, ROR #25                  SEP      xar_m1 $vBgo, $vAme, $vE1, 19
bic tmp, sAgu_, sAgo_, ROR #16                  SEP
eor sAgi, tmp,  sAgi_, ROR #58                  SEP      xar_m1 $vBke, $vAgi, $vE2, 58
bic tmp, sAga_, sAgu_, ROR #31                  SEP      xar_m1 $vBgi, $vAka, $vE0, 61
eor sAgo, tmp,  sAgo_, ROR #47                  SEP
bic tmp, sAge_, sAga_, ROR #56                  SEP      xar_m1 $vBga, $vAbo, $vE3, 36
eor sAgu, tmp,  sAgu_, ROR #23                  SEP      xar_m1 $vBbo, $vAmo, $vE3, 43
bic tmp, sAki_, sAke_, ROR #19                  SEP
eor sAka, tmp,  sAka_, ROR #24                  SEP      xar_m1 $vBmo, $vAmi, $vE2, 49
bic tmp, sAko_, sAki_, ROR #47                  SEP      xar_m1 $vBmi, $vAke, $vE1, 54
eor sAke, tmp,  sAke_, ROR #2                   SEP
bic tmp, sAku_, sAko_, ROR #10                  SEP      xar_m1 $vBge, $vAgu, $vE4, 44
eor sAki, tmp,  sAki_, ROR #57                  SEP      mov $vE3.16b, $vAga.16b
bic tmp, sAka_, sAku_, ROR #47                  SEP
eor sAko, tmp,  sAko_, ROR #57                  SEP      bcax_m1 $vAga, $vBga, $vBgi, $vBge
bic tmp, sAke_, sAka_, ROR #5                   SEP
eor sAku, tmp,  sAku_, ROR #52                  SEP      xar_m1 $vBgu, $vAsi, $vE2, 3
bic tmp, sAmi_, sAme_, ROR #38                  SEP      xar $vBsi, $vAku, $vE4, #25
eor sAma, tmp,  sAma_, ROR #47                  SEP
bic tmp, sAmo_, sAmi_, ROR #5                   SEP      xar_m0 $vBku, $vAsa, $vE0, #46
eor sAme, tmp,  sAme_, ROR #43                  SEP      xar $vBma, $vAbu, $vE4, #37
bic tmp, sAmu_, sAmo_, ROR #41                  SEP
eor sAmi, tmp,  sAmi_, ROR #46                  SEP      xar $vBbu, $vAsu, $vE4, #50
bic tmp, sAma_, sAmu_, ROR #35                  SEP      xar_m1 $vBsu, $vAse, $vE1, 62
ldr cur_const, [const_addr, count, UXTW #3]     SEP
add count, count, #1                            SEP      xar $vBme, $vE3, $vE0, #28
eor sAmo, tmp,  sAmo_, ROR #12                  SEP      xar $vBbe, $vAge, $vE1, #20
bic tmp, sAme_, sAma_, ROR #9                   SEP
eor sAmu, tmp,  sAmu_, ROR #44                  SEP      bcax_m0 $vAge, $vBge, $vBgo, $vBgi
bic tmp, sAsi_, sAse_, ROR #48                  SEP      bcax_m1 $vAgi, $vBgi, $vBgu, $vBgo
eor sAsa, tmp,  sAsa_, ROR #41                  SEP
bic tmp, sAso_, sAsi_, ROR #2                   SEP      bcax_m0 $vAgo, $vBgo, $vBga, $vBgu
eor sAse, tmp,  sAse_, ROR #50                  SEP      bcax_m1 $vAgu, $vBgu, $vBge, $vBga
bic tmp, sAsu_, sAso_, ROR #25                  SEP
eor sAsi, tmp,  sAsi_, ROR #27                  SEP      bcax_m0 $vAka, $vBka, $vBki, $vBke
bic tmp, sAsa_, sAsu_, ROR #60                  SEP      bcax_m1 $vAke, $vBke, $vBko, $vBki
eor sAso, tmp,  sAso_, ROR #21                  SEP
bic tmp, sAse_, sAsa_, ROR #57                  SEP      bcax_m0 $vAki, $vBki, $vBku, $vBko
eor sAsu, tmp,  sAsu_, ROR #53                  SEP      bcax_m1 $vAko, $vBko, $vBka, $vBku
bic tmp, sAbi_, sAbe_, ROR #63                  SEP
eor s_Aba, s_Aba_, tmp,  ROR #21                SEP      bcax_m0 $vAku, $vBku, $vBke, $vBka
bic tmp, sAbo_, sAbi_, ROR #42                  SEP      bcax_m1 $vAma, $vBma, $vBmi, $vBme
eor sAbe, tmp,  sAbe_, ROR #41                  SEP
bic tmp, sAbu_, sAbo_, ROR #57                  SEP      bcax_m0 $vAme, $vBme, $vBmo, $vBmi
eor sAbi, tmp,  sAbi_, ROR #35                  SEP
bic tmp, s_Aba_, sAbu_, ROR #50                 SEP      bcax_m1 $vAmi, $vBmi, $vBmu, $vBmo
eor sAbo, tmp,  sAbo_, ROR #43                  SEP      bcax_m0 $vAmo, $vBmo, $vBma, $vBmu
bic tmp, sAbe_, s_Aba_, ROR #44                 SEP
eor sAbu, tmp,  sAbu_, ROR #30                  SEP      bcax_m1 $vAmu, $vBmu, $vBme, $vBma
eor s_Aba, s_Aba, cur_const                     SEP      bcax_m0 $vAsa, $vBsa, $vBsi, $vBse
ror sAga, sAga,(64-3)                           SEP
ror sAka, sAka,(64-25)                          SEP      bcax_m1 $vAse, $vBse, $vBso, $vBsi
ror sAma, sAma,(64-10)                          SEP      bcax_m0 $vAsi, $vBsi, $vBsu, $vBso
ror sAsa, sAsa,(64-39)                          SEP
ror sAbe, sAbe,(64-21)                          SEP      bcax_m1 $vAso, $vBso, $vBsa, $vBsu
ror sAge, sAge,(64-45)                          SEP      bcax_m0 $vAsu, $vBsu, $vBse, $vBsa
ror sAke, sAke,(64-8)                           SEP
ror sAme, sAme,(64-15)                          SEP      bcax_m1 $vAba, $vBba, $vBbi, $vBbe
ror sAse, sAse,(64-41)                          SEP      bcax_m0 $vAbe, $vBbe, $vBbo, $vBbi
ror sAbi, sAbi,(64-14)                          SEP
ror sAgi, sAgi,(64-61)                          SEP      bcax_m1 $vAbi, $vBbi, $vBbu, $vBbo
ror sAki, sAki,(64-18)                          SEP      bcax_m0 $vAbo, $vBbo, $vBba, $vBbu
ror sAmi, sAmi,(64-56)                          SEP      
ror sAsi, sAsi,(64-2)                           SEP      bcax_m1 $vAbu, $vBbu, $vBbe, $vBba
ror sAgo, sAgo,(64-28)                          SEP
ror sAko, sAko,(64-1)                           SEP
ror sAmo, sAmo,(64-27)                          SEP      restore x26, STACK_OFFSET_CONST
ror sAso, sAso,(64-62)                          SEP      ldr vvtmpq, [x26], #16
ror sAbu, sAbu,(64-44)                          SEP
ror sAgu, sAgu,(64-20)                          SEP      save x26, STACK_OFFSET_CONST
ror sAku, sAku,(64-6)                           SEP      eor $vAba.16b, $vAba.16b, vvtmp.16b
                                                SEP   //movi v0.4s, #0
                                                SEP   //movi v1.4s, #1
                                                SEP   //xar v0.2d, v1.2d, v0.2d, 2
                                                SEP   //xar v0.2d, v0.2d, v0.2d, 2
                                                SEP   //movi v24.4s, #0

                                                SEP   //xar $vBsa, $vAbi, $vE2, 2
ror sAmu, sAmu,(64-36)                          SEP      .unreq vvtmp
ror sAsu, sAsu,(64-55)                          SEP      .unreq vvtmpq
.endm

#define KECCAK_F1600_ROUNDS 24

.text
.align 4
.global keccak_f1600_x3_hybrid_asm_v6
.global _keccak_f1600_x3_hybrid_asm_v6

keccak_f1600_x3_hybrid_asm_v6:
_keccak_f1600_x3_hybrid_asm_v6:
     alloc_stack
    save_gprs
    save_vregs
    save input_addr, STACK_OFFSET_INPUT


     adr const_addr, round_constants_vec

     save const_addr, STACK_OFFSET_CONST
     load_input_vector 1,0

     add input_addr, input_addr, #16
     load_input_scalar 1,0  
     hybrid_round_initial
    loop_0:
        hybrid_round_noninitial
        cmp count, #(KECCAK_F1600_ROUNDS-3)
        ble loop_0

        hybrid_round_final

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