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

#define SEP ;
#include <openssl/arm_arch.h>
.type	round_constants, %object
_round_constants:
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
.size	_round_constants, .-_round_constants

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

    $input_addr  = "x0";
    $const_addr  = "x1";
    $count       = "x2";
    $cur_const   = "x3";

    $vAba     = "v0";
    $vAbe     = "v1";
    $vAbi     = "v2";
    $vAbo     = "v3";
    $vAbu     = "v4";
    $vAga     = "v5";
    $vAge     = "v6";
    $vAgi     = "v7";
    $vAgo     = "v8";
    $vAgu     = "v9";
    $vAka     = "v10";
    $vAke     = "v11";
    $vAki     = "v12";
    $vAko     = "v13";
    $vAku     = "v14";
    $vAma     = "v15";
    $vAme     = "v16";
    $vAmi     = "v17";
    $vAmo     = "v18";
    $vAmu     = "v19";
    $vAsa     = "v20";
    $vAse     = "v21";
    $vAsi     = "v22";
    $vAso     = "v23";
    $vAsu     = "v24";

    $Abaq   = "q0";
    $Abeq   = "q1";
    $Abiq   = "q2";
    $Aboq   = "q3";
    $Abuq   = "q4";
    $Agaq   = "q5";
    $Ageq   = "q6";
    $Agiq   = "q7";
    $Agoq   = "q8";
    $Aguq   = "q9";
    $Akaq   = "q10";
    $Akeq   = "q11";
    $Akiq   = "q12";
    $Akoq   = "q13";
    $Akuq   = "q14";
    $Amaq   = "q15";
    $Ameq   = "q16";
    $Amiq   = "q17";
    $Amoq   = "q18";
    $Amuq   = "q19";
    $Asaq   = "q20";
    $Aseq   = "q21";
    $Asiq   = "q22";
    $Asoq   = "q23";
    $Asuq   = "q24";

    $vC0  = "v27";
    $vC1  = "v28";
    $vC2  = "v29";
    $vC3  = "v30";
    $vC4  = "v31";

    $vC0q = "q27";
    $vC1q = "q28";
    $vC2q = "q29";
    $vC3q = "q30";
    $vC4q = "q31";

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

    $vE0  = "v31";
    $vE1  = "v27";
    $vE2  = "v26"; 
    $vE3  = "v29";
    $vE4  = "v30";
    
    $vE0q =  "q31";
    $vE1q =  "q27";
    $vE2q =  "q26"; 
    $vE3q =  "q29";
    $vE4q =  "q30";

	


$code.=<<___;

/****************** REGISTER ALLOCATIONS *******************/


    /* Mapping of Kecck-f1600 state to vector registers
     * at the beginning and end of each round. */
    
.macro load_constant_ptr
	adr $const_addr, round_constants
.endm

/************************ MACROS ****************************/

.macro load_input
    ldp $Abaq, $Abeq, [$input_addr, #(2*8*0)]
    ldp $Abiq, $Aboq, [$input_addr, #(2*8*2)]
    ldp $Abuq, $Agaq, [$input_addr, #(2*8*4)]
    ldp $Ageq, $Agiq, [$input_addr, #(2*8*6)]
    ldp $Agoq, $Aguq, [$input_addr, #(2*8*8)]
    ldp $Akaq, $Akeq, [$input_addr, #(2*8*10)]
    ldp $Akiq, $Akoq, [$input_addr, #(2*8*12)]
    ldp $Akuq, $Amaq, [$input_addr, #(2*8*14)]
    ldp $Ameq, $Amiq, [$input_addr, #(2*8*16)]
    ldp $Amoq, $Amuq, [$input_addr, #(2*8*18)]
    ldp $Asaq, $Aseq, [$input_addr, #(2*8*20)]
    ldp $Asiq, $Asoq, [$input_addr, #(2*8*22)]
    ldr $Asuq, [$input_addr, #(2*8*24)]
.endm

.macro store_input
    str $Abaq, [$input_addr, #(2*8*0)]
    str $Abeq, [$input_addr, #(2*8*1)]
    str $Abiq, [$input_addr, #(2*8*2)]
    str $Aboq, [$input_addr, #(2*8*3)]
    str $Abuq, [$input_addr, #(2*8*4)]
    str $Agaq, [$input_addr, #(2*8*5)]
    str $Ageq, [$input_addr, #(2*8*6)]
    str $Agiq, [$input_addr, #(2*8*7)]
    str $Agoq, [$input_addr, #(2*8*8)]
    str $Aguq, [$input_addr, #(2*8*9)]
    str $Akaq, [$input_addr, #(2*8*10)]
    str $Akeq, [$input_addr, #(2*8*11)]
    str $Akiq, [$input_addr, #(2*8*12)]
    str $Akoq, [$input_addr, #(2*8*13)]
    str $Akuq, [$input_addr, #(2*8*14)]
    str $Amaq, [$input_addr, #(2*8*15)]
    str $Ameq, [$input_addr, #(2*8*16)]
    str $Amiq, [$input_addr, #(2*8*17)]
    str $Amoq, [$input_addr, #(2*8*18)]
    str $Amuq, [$input_addr, #(2*8*19)]
    str $Asaq, [$input_addr, #(2*8*20)]
    str $Aseq, [$input_addr, #(2*8*21)]
    str $Asiq, [$input_addr, #(2*8*22)]
    str $Asoq, [$input_addr, #(2*8*23)]
    str $Asuq, [$input_addr, #(2*8*24)]
.endm

#define STACK_SIZE (16*4 + 16*34)
#define STACK_BASE_VREGS 0
#define STACK_BASE_TMP   16*4

#define Aga_offset 0

.macro alloc_stack
   sub sp, sp, #(STACK_SIZE)
.endm

.macro free_stack
    add sp, sp, #(STACK_SIZE)
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

/* Macros using v8.4-A SHA-3 instructions */

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
    bic tmp.16b, \\s1\\().16b, \\s2\\().16b
    eor \\d\\().16b, tmp.16b, \\s0\\().16b
.endm

/* Keccak-f1600 round */

.macro keccak_f1600_round_pre

    /* 10 EOR3, so 20 individual EOR */

    eor3_m0 $vC1, $vAbe, $vAge, $vAke
    eor3_m1 $vC3, $vAbo, $vAgo, $vAko
    eor3_m0 $vC0, $vAba, $vAga, $vAka
    eor3_m1 $vC2, $vAbi, $vAgi, $vAki
    eor3_m0 $vC4, $vAbu, $vAgu, $vAku
    eor3_m1 $vC1, $vC1, $vAme,  $vAse
    eor3_m0 $vC3, $vC3, $vAmo,  $vAso
    eor3_m1 $vC0, $vC0, $vAma,  $vAsa
    eor3_m0 $vC2, $vC2, $vAmi,  $vAsi
    eor3_m1 $vC4, $vC4, $vAmu,  $vAsu

.endm

.macro keccak_f1600_round
    eor3_m1_0 $vC0, $vAba, $vAga, $vAka
    eor3_m1_0 $vC1, $vAbe, $vAge, $vAke
    eor3_m1_0 $vC2, $vAbi, $vAgi, $vAki
    eor3_m1_0 $vC3, $vAbo, $vAgo, $vAko
    eor3_m1_0 $vC4, $vAbu, $vAgu, $vAku
    eor3_m1_1 $vC0, $vAba, $vAga, $vAka
    eor3_m1_1 $vC1, $vAbe, $vAge, $vAke
    eor3_m1_1 $vC2, $vAbi, $vAgi, $vAki
    eor3_m1_1 $vC3, $vAbo, $vAgo, $vAko
    eor3_m1_1 $vC4, $vAbu, $vAgu, $vAku
    eor3_m1_0 $vC0, $vC0, $vAma,  $vAsa
    eor3_m1_0 $vC1, $vC1, $vAme,  $vAse
    eor3_m1_0 $vC2, $vC2, $vAmi,  $vAsi
    eor3_m1_0 $vC3, $vC3, $vAmo,  $vAso
    eor3_m1_0 $vC4, $vC4, $vAmu,  $vAsu
    eor3_m1_1 $vC0, $vC0, $vAma,  $vAsa
    eor3_m1_1 $vC1, $vC1, $vAme,  $vAse
    eor3_m1_1 $vC2, $vC2, $vAmi,  $vAsi
    eor3_m1_1 $vC3, $vC3, $vAmo,  $vAso
    eor3_m1_1 $vC4, $vC4, $vAmu,  $vAsu

    tmp .req $vBba
    rax1_m1 $vE2, $vC1, $vC3
    rax1_m1 $vE4, $vC3, $vC0
    rax1_m1 $vE1, $vC0, $vC2
    rax1_m1 $vE3, $vC2, $vC4
    rax1_m1 $vE0, $vC4, $vC1
    .unreq tmp

    tmp  .req $vC1
    tmpq .req $vC1q

    eor $vBba.16b, $vAba.16b, $vE0.16b
    xar_m1 $vBsa, $vAbi, $vE2, 2
    xar_m1 $vBbi, $vAki, $vE2, 21
    xar_m1 $vBki, $vAko, $vE3, 39
    xar_m1 $vBko, $vAmu, $vE4, 56
    xar_m1 $vBmu, $vAso, $vE3, 8
    xar_m1 $vBso, $vAma, $vE0, 23
    xar_m1 $vBka, $vAbe, $vE1, 63
    xar_m1 $vBse, $vAgo, $vE3, 9
    xar_m1 $vBgo, $vAme, $vE1, 19
    xar_m1 $vBke, $vAgi, $vE2, 58
    xar_m1 $vBgi, $vAka, $vE0, 61
    xar_m1 $vBga, $vAbo, $vE3, 36
    xar_m1 $vBbo, $vAmo, $vE3, 43
    xar_m1 $vBmo, $vAmi, $vE2, 49
    xar_m1 $vBmi, $vAke, $vE1, 54
    xar_m1 $vBge, $vAgu, $vE4, 44
    xar_m1 $vBgu, $vAsi, $vE2, 3
    xar_m1 $vBsi, $vAku, $vE4, 25
    xar_m1 $vBku, $vAsa, $vE0, 46
    xar_m1 $vBma, $vAbu, $vE4, 37
    xar_m1 $vBbu, $vAsu, $vE4, 50
    xar_m1 $vBsu, $vAse, $vE1, 62
    xar_m1 $vBme, $vAga, $vE0, 28
    xar_m1 $vBbe, $vAge, $vE1, 20

    bcax_m1 $vAga, $vBga, $vBgi, $vBge
    bcax_m1 $vAge, $vBge, $vBgo, $vBgi
    bcax_m1 $vAgi, $vBgi, $vBgu, $vBgo
    bcax_m1 $vAgo, $vBgo, $vBga, $vBgu
    bcax_m1 $vAgu, $vBgu, $vBge, $vBga
    bcax_m1 $vAka, $vBka, $vBki, $vBke
    bcax_m1 $vAke, $vBke, $vBko, $vBki
    bcax_m1 $vAki, $vBki, $vBku, $vBko
    bcax_m1 $vAko, $vBko, $vBka, $vBku
    bcax_m1 $vAku, $vBku, $vBke, $vBka
    bcax_m1 $vAma, $vBma, $vBmi, $vBme
    bcax_m1 $vAme, $vBme, $vBmo, $vBmi
    bcax_m1 $vAmi, $vBmi, $vBmu, $vBmo
    bcax_m1 $vAmo, $vBmo, $vBma, $vBmu
    bcax_m1 $vAmu, $vBmu, $vBme, $vBma
    bcax_m1 $vAsa, $vBsa, $vBsi, $vBse
    bcax_m1 $vAse, $vBse, $vBso, $vBsi
    bcax_m1 $vAsi, $vBsi, $vBsu, $vBso
    bcax_m1 $vAso, $vBso, $vBsa, $vBsu
    bcax_m1 $vAsu, $vBsu, $vBse, $vBsa
    bcax_m1 $vAba, $vBba, $vBbi, $vBbe
    bcax_m1 $vAbe, $vBbe, $vBbo, $vBbi
    bcax_m1 $vAbi, $vBbi, $vBbu, $vBbo
    bcax_m1 $vAbo, $vBbo, $vBba, $vBbu
    bcax_m1 $vAbu, $vBbu, $vBbe, $vBba

    // iota step
    //ld1r {tmp.2d}, [$const_addr], #8
    ldr tmpq, [$const_addr], #16
    eor $vAba.16b, $vAba.16b, tmp.16b

    .unreq tmp
    .unreq tmpq

.endm

.macro keccak_f1600_round_core

    /* 5x RAX1, 15 Neon Instructions total */

    tmp .req $vBba
    rax1_m0 $vE2, $vC1, $vC3
    rax1_m1 $vE4, $vC3, $vC0
    rax1_m0 $vE1, $vC0, $vC2
    rax1_m1 $vE3, $vC2, $vC4
    rax1_m0 $vE0, $vC4, $vC1

    /* 25x XAR, 75 in total */

    .unreq tmp
    tmp .req $vC1
    tmpq .req $vC1q

    eor $vBba.16b, $vAba.16b, $vE0.16b
    xar_m1 $vBsa, $vAbi, $vE2, 2
    xar_m0 $vBbi, $vAki, $vE2, #21
    xar_m1 $vBki, $vAko, $vE3, 39
    xar_m0 $vBko, $vAmu, $vE4, #56
    xar_m1 $vBmu, $vAso, $vE3, 8
    xar_m0 $vBso, $vAma, $vE0, #23
    xar_m1 $vBka, $vAbe, $vE1, 63
    xar_m0 $vBse, $vAgo, $vE3, #9
    xar_m1 $vBgo, $vAme, $vE1, 19
    xar_m0 $vBke, $vAgi, $vE2, #58
    xar_m1 $vBgi, $vAka, $vE0, 61
    xar_m0 $vBga, $vAbo, $vE3, #36
    xar_m1 $vBbo, $vAmo, $vE3, 43
    xar_m0 $vBmo, $vAmi, $vE2, #49
    xar_m1 $vBmi, $vAke, $vE1, 54
    xar_m0 $vBge, $vAgu, $vE4, #44
    mov $vE3.16b, $vAga.16b
    bcax_m1 $vAga, $vBga, $vBgi, $vBge
    xar_m0 $vBgu, $vAsi, $vE2, #3
    xar_m1 $vBsi, $vAku, $vE4, 25
    xar_m0 $vBku, $vAsa, $vE0, #46
    xar_m1 $vBma, $vAbu, $vE4, 37
    xar_m0 $vBbu, $vAsu, $vE4, #50
    xar_m1 $vBsu, $vAse, $vE1, 62
    xar_m0 $vBme, $vE3, $vE0, #28
    xar_m1 $vBbe, $vAge, $vE1, 20

    /* 25x BCAX, 50 in total */

    bcax_m1 $vAge, $vBge, $vBgo, $vBgi
    bcax_m0 $vAgi, $vBgi, $vBgu, $vBgo
    bcax_m1 $vAgo, $vBgo, $vBga, $vBgu
    bcax_m0 $vAgu, $vBgu, $vBge, $vBga
    bcax_m1 $vAka, $vBka, $vBki, $vBke
    bcax_m0 $vAke, $vBke, $vBko, $vBki

    .unreq tmp
    .unreq tmpq

    eor2    $vC0,  $vAka, $vAga
    str $Agaq, [sp, #(STACK_BASE_TMP + 16 * Aga_offset)]

    tmp .req $vAga
    tmpq .req $Agaq
    bcax_m0 $vAki, $vBki, $vBku, $vBko
    bcax_m1 $vAko, $vBko, $vBka, $vBku
    eor2    $vC1,  $vAke, $vAge
    bcax_m0 $vAku, $vBku, $vBke, $vBka
    eor2    $vC2,  $vAki, $vAgi
    bcax_m1 $vAma, $vBma, $vBmi, $vBme
    eor2    $vC3,  $vAko, $vAgo
    bcax_m0 $vAme, $vBme, $vBmo, $vBmi
    eor2    $vC4,  $vAku, $vAgu
    bcax_m1 $vAmi, $vBmi, $vBmu, $vBmo
    eor2    $vC0,  $vC0,  $vAma
    bcax_m0 $vAmo, $vBmo, $vBma, $vBmu
    eor2    $vC1,  $vC1,  $vAme
    bcax_m1 $vAmu, $vBmu, $vBme, $vBma
    eor2    $vC2,  $vC2,  $vAmi
    bcax_m0 $vAsa, $vBsa, $vBsi, $vBse
    eor2    $vC3,  $vC3,  $vAmo
    bcax_m1 $vAse, $vBse, $vBso, $vBsi
    eor2    $vC4,  $vC4,  $vAmu
    bcax_m0 $vAsi, $vBsi, $vBsu, $vBso
    eor2    $vC0,  $vC0,  $vAsa
    bcax_m1 $vAso, $vBso, $vBsa, $vBsu
    eor2    $vC1,  $vC1,  $vAse
    bcax_m0 $vAsu, $vBsu, $vBse, $vBsa
    eor2    $vC2,  $vC2,  $vAsi
    eor2    $vC3,  $vC3,  $vAso
    bcax_m1 $vAba, $vBba, $vBbi, $vBbe
    bcax_m0 $vAbe, $vBbe, $vBbo, $vBbi
    eor2    $vC1,  $vC1,  $vAbe

    // iota step
    //ld1r {tmp.2d}, [$const_addr], #8
    ldr tmpq, [$const_addr], #16
    eor $vAba.16b, $vAba.16b, tmp.16b
    eor2    $vC4,  $vC4,  $vAsu
    bcax_m0 $vAbi, $vBbi, $vBbu, $vBbo
    bcax_m1 $vAbo, $vBbo, $vBba, $vBbu
    eor2    $vC3,  $vC3,  $vAbo
    eor2    $vC2,  $vC2,  $vAbi
    eor2    $vC0,  $vC0,  $vAba
    bcax_m0 $vAbu, $vBbu, $vBbe, $vBba
    eor2    $vC4,  $vC4,  $vAbu

    ldr $Agaq, [sp, #(STACK_BASE_TMP + 16 * Aga_offset)]
    .unreq tmp
    .unreq tmpq

.endm

.macro keccak_f1600_round_post
    tmp .req $vBba
    rax1_m0 $vE2, $vC1, $vC3
    rax1_m1 $vE4, $vC3, $vC0
    rax1_m0 $vE1, $vC0, $vC2
    rax1_m1 $vE3, $vC2, $vC4
    rax1_m0 $vE0, $vC4, $vC1

    .unreq tmp
    tmp .req $vC1
    tmpq .req $vC1q

    eor $vBba.16b, $vAba.16b, $vE0.16b
    xar_m0 $vBsa, $vAbi, $vE2, #2
    xar_m1 $vBbi, $vAki, $vE2, 21
    xar_m0 $vBki, $vAko, $vE3, #39
    xar_m1 $vBko, $vAmu, $vE4, 56
    xar_m0 $vBmu, $vAso, $vE3, #8
    xar_m1 $vBso, $vAma, $vE0, 23
    xar_m0 $vBka, $vAbe, $vE1, #63
    xar_m1 $vBse, $vAgo, $vE3, 9
    xar_m0 $vBgo, $vAme, $vE1, #19
    xar_m1 $vBke, $vAgi, $vE2, 58
    xar_m0 $vBgi, $vAka, $vE0, #61
    xar_m1 $vBga, $vAbo, $vE3, 36
    xar_m0 $vBbo, $vAmo, $vE3, #43
    xar_m1 $vBmo, $vAmi, $vE2, 49
    xar_m0 $vBmi, $vAke, $vE1, #54
    xar_m1 $vBge, $vAgu, $vE4, 44
    mov $vE3.16b, $vAga.16b
    bcax_m1 $vAga, $vBga, $vBgi, $vBge
    xar_m0 $vBgu, $vAsi, $vE2, #3
    xar_m1 $vBsi, $vAku, $vE4, 25
    xar_m0 $vBku, $vAsa, $vE0, #46
    xar_m1 $vBma, $vAbu, $vE4, 37
    xar_m0 $vBbu, $vAsu, $vE4, #50
    xar_m1 $vBsu, $vAse, $vE1, 62
    xar_m0 $vBme, $vE3, $vE0, #28
    xar_m1 $vBbe, $vAge, $vE1, 20

    bcax_m0 $vAge, $vBge, $vBgo, $vBgi
    bcax_m1 $vAgi, $vBgi, $vBgu, $vBgo
    bcax_m0 $vAgo, $vBgo, $vBga, $vBgu
    bcax_m1 $vAgu, $vBgu, $vBge, $vBga
    bcax_m0 $vAka, $vBka, $vBki, $vBke
    bcax_m1 $vAke, $vBke, $vBko, $vBki
    bcax_m0 $vAki, $vBki, $vBku, $vBko
    bcax_m1 $vAko, $vBko, $vBka, $vBku
    bcax_m0 $vAku, $vBku, $vBke, $vBka
    bcax_m1 $vAma, $vBma, $vBmi, $vBme
    bcax_m0 $vAme, $vBme, $vBmo, $vBmi
    bcax_m1 $vAmi, $vBmi, $vBmu, $vBmo
    bcax_m0 $vAmo, $vBmo, $vBma, $vBmu
    bcax_m1 $vAmu, $vBmu, $vBme, $vBma
    bcax_m0 $vAsa, $vBsa, $vBsi, $vBse
    bcax_m1 $vAse, $vBse, $vBso, $vBsi
    bcax_m0 $vAsi, $vBsi, $vBsu, $vBso
    bcax_m1 $vAso, $vBso, $vBsa, $vBsu
    bcax_m0 $vAsu, $vBsu, $vBse, $vBsa
    bcax_m1 $vAba, $vBba, $vBbi, $vBbe
    bcax_m0 $vAbe, $vBbe, $vBbo, $vBbi
    bcax_m1 $vAbi, $vBbi, $vBbu, $vBbo
    bcax_m0 $vAbo, $vBbo, $vBba, $vBbu
    bcax_m1 $vAbu, $vBbu, $vBbe, $vBba

    // iota step
    //ld1r {tmp.2d}, [$const_addr], #8
    ldr tmpq, [$const_addr], #16
    eor $vAba.16b, $vAba.16b, tmp.16b

    .unreq tmp
    .unreq tmpq

.endm

.text
.align 4
.global keccak_f1600_x2_hybrid_asm_v2pp2
.global _keccak_f1600_x2_hybrid_asm_v2pp2

#define KECCAK_F1600_ROUNDS 24

keccak_f1600_x2_hybrid_asm_v2pp2:
_keccak_f1600_x2_hybrid_asm_v2pp2:
    alloc_stack
    save_vregs
    load_constant_ptr
    load_input

    //mov count, #(KECCAK_F1600_ROUNDS-2)
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
    "bcax_m0"    => 0xce200000,    "xar_m0"    => 0xce800000 );

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