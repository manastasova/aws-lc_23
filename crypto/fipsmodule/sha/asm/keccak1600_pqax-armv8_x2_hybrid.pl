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

    $Aba     = "v0";
    $Abe     = "v1";
    $Abi     = "v2";
    $Abo     = "v3";
    $Abu     = "v4";
    $Aga     = "v5";
    $Age     = "v6";
    $Agi     = "v7";
    $Ago     = "v8";
    $Agu     = "v9";
    $Aka     = "v10";
    $Ake     = "v11";
    $Aki     = "v12";
    $Ako     = "v13";
    $Aku     = "v14";
    $Ama     = "v15";
    $Ame     = "v16";
    $Ami     = "v17";
    $Amo     = "v18";
    $Amu     = "v19";
    $Asa     = "v20";
    $Ase     = "v21";
    $Asi     = "v22";
    $Aso     = "v23";
    $Asu     = "v24";

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

    $C0  = "v27";
    $C1  = "v28";
    $C2  = "v29";
    $C3  = "v30";
    $C4  = "v31";

    $C0q = "q27";
    $C1q = "q28";
    $C2q = "q29";
    $C3q = "q30";
    $C4q = "q31";

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

    $vBbaq = "q25" ;
    $vBbeq = "q26" ;
    $vBbiq = "q2";
    $vBboq = "q3";
    $vBbuq = "q4";
    $vBgaq = "q10";
    $vBgeq = "q11";
    $vBgiq = "q7";
    $vBgoq = "q8";
    $vBguq = "q9";
    $vBkaq = "q15";
    $vBkeq = "q16";
    $vBkiq = "q12";
    $vBkoq = "q13";
    $vBkuq = "q14";
    $vBmaq = "q20";
    $vBmeq = "q21";
    $vBmiq = "q17";
    $vBmoq = "q18";
    $vBmuq = "q19";
    $vBsaq = "q0";
    $vBseq = "q1";
    $vBsiq = "q22";
    $vBsoq = "q23";
    $vBsuq = "q24";

    $E0  = "v31";
    $E1  = "v27";
    $E2  = "v26"; 
    $E3  = "v29";
    $E4  = "v30";
    $E0q = "q31";
    $E1q = "q27";
    $E2q = "q26" ;
    $E3q = "q29";
    $E4q = "q30";
	


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
   .elseif \\imm == 62
     eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
     add \\d\\().2d, \\s0\\().2d, \\s0\\().2d
     add \\d\\().2d, \\d\\().2d,  \\d\\().2d
     sri \\d\\().2d, \\s0\\().2d, #(62)
   // .elseif \\imm == 61
   //   eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
   //   add \\d\\().2d, \\s0\\().2d, \\s0\\().2d
   //   add \\d\\().2d, \\d\\().2d,  \\d\\().2d
   //   add \\d\\().2d, \\d\\().2d,  \\d\\().2d
   //   sri \\d\\().2d, \\s0\\().2d, #(61)
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


.macro keccak_f1600_round_pre

    eor3_m1_0 $C1, $Abe, $Age, $Ake
    eor3_m1_0 $C3, $Abo, $Ago, $Ako
    eor3_m1_0 $C0, $Aba, $Aga, $Aka
    eor3_m1_0 $C2, $Abi, $Agi, $Aki
    eor3_m1_0 $C4, $Abu, $Agu, $Aku
    eor3_m1_1 $C1, $Abe, $Age, $Ake
    eor3_m1_1 $C3, $Abo, $Ago, $Ako
    eor3_m1_1 $C0, $Aba, $Aga, $Aka
    eor3_m1_1 $C2, $Abi, $Agi, $Aki
    eor3_m1_1 $C4, $Abu, $Agu, $Aku
    eor3_m1_0 $C1, $C1, $Ame,  $Ase
    eor3_m1_0 $C3, $C3, $Amo,  $Aso
    eor3_m1_0 $C0, $C0, $Ama,  $Asa
    eor3_m1_0 $C2, $C2, $Ami,  $Asi
    eor3_m1_0 $C4, $C4, $Amu,  $Asu
    eor3_m1_1 $C1, $C1, $Ame,  $Ase
    eor3_m1_1 $C3, $C3, $Amo,  $Aso
    eor3_m1_1 $C0, $C0, $Ama,  $Asa
    eor3_m1_1 $C2, $C2, $Ami,  $Asi
    eor3_m1_1 $C4, $C4, $Amu,  $Asu

.endm

.macro keccak_f1600_round

    eor3_m1_0 $C0, $Aba, $Aga, $Aka
    eor3_m1_0 $C1, $Abe, $Age, $Ake
    eor3_m1_0 $C2, $Abi, $Agi, $Aki
    eor3_m1_0 $C3, $Abo, $Ago, $Ako
    eor3_m1_0 $C4, $Abu, $Agu, $Aku
    eor3_m1_1 $C0, $Aba, $Aga, $Aka
    eor3_m1_1 $C1, $Abe, $Age, $Ake
    eor3_m1_1 $C2, $Abi, $Agi, $Aki
    eor3_m1_1 $C3, $Abo, $Ago, $Ako
    eor3_m1_1 $C4, $Abu, $Agu, $Aku
    eor3_m1_0 $C0, $C0, $Ama,  $Asa
    eor3_m1_0 $C1, $C1, $Ame,  $Ase
    eor3_m1_0 $C2, $C2, $Ami,  $Asi
    eor3_m1_0 $C3, $C3, $Amo,  $Aso
    eor3_m1_0 $C4, $C4, $Amu,  $Asu
    eor3_m1_1 $C0, $C0, $Ama,  $Asa
    eor3_m1_1 $C1, $C1, $Ame,  $Ase
    eor3_m1_1 $C2, $C2, $Ami,  $Asi
    eor3_m1_1 $C3, $C3, $Amo,  $Aso
    eor3_m1_1 $C4, $C4, $Amu,  $Asu

    tmp .req $vBba
    rax1_m1 $E2, $C1, $C3
    rax1_m1 $E4, $C3, $C0
    rax1_m1 $E1, $C0, $C2
    rax1_m1 $E3, $C2, $C4
    rax1_m1 $E0, $C4, $C1
    .unreq tmp

    tmp  .req $C1
    tmpq .req $C1q

    eor $vBba.16b, $Aba.16b, $E0.16b
    xar_m1 $vBsa, $Abi, $E2, 2
    xar_m1 $vBbi, $Aki, $E2, 21
    xar_m1 $vBki, $Ako, $E3, 39
    xar_m1 $vBko, $Amu, $E4, 56
    xar_m1 $vBmu, $Aso, $E3, 8
    xar_m1 $vBso, $Ama, $E0, 23
    xar_m1 $vBka, $Abe, $E1, 63
    xar_m1 $vBse, $Ago, $E3, 9
    xar_m1 $vBgo, $Ame, $E1, 19
    xar_m1 $vBke, $Agi, $E2, 58
    xar_m1 $vBgi, $Aka, $E0, 61
    xar_m1 $vBga, $Abo, $E3, 36
    xar_m1 $vBbo, $Amo, $E3, 43
    xar_m1 $vBmo, $Ami, $E2, 49
    xar_m1 $vBmi, $Ake, $E1, 54
    xar_m1 $vBge, $Agu, $E4, 44
    xar_m1 $vBgu, $Asi, $E2, 3
    xar_m1 $vBsi, $Aku, $E4, 25
    xar_m1 $vBku, $Asa, $E0, 46
    xar_m1 $vBma, $Abu, $E4, 37
    xar_m1 $vBbu, $Asu, $E4, 50
    xar_m1 $vBsu, $Ase, $E1, 62
    xar_m1 $vBme, $Aga, $E0, 28
    xar_m1 $vBbe, $Age, $E1, 20

    bcax_m1 $Aga, $vBga, $vBgi, $vBge
    bcax_m1 $Age, $vBge, $vBgo, $vBgi
    bcax_m1 $Agi, $vBgi, $vBgu, $vBgo
    bcax_m1 $Ago, $vBgo, $vBga, $vBgu
    bcax_m1 $Agu, $vBgu, $vBge, $vBga
    bcax_m1 $Aka, $vBka, $vBki, $vBke
    bcax_m1 $Ake, $vBke, $vBko, $vBki
    bcax_m1 $Aki, $vBki, $vBku, $vBko
    bcax_m1 $Ako, $vBko, $vBka, $vBku
    bcax_m1 $Aku, $vBku, $vBke, $vBka
    bcax_m1 $Ama, $vBma, $vBmi, $vBme
    bcax_m1 $Ame, $vBme, $vBmo, $vBmi
    bcax_m1 $Ami, $vBmi, $vBmu, $vBmo
    bcax_m1 $Amo, $vBmo, $vBma, $vBmu
    bcax_m1 $Amu, $vBmu, $vBme, $vBma
    bcax_m1 $Asa, $vBsa, $vBsi, $vBse
    bcax_m1 $Ase, $vBse, $vBso, $vBsi
    bcax_m1 $Asi, $vBsi, $vBsu, $vBso
    bcax_m1 $Aso, $vBso, $vBsa, $vBsu
    bcax_m1 $Asu, $vBsu, $vBse, $vBsa
    bcax_m1 $Aba, $vBba, $vBbi, $vBbe
    bcax_m1 $Abe, $vBbe, $vBbo, $vBbi
    bcax_m1 $Abi, $vBbi, $vBbu, $vBbo
    bcax_m1 $Abo, $vBbo, $vBba, $vBbu
    bcax_m1 $Abu, $vBbu, $vBbe, $vBba

    // iota step
    //ld1r {tmp.2d}, [$const_addr], #8
    ldr tmpq, [$const_addr], #16
    eor $Aba.16b, $Aba.16b, tmp.16b

    .unreq tmp
    .unreq tmpq

.endm

.macro keccak_f1600_round_core

    tmp .req $vBba
    rax1_m1 $E2, $C1, $C3
    str $Agaq, [sp, #(STACK_BASE_TMP + 16 * 30)]
    rax1_m1 $E4, $C3, $C0
    rax1_m1 $E1, $C0, $C2
    rax1_m1 $E3, $C2, $C4
    rax1_m1 $E0, $C4, $C1


    .unreq tmp
    tmp .req $C1
    tmpq .req $C1q

    eor $vBba.16b, $Aba.16b, $E0.16b
    xar_m1 $vBsa, $Abi, $E2, 2
    xar_m1 $vBbi, $Aki, $E2, 21
    xar_m1 $vBki, $Ako, $E3, 39
    xar_m1 $vBko, $Amu, $E4, 56
    xar_m1 $vBmu, $Aso, $E3, 8
    xar_m1 $vBso, $Ama, $E0, 23
    xar_m1 $vBka, $Abe, $E1, 63
    xar_m1 $vBse, $Ago, $E3, 9
    xar_m1 $vBgo, $Ame, $E1, 19
    xar_m1 $vBke, $Agi, $E2, 58
    xar_m1 $vBgi, $Aka, $E0, 61
    xar_m1 $vBga, $Abo, $E3, 36
    xar_m1 $vBbo, $Amo, $E3, 43
    xar_m1 $vBmo, $Ami, $E2, 49
    xar_m1 $vBmi, $Ake, $E1, 54
    xar_m1 $vBge, $Agu, $E4, 44
    bcax_m1 $Aga, $vBga, $vBgi, $vBge
    xar_m1 $vBgu, $Asi, $E2, 3
    xar_m1 $vBsi, $Aku, $E4, 25
    xar_m1 $vBku, $Asa, $E0, 46
    xar_m1 $vBma, $Abu, $E4, 37
    xar_m1 $vBbu, $Asu, $E4, 50
    xar_m1 $vBsu, $Ase, $E1, 62
    ldr tmpq, [sp, #(STACK_BASE_TMP + 16*30)]
    xar_m1 $vBme, tmp, $E0, 28
    xar_m1 $vBbe, $Age, $E1, 20

    bcax_m1 $Age, $vBge, $vBgo, $vBgi
    bcax_m1 $Agi, $vBgi, $vBgu, $vBgo
    bcax_m1 $Ago, $vBgo, $vBga, $vBgu
    bcax_m1 $Agu, $vBgu, $vBge, $vBga
    bcax_m1 $Aka, $vBka, $vBki, $vBke
    bcax_m1 $Ake, $vBke, $vBko, $vBki

    .unreq tmp
    .unreq tmpq

    eor2    $C0,  $Aka, $Aga
    str $Agaq, [sp, #(STACK_BASE_TMP + 16 * Aga_offset)]

    tmp .req $Aga
    tmpq .req $Agaq
    bcax_m1 $Aki, $vBki, $vBku, $vBko
    bcax_m1 $Ako, $vBko, $vBka, $vBku
    eor2    $C1,  $Ake, $Age
    bcax_m1 $Aku, $vBku, $vBke, $vBka
    eor2    $C2,  $Aki, $Agi
    bcax_m1 $Ama, $vBma, $vBmi, $vBme
    eor2    $C3,  $Ako, $Ago
    bcax_m1 $Ame, $vBme, $vBmo, $vBmi
    eor2    $C4,  $Aku, $Agu
    bcax_m1 $Ami, $vBmi, $vBmu, $vBmo
    eor2    $C0,  $C0,  $Ama
    bcax_m1 $Amo, $vBmo, $vBma, $vBmu
    eor2    $C1,  $C1,  $Ame
    bcax_m1 $Amu, $vBmu, $vBme, $vBma
    eor2    $C2,  $C2,  $Ami
    bcax_m1 $Asa, $vBsa, $vBsi, $vBse
    eor2    $C3,  $C3,  $Amo
    bcax_m1 $Ase, $vBse, $vBso, $vBsi
    eor2    $C4,  $C4,  $Amu
    bcax_m1 $Asi, $vBsi, $vBsu, $vBso
    eor2    $C0,  $C0,  $Asa
    bcax_m1 $Aso, $vBso, $vBsa, $vBsu
    eor2    $C1,  $C1,  $Ase
    bcax_m1 $Asu, $vBsu, $vBse, $vBsa
    eor2    $C2,  $C2,  $Asi
    eor2    $C3,  $C3,  $Aso
    bcax_m1 $Aba, $vBba, $vBbi, $vBbe
    bcax_m1 $Abe, $vBbe, $vBbo, $vBbi
    eor2    $C1,  $C1,  $Abe

    // iota step
    //ld1r {tmp.2d}, [$const_addr], #8
    ldr tmpq, [$const_addr], #16
    eor $Aba.16b, $Aba.16b, tmp.16b
    eor2    $C4,  $C4,  $Asu
    bcax_m1 $Abi, $vBbi, $vBbu, $vBbo
    bcax_m1 $Abo, $vBbo, $vBba, $vBbu
    eor2    $C3,  $C3,  $Abo
    eor2    $C2,  $C2,  $Abi
    eor2    $C0,  $C0,  $Aba
    bcax_m1 $Abu, $vBbu, $vBbe, $vBba
    eor2    $C4,  $C4,  $Abu

    ldr $Agaq, [sp, #(STACK_BASE_TMP + 16 * Aga_offset)]
    .unreq tmp
    .unreq tmpq

.endm

.macro keccak_f1600_round_post

    tmp .req $vBba
    rax1_m1 $E2, $C1, $C3
    str $Agaq, [sp, #(STACK_BASE_TMP + 16 * 30)]
    rax1_m1 $E4, $C3, $C0
    rax1_m1 $E1, $C0, $C2
    rax1_m1 $E3, $C2, $C4
    rax1_m1 $E0, $C4, $C1


    .unreq tmp
    tmp .req $C1
    tmpq .req $C1q

    eor $vBba.16b, $Aba.16b, $E0.16b
    xar_m1 $vBsa, $Abi, $E2, 2
    xar_m1 $vBbi, $Aki, $E2, 21
    xar_m1 $vBki, $Ako, $E3, 39
    xar_m1 $vBko, $Amu, $E4, 56
    xar_m1 $vBmu, $Aso, $E3, 8
    xar_m1 $vBso, $Ama, $E0, 23
    xar_m1 $vBka, $Abe, $E1, 63
    xar_m1 $vBse, $Ago, $E3, 9
    xar_m1 $vBgo, $Ame, $E1, 19
    xar_m1 $vBke, $Agi, $E2, 58
    xar_m1 $vBgi, $Aka, $E0, 61
    xar_m1 $vBga, $Abo, $E3, 36
    xar_m1 $vBbo, $Amo, $E3, 43
    xar_m1 $vBmo, $Ami, $E2, 49
    xar_m1 $vBmi, $Ake, $E1, 54
    xar_m1 $vBge, $Agu, $E4, 44
    bcax_m1 $Aga, $vBga, $vBgi, $vBge
    xar_m1 $vBgu, $Asi, $E2, 3
    xar_m1 $vBsi, $Aku, $E4, 25
    xar_m1 $vBku, $Asa, $E0, 46
    xar_m1 $vBma, $Abu, $E4, 37
    xar_m1 $vBbu, $Asu, $E4, 50
    xar_m1 $vBsu, $Ase, $E1, 62
    ldr tmpq, [sp, #(STACK_BASE_TMP + 16*30)]
    xar_m1 $vBme, tmp, $E0, 28
    xar_m1 $vBbe, $Age, $E1, 20

    bcax_m1 $Age, $vBge, $vBgo, $vBgi
    bcax_m1 $Agi, $vBgi, $vBgu, $vBgo
    bcax_m1 $Ago, $vBgo, $vBga, $vBgu
    bcax_m1 $Agu, $vBgu, $vBge, $vBga
    bcax_m1 $Aka, $vBka, $vBki, $vBke
    bcax_m1 $Ake, $vBke, $vBko, $vBki
    bcax_m1 $Aki, $vBki, $vBku, $vBko
    bcax_m1 $Ako, $vBko, $vBka, $vBku
    bcax_m1 $Aku, $vBku, $vBke, $vBka
    bcax_m1 $Ama, $vBma, $vBmi, $vBme
    bcax_m1 $Ame, $vBme, $vBmo, $vBmi
    bcax_m1 $Ami, $vBmi, $vBmu, $vBmo
    bcax_m1 $Amo, $vBmo, $vBma, $vBmu
    bcax_m1 $Amu, $vBmu, $vBme, $vBma
    bcax_m1 $Asa, $vBsa, $vBsi, $vBse
    bcax_m1 $Ase, $vBse, $vBso, $vBsi
    bcax_m1 $Asi, $vBsi, $vBsu, $vBso
    bcax_m1 $Aso, $vBso, $vBsa, $vBsu
    bcax_m1 $Asu, $vBsu, $vBse, $vBsa
    bcax_m1 $Aba, $vBba, $vBbi, $vBbe
    bcax_m1 $Abe, $vBbe, $vBbo, $vBbi
    bcax_m1 $Abi, $vBbi, $vBbu, $vBbo
    bcax_m1 $Abo, $vBbo, $vBba, $vBbu
    bcax_m1 $Abu, $vBbu, $vBbe, $vBba

    // iota step
    //ld1r {tmp.2d}, [$const_addr], #8
    ldr tmpq, [$const_addr], #16
    eor $Aba.16b, $Aba.16b, tmp.16b

    .unreq tmp

.endm


.text
.align 4
.global keccak_f1600_x2_v84a_asm_v2pp2
.global _keccak_f1600_x2_v84a_asm_v2pp2

#define KECCAK_F1600_ROUNDS 24

keccak_f1600_x2_v84a_asm_v2pp2:
_keccak_f1600_x2_v84a_asm_v2pp2:
    alloc_stack
    save_vregs
    load_constant_ptr
    load_input

    //mov $count, #(KECCAK_F1600_ROUNDS-2)
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

foreach(split("\n", $code)) {
	s/\`([^\`]*)\`/eval($1)/ge;
	m/\bld1r\b/ and s/\.16b/.2d/g;
	print $_, "\n";
}

close STDOUT or die "error closing STDOUT: $!";