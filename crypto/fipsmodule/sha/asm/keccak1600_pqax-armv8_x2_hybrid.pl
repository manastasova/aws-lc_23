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
    const_addr     .req x1
    count          .req x2
    cur_const      .req x3

    /* Mapping of Kecck-f1600 state to vector registers
     * at the beginning and end of each round. */
    Aba     .req v0
    Abe     .req v1
    Abi     .req v2
    Abo     .req v3
    Abu     .req v4
    Aga     .req v5
    Age     .req v6
    Agi     .req v7
    Ago     .req v8
    Agu     .req v9
    Aka     .req v10
    Ake     .req v11
    Aki     .req v12
    Ako     .req v13
    Aku     .req v14
    Ama     .req v15
    Ame     .req v16
    Ami     .req v17
    Amo     .req v18
    Amu     .req v19
    Asa     .req v20
    Ase     .req v21
    Asi     .req v22
    Aso     .req v23
    Asu     .req v24

    /* q-form of the above mapping */
    Abaq    .req q0
    Abeq    .req q1
    Abiq    .req q2
    Aboq    .req q3
    Abuq    .req q4
    Agaq    .req q5
    Ageq    .req q6
    Agiq    .req q7
    Agoq    .req q8
    Aguq    .req q9
    Akaq    .req q10
    Akeq    .req q11
    Akiq    .req q12
    Akoq    .req q13
    Akuq    .req q14
    Amaq    .req q15
    Ameq    .req q16
    Amiq    .req q17
    Amoq    .req q18
    Amuq    .req q19
    Asaq    .req q20
    Aseq    .req q21
    Asiq    .req q22
    Asoq    .req q23
    Asuq    .req q24

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

    /* E[x] = C[x-1] xor rot(C[x+1],1), for x in 0..4 */
    E0 .req v26
    E1 .req v26
    E2 .req v26
    E3 .req v26
    E4 .req v26

    E0q .req q26
    E1q .req q26
    E2q .req q26
    E3q .req q26
    E4q .req q26

    /* A_[y,2*x+3*y] = rot(A[x,y]) */
    vBgo .req v27
    vBgi .req Ame
    vBga .req Aka
    vBge .req Abo
    vBgu .req Agu
    vBki .req Asi
    vBko .req Ako
    vBka .req Amu
    vBke .req Abe
    vBku .req Agi
    vBmu .req Asa
    vBmo .req Aso
    vBmi .req Ami
    vBma .req Ake
    vBme .req Abu
    vBba .req Aga
    vBbi .req Aba
    vBbo .req Aki
    vBbu .req Amo
    vBbe .req Asu
    vBsa .req Age
    vBso .req Abi
    vBse .req Ama
    vBsi .req Ago
    vBsu .req Aku

    vBgoq .req q27
    vBgiq .req Ameq
    vBgaq .req Akaq
    vBgeq .req Aboq
    vBguq .req Aguq
    vBkiq .req Asiq
    vBkoq .req Akoq
    vBkaq .req Amuq
    vBkeq .req Abeq
    vBkuq .req Agiq
    vBmuq .req Asaq
    vBmoq .req Asoq
    vBmiq .req Amiq
    vBmaq .req Akeq
    vBmeq .req Abuq
    vBbaq .req Agaq
    vBbiq .req Abaq
    vBboq .req Akiq
    vBbuq .req Amoq
    vBbeq .req Asuq
    vBsaq .req Ageq
    vBsoq .req Abiq
    vBseq .req Amaq
    vBsiq .req Agoq
    vBsuq .req Akuq

    vEga .req v28
    vEge .req v29
    vEgi .req vBgi
    vEgo .req vBgo
    vEgu .req vBgu
    vEka .req vBga
    vEke .req vBge
    vEki .req vBki
    vEko .req vBko
    vEku .req vBku
    vEma .req vBka
    vEme .req vBke
    vEmi .req vBmi
    vEmo .req vBmo
    vEmu .req vBmu
    vEba .req vBma
    vEbe .req vBme
    vEbi .req vBbi
    vEbo .req vBbo
    vEbu .req vBbu
    vEsa .req vBba
    vEse .req vBbe
    vEsi .req vBsi
    vEso .req vBso
    vEsu .req vBsu

    vEgaq .req q28
    vEgeq .req q29
    vEgiq .req vBgiq
    vEgoq .req vBgoq
    vEguq .req vBguq
    vEkaq .req vBgaq
    vEkeq .req vBgeq
    vEkiq .req vBkiq
    vEkoq .req vBkoq
    vEkuq .req vBkuq
    vEmaq .req vBkaq
    vEmeq .req vBkeq
    vEmiq .req vBmiq
    vEmoq .req vBmoq
    vEmuq .req vBmuq
    vEbaq .req vBmaq
    vEbeq .req vBmeq
    vEbiq .req vBbiq
    vEboq .req vBboq
    vEbuq .req vBbuq
    vEsaq .req vBbaq
    vEseq .req vBbeq
    vEsiq .req vBsiq
    vEsoq .req vBsoq
    vEsuq .req vBsuq

/************************ MACROS ****************************/

.macro load_input
    ldp Abaq, Abeq, [input_addr, #(2*8*0)]
    ldp Abiq, Aboq, [input_addr, #(2*8*2)]
    ldp Abuq, Agaq, [input_addr, #(2*8*4)]
    ldp Ageq, Agiq, [input_addr, #(2*8*6)]
    ldp Agoq, Aguq, [input_addr, #(2*8*8)]
    ldp Akaq, Akeq, [input_addr, #(2*8*10)]
    ldp Akiq, Akoq, [input_addr, #(2*8*12)]
    ldp Akuq, Amaq, [input_addr, #(2*8*14)]
    ldp Ameq, Amiq, [input_addr, #(2*8*16)]
    ldp Amoq, Amuq, [input_addr, #(2*8*18)]
    ldp Asaq, Aseq, [input_addr, #(2*8*20)]
    ldp Asiq, Asoq, [input_addr, #(2*8*22)]
    ldr Asuq, [input_addr, #(2*8*24)]
.endm

.macro store_input
    str Abaq, [input_addr, #(2*8*0)]
    str Abeq, [input_addr, #(2*8*1)]
    str Abiq, [input_addr, #(2*8*2)]
    str Aboq, [input_addr, #(2*8*3)]
    str Abuq, [input_addr, #(2*8*4)]
    str Agaq, [input_addr, #(2*8*5)]
    str Ageq, [input_addr, #(2*8*6)]
    str Agiq, [input_addr, #(2*8*7)]
    str Agoq, [input_addr, #(2*8*8)]
    str Aguq, [input_addr, #(2*8*9)]
    str Akaq, [input_addr, #(2*8*10)]
    str Akeq, [input_addr, #(2*8*11)]
    str Akiq, [input_addr, #(2*8*12)]
    str Akoq, [input_addr, #(2*8*13)]
    str Akuq, [input_addr, #(2*8*14)]
    str Amaq, [input_addr, #(2*8*15)]
    str Ameq, [input_addr, #(2*8*16)]
    str Amiq, [input_addr, #(2*8*17)]
    str Amoq, [input_addr, #(2*8*18)]
    str Amuq, [input_addr, #(2*8*19)]
    str Asaq, [input_addr, #(2*8*20)]
    str Aseq, [input_addr, #(2*8*21)]
    str Asiq, [input_addr, #(2*8*22)]
    str Asoq, [input_addr, #(2*8*23)]
    str Asuq, [input_addr, #(2*8*24)]
.endm

#define STACK_SIZE (16*4 + 16*30)
#define STACK_BASE_VREGS 0
#define STACK_BASE_TMP   16*4

#define E0_offset  0
#define E1_offset  1
#define E2_offset  2
#define E3_offset  3
#define E4_offset  4

#define Aba_offset (5 + 0  )
#define Abe_offset (5 + 1  )
#define Abi_offset (5 + 2  )
#define Abo_offset (5 + 3  )
#define Abu_offset (5 + 4  )
#define Aga_offset (5 + 5  )
#define Age_offset (5 + 6  )
#define Agi_offset (5 + 7  )
#define Ago_offset (5 + 8  )
#define Agu_offset (5 + 9  )
#define Aka_offset (5 + 10 )
#define Ake_offset (5 + 11 )
#define Aki_offset (5 + 12 )
#define Ako_offset (5 + 13 )
#define Aku_offset (5 + 14 )
#define Ama_offset (5 + 15 )
#define Ame_offset (5 + 16 )
#define Ami_offset (5 + 17 )
#define Amo_offset (5 + 18 )
#define Amu_offset (5 + 19 )
#define Asa_offset (5 + 20 )
#define Ase_offset (5 + 21 )
#define Asi_offset (5 + 22 )
#define Aso_offset (5 + 23 )
#define Asu_offset (5 + 24 )

#define vEba_offset (5 + 0  )
#define vEbe_offset (5 + 1  )
#define vEbi_offset (5 + 2  )
#define vEbo_offset (5 + 3  )
#define vEbu_offset (5 + 4  )
#define vEga_offset (5 + 5  )
#define vEge_offset (5 + 6  )
#define vEgi_offset (5 + 7  )
#define vEgo_offset (5 + 8  )
#define vEgu_offset (5 + 9  )
#define vEka_offset (5 + 10 )
#define vEke_offset (5 + 11 )
#define vEki_offset (5 + 12 )
#define vEko_offset (5 + 13 )
#define vEku_offset (5 + 14 )
#define vEma_offset (5 + 15 )
#define vEme_offset (5 + 16 )
#define vEmi_offset (5 + 17 )
#define vEmo_offset (5 + 18 )
#define vEmu_offset (5 + 19 )
#define vEsa_offset (5 + 20 )
#define vEse_offset (5 + 21 )
#define vEsi_offset (5 + 22 )
#define vEso_offset (5 + 23 )
#define vEsu_offset (5 + 24 )

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
    eor3_m1_0 \\d\\(), \\s0\\(), \\s1\\(), \\s2\\()
    eor3_m1_1 \\d\\(), \\s0\\(), \\s1\\(), \\s2\\() 
.endm

.macro rax1_m1 d s0 s1
   add tmp.2d, \\s1\\().2d, \\s1\\().2d
   sri tmp.2d, \\s1\\().2d, #63
   eor \\d\\().16b, tmp.16b, \\s0\\().16b
.endm

.macro xar_m1 d s0 s1 imm
   eor \\s0\\().16b, \\s0\\().16b, \\s1\\().16b
   shl \\d\\().2d, \\s0\\().2d, #(64-\\imm)
   sri \\d\\().2d, \\s0\\().2d, #(\\imm)
.endm

.macro xar_m1_0 d s0 s1 imm tmp
   eor \\tmp\\().16b, \\s0\\().16b, \\s1\\().16b
.endm

.macro xar_m1_1 d s0 s1 imm tmp
   shl \\d\\().2d, \\tmp\\().2d, #(64-\\imm)
.endm

.macro xar_m1_2 d s0 s1 imm tmp
   sri \\d\\().2d, \\tmp\\().2d, #(\\imm)
.endm

.macro bcax_m1 d s0 s1 s2
    bic tmp.16b, \\s1\\().16b, \\s2\\().16b
    eor \\d\\().16b, tmp.16b, \\s0\\().16b
.endm

.macro refresh d
    mov \\d\\().16b, \\d\\().16b
.endm
/* Keccak-f1600 round */

.macro keccak_f1600_round_pre
    eor2 C0,  Aka, Aga
    eor2 C1,  Ake, Age
    eor2 C2,  Aki, Agi
    eor2 C3,  Ako, Ago
    eor2 C4,  Aku, Agu
    eor2 C0,  C0,  Ama
    eor2 C1,  C1,  Ame
    eor2 C2,  C2,  Ami
    eor2 C3,  C3,  Amo
    eor2 C4,  C4,  Amu
    eor2 C0,  C0,  Asa
    eor2 C1,  C1,  Ase
    eor2 C2,  C2,  Asi
    eor2 C3,  C3,  Aso
    eor2 C4,  C4,  Asu
    eor2 C0,  C0,  Aba
    eor2 C1,  C1,  Abe
    eor2 C2,  C2,  Abi
    eor2 C3,  C3,  Abo
    eor2 C4,  C4,  Abu
.endm

.macro keccak_f1600_round_post
    /* 5x RAX1, 15 Neon Instructions total */

    tmp .req v25
    rax1_m1 E2, C1, C3                 SEP      str E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    rax1_m1 E4, C3, C0                 SEP      str E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    rax1_m1 E1, C0, C2                 SEP      str E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    rax1_m1 E3, C2, C4                 SEP      str E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    rax1_m1 E0, C4, C1                 SEP      str E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]

                                                ldr E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    xar_m1 vBgo, Ame, E1, 19           SEP      ldr E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    xar_m1 vBgi, Aka, E0, 61           SEP      ldr E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    xar_m1 vBga, Abo, E3, 36           SEP      ldr E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    xar_m1 vBge, Agu, E4, 44           SEP      ldr E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    xar_m1 vBgu, Asi, E2, 3            SEP

    bcax_m1 vEga, vBga, vBgi, vBge     SEP      str vEgaq, [sp, #(STACK_BASE_TMP + 16 * vEga_offset)]
    bcax_m1 vEge, vBge, vBgo, vBgi     SEP      str vEgeq, [sp, #(STACK_BASE_TMP + 16 * vEge_offset)]
    bcax_m1 vEgi, vBgi, vBgu, vBgo     SEP      str vEgiq, [sp, #(STACK_BASE_TMP + 16 * vEgi_offset)]
    bcax_m1 vEgo, vBgo, vBga, vBgu     SEP      str vEgoq, [sp, #(STACK_BASE_TMP + 16 * vEgo_offset)]
    bcax_m1 vEgu, vBgu, vBge, vBga     SEP      str vEguq, [sp, #(STACK_BASE_TMP + 16 * vEgu_offset)]

                                                ldr E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    xar_m1 vBki, Ako, E3, 39           SEP      ldr E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    xar_m1 vBko, Amu, E4, 56           SEP      ldr E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    xar_m1 vBka, Abe, E1, 63           SEP      ldr E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    xar_m1 vBke, Agi, E2, 58           SEP      ldr E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    xar_m1 vBku, Asa, E0, 46

    bcax_m1 vEka, vBka, vBki, vBke     SEP      str vEkaq, [sp, #(STACK_BASE_TMP + 16 * vEka_offset)]
    bcax_m1 vEke, vBke, vBko, vBki     SEP      str vEkeq, [sp, #(STACK_BASE_TMP + 16 * vEke_offset)]
    bcax_m1 vEki, vBki, vBku, vBko     SEP      str vEkiq, [sp, #(STACK_BASE_TMP + 16 * vEki_offset)]
    bcax_m1 vEko, vBko, vBka, vBku     SEP      str vEkoq, [sp, #(STACK_BASE_TMP + 16 * vEko_offset)]
    bcax_m1 vEku, vBku, vBke, vBka     SEP      str vEkuq, [sp, #(STACK_BASE_TMP + 16 * vEku_offset)]

                                                ldr E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    xar_m1 vBmu, Aso, E3, 8            SEP      ldr E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    xar_m1 vBmo, Ami, E2, 49           SEP      ldr E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    xar_m1 vBmi, Ake, E1, 54           SEP      ldr E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    xar_m1 vBma, Abu, E4, 37           SEP      ldr E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    xar_m1 vBme, Aga, E0, 28

    bcax_m1 vEma, vBma, vBmi, vBme     SEP      str vEmaq, [sp, #(STACK_BASE_TMP + 16 * vEma_offset)]
    bcax_m1 vEme, vBme, vBmo, vBmi     SEP      str vEmeq, [sp, #(STACK_BASE_TMP + 16 * vEme_offset)]
    bcax_m1 vEmi, vBmi, vBmu, vBmo     SEP      str vEmiq, [sp, #(STACK_BASE_TMP + 16 * vEmi_offset)]
    bcax_m1 vEmo, vBmo, vBma, vBmu     SEP      str vEmoq, [sp, #(STACK_BASE_TMP + 16 * vEmo_offset)]
    bcax_m1 vEmu, vBmu, vBme, vBma     SEP      str vEmuq, [sp, #(STACK_BASE_TMP + 16 * vEmu_offset)]

                                                ldr E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    eor2   vBba, Aba, E0               SEP      ldr E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    xar_m1 vBbi, Aki, E2, 21           SEP      ldr E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    xar_m1 vBbo, Amo, E3, 43           SEP      ldr E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    xar_m1 vBbu, Asu, E4, 50           SEP      ldr E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    xar_m1 vBbe, Age, E1, 20

    bcax_m1 vEba, vBba, vBbi, vBbe     SEP      str vEbaq, [sp, #(STACK_BASE_TMP + 16 * vEba_offset)]
    bcax_m1 vEbe, vBbe, vBbo, vBbi     SEP      str vEbeq, [sp, #(STACK_BASE_TMP + 16 * vEbe_offset)]
    bcax_m1 vEbi, vBbi, vBbu, vBbo     SEP      str vEbiq, [sp, #(STACK_BASE_TMP + 16 * vEbi_offset)]
    bcax_m1 vEbo, vBbo, vBba, vBbu     SEP      str vEboq, [sp, #(STACK_BASE_TMP + 16 * vEbo_offset)]
    bcax_m1 vEbu, vBbu, vBbe, vBba     SEP      str vEbuq, [sp, #(STACK_BASE_TMP + 16 * vEbu_offset)]

                                                ldr E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    xar_m1 vBsa, Abi, E2, 2           SEP       ldr E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    xar_m1 vBso, Ama, E0, 23          SEP       ldr E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    xar_m1 vBse, Ago, E3, 9           SEP       ldr E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    xar_m1 vBsi, Aku, E4, 25          SEP       ldr E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    xar_m1 vBsu, Ase, E1, 62

    bcax_m1 vEsa, vBsa, vBsi, vBse    SEP       str vEsaq, [sp, #(STACK_BASE_TMP + 16 * vEsa_offset)]
    bcax_m1 vEse, vBse, vBso, vBsi    SEP       str vEseq, [sp, #(STACK_BASE_TMP + 16 * vEse_offset)]
    bcax_m1 vEsi, vBsi, vBsu, vBso    SEP       str vEsiq, [sp, #(STACK_BASE_TMP + 16 * vEsi_offset)]
    bcax_m1 vEso, vBso, vBsa, vBsu    SEP       str vEsoq, [sp, #(STACK_BASE_TMP + 16 * vEso_offset)]
    bcax_m1 vEsu, vBsu, vBse, vBsa    SEP       str vEsuq, [sp, #(STACK_BASE_TMP + 16 * vEsu_offset)]

    ldr Abaq, [sp, #(STACK_BASE_TMP + 16 * Aba_offset)]
    ldr Abeq, [sp, #(STACK_BASE_TMP + 16 * Abe_offset)]
    ldr Abiq, [sp, #(STACK_BASE_TMP + 16 * Abi_offset)]
    ldr Aboq, [sp, #(STACK_BASE_TMP + 16 * Abo_offset)]
    ldr Abuq, [sp, #(STACK_BASE_TMP + 16 * Abu_offset)]
    ldr Agaq, [sp, #(STACK_BASE_TMP + 16 * Aga_offset)]
    ldr Ageq, [sp, #(STACK_BASE_TMP + 16 * Age_offset)]
    ldr Agiq, [sp, #(STACK_BASE_TMP + 16 * Agi_offset)]
    ldr Agoq, [sp, #(STACK_BASE_TMP + 16 * Ago_offset)]
    ldr Aguq, [sp, #(STACK_BASE_TMP + 16 * Agu_offset)]
    ldr Akaq, [sp, #(STACK_BASE_TMP + 16 * Aka_offset)]
    ldr Akeq, [sp, #(STACK_BASE_TMP + 16 * Ake_offset)]
    ldr Akiq, [sp, #(STACK_BASE_TMP + 16 * Aki_offset)]
    ldr Akoq, [sp, #(STACK_BASE_TMP + 16 * Ako_offset)]
    ldr Akuq, [sp, #(STACK_BASE_TMP + 16 * Aku_offset)]
    ldr Amaq, [sp, #(STACK_BASE_TMP + 16 * Ama_offset)]
    ldr Ameq, [sp, #(STACK_BASE_TMP + 16 * Ame_offset)]
    ldr Amiq, [sp, #(STACK_BASE_TMP + 16 * Ami_offset)]
    ldr Amoq, [sp, #(STACK_BASE_TMP + 16 * Amo_offset)]
    ldr Amuq, [sp, #(STACK_BASE_TMP + 16 * Amu_offset)]
    ldr Asaq, [sp, #(STACK_BASE_TMP + 16 * Asa_offset)]
    ldr Aseq, [sp, #(STACK_BASE_TMP + 16 * Ase_offset)]
    ldr Asiq, [sp, #(STACK_BASE_TMP + 16 * Asi_offset)]
    ldr Asoq, [sp, #(STACK_BASE_TMP + 16 * Aso_offset)]
    ldr Asuq, [sp, #(STACK_BASE_TMP + 16 * Asu_offset)]

    ld1r {tmp.2d}, [const_addr], #8
    eor Aba.16b, Aba.16b, tmp.16b

    .unreq tmp

.endm

.macro keccak_f1600_round_core

    /* 5x RAX1, 15 Neon Instructions total */

    tmp .req v25

    rax1_m1 E1, C0, C2                 SEP      str E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    rax1_m1 E0, C4, C1                 SEP      str E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    rax1_m1 E3, C2, C4                 SEP      str E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    rax1_m1 E4, C3, C0                 SEP      str E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    rax1_m1 E2, C1, C3                 SEP      str E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]

                                                ldr E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    xar_m1 vBgo, Ame, E1, 19           SEP      ldr E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    xar_m1 vBgi, Aka, E0, 61           SEP      ldr E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    xar_m1 vBga, Abo, E3, 36           SEP      ldr E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    xar_m1 vBge, Agu, E4, 44           SEP      ldr E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    xar_m1 vBgu, Asi, E2, 3            SEP

    bcax_m1 vEga, vBga, vBgi, vBge     SEP      str vEgaq, [sp, #(STACK_BASE_TMP + 16 * vEga_offset)]
    bcax_m1 vEge, vBge, vBgo, vBgi     SEP      str vEgeq, [sp, #(STACK_BASE_TMP + 16 * vEge_offset)]
    bcax_m1 vEgi, vBgi, vBgu, vBgo     SEP      str vEgiq, [sp, #(STACK_BASE_TMP + 16 * vEgi_offset)]
    bcax_m1 vEgo, vBgo, vBga, vBgu     SEP      str vEgoq, [sp, #(STACK_BASE_TMP + 16 * vEgo_offset)]
    bcax_m1 vEgu, vBgu, vBge, vBga     SEP      str vEguq, [sp, #(STACK_BASE_TMP + 16 * vEgu_offset)]

                                                ldr E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    xar_m1 vBki, Ako, E3, 39           SEP      ldr E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    xar_m1 vBko, Amu, E4, 56           SEP      ldr E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    xar_m1 vBka, Abe, E1, 63           SEP      ldr E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    xar_m1 vBke, Agi, E2, 58           SEP      ldr E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    xar_m1 vBku, Asa, E0, 46

    bcax_m1 vEka, vBka, vBki, vBke     SEP      str vEkaq, [sp, #(STACK_BASE_TMP + 16 * vEka_offset)]
    bcax_m1 vEke, vBke, vBko, vBki     SEP      str vEkeq, [sp, #(STACK_BASE_TMP + 16 * vEke_offset)]
    bcax_m1 vEki, vBki, vBku, vBko     SEP      str vEkiq, [sp, #(STACK_BASE_TMP + 16 * vEki_offset)]
    bcax_m1 vEko, vBko, vBka, vBku     SEP      str vEkoq, [sp, #(STACK_BASE_TMP + 16 * vEko_offset)]
    bcax_m1 vEku, vBku, vBke, vBka     SEP      str vEkuq, [sp, #(STACK_BASE_TMP + 16 * vEku_offset)]

    eor2 C3, vEko, vEgo 
    eor2 C0, vEka, vEga
    eor2 C1, vEke, vEge
    eor2 C2, vEki, vEgi
    eor2 C4, vEku, vEgu
                                                ldr E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    xar_m1 vBmu, Aso, E3, 8            SEP      ldr E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    xar_m1 vBmo, Ami, E2, 49           SEP      ldr E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    xar_m1 vBmi, Ake, E1, 54           SEP      ldr E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    xar_m1 vBma, Abu, E4, 37           SEP      ldr E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    xar_m1 vBme, Aga, E0, 28

    bcax_m1 vEma, vBma, vBmi, vBme     SEP      str vEmaq, [sp, #(STACK_BASE_TMP + 16 * vEma_offset)]
    bcax_m1 vEme, vBme, vBmo, vBmi     SEP      str vEmeq, [sp, #(STACK_BASE_TMP + 16 * vEme_offset)]
    bcax_m1 vEmi, vBmi, vBmu, vBmo     SEP      str vEmiq, [sp, #(STACK_BASE_TMP + 16 * vEmi_offset)]
    bcax_m1 vEmo, vBmo, vBma, vBmu     SEP      str vEmoq, [sp, #(STACK_BASE_TMP + 16 * vEmo_offset)]
    bcax_m1 vEmu, vBmu, vBme, vBma     SEP      str vEmuq, [sp, #(STACK_BASE_TMP + 16 * vEmu_offset)]

    eor2 C0,  C0,  vEma
    eor2 C1,  C1,  vEme
    eor2 C2,  C2,  vEmi
    eor2 C3,  C3,  vEmo
    eor2 C4,  C4,  vEmu
                                                ldr E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    eor2   vBba, Aba, E0               SEP      ldr E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    xar_m1 vBbi, Aki, E2, 21           SEP      ldr E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    xar_m1 vBbo, Amo, E3, 43           SEP      ldr E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    xar_m1 vBbu, Asu, E4, 50           SEP      ldr E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    xar_m1 vBbe, Age, E1, 20

    bcax_m1 vEba, vBba, vBbi, vBbe
    ld1r {tmp.2d}, [const_addr], #8
    eor2    vEba, vEba, tmp            SEP     str vEbaq, [sp, #(STACK_BASE_TMP + 16 * vEba_offset)]
    bcax_m1 vEbe, vBbe, vBbo, vBbi     SEP     str vEbeq, [sp, #(STACK_BASE_TMP + 16 * vEbe_offset)]
    bcax_m1 vEbi, vBbi, vBbu, vBbo     SEP     str vEbiq, [sp, #(STACK_BASE_TMP + 16 * vEbi_offset)]
    bcax_m1 vEbo, vBbo, vBba, vBbu     SEP     str vEboq, [sp, #(STACK_BASE_TMP + 16 * vEbo_offset)]
    bcax_m1 vEbu, vBbu, vBbe, vBba     SEP     str vEbuq, [sp, #(STACK_BASE_TMP + 16 * vEbu_offset)]

    eor2 C0,  C0,  vEba
    eor2 C1,  C1,  vEbe
    eor2 C2,  C2,  vEbi
    eor2 C3,  C3,  vEbo
    eor2 C4,  C4,  vEbu
                                               ldr E2q, [sp, #(STACK_BASE_TMP + 16 * E2_offset)]
    xar_m1 vBsa, Abi, E2, 2           SEP      ldr E0q, [sp, #(STACK_BASE_TMP + 16 * E0_offset)]
    xar_m1 vBso, Ama, E0, 23          SEP      ldr E3q, [sp, #(STACK_BASE_TMP + 16 * E3_offset)]
    xar_m1 vBse, Ago, E3, 9           SEP      ldr E4q, [sp, #(STACK_BASE_TMP + 16 * E4_offset)]
    xar_m1 vBsi, Aku, E4, 25          SEP      ldr E1q, [sp, #(STACK_BASE_TMP + 16 * E1_offset)]
    xar_m1 vBsu, Ase, E1, 62

    bcax_m1 vEsa, vBsa, vBsi, vBse    SEP      str vEsaq, [sp, #(STACK_BASE_TMP + 16 * vEsa_offset)]
    bcax_m1 vEse, vBse, vBso, vBsi    SEP      str vEseq, [sp, #(STACK_BASE_TMP + 16 * vEse_offset)]
    bcax_m1 vEsi, vBsi, vBsu, vBso    SEP      str vEsiq, [sp, #(STACK_BASE_TMP + 16 * vEsi_offset)]
    bcax_m1 vEsu, vBsu, vBse, vBsa    SEP      str vEsuq, [sp, #(STACK_BASE_TMP + 16 * vEsu_offset)]

    eor2 C0,  C0,  vEsa
    eor2 C1,  C1,  vEse
    eor2 C2,  C2,  vEsi
    eor2 C3,  C3,  vEso
    eor2 C4,  C4,  vEsu

    ldr Abaq, [sp, #(STACK_BASE_TMP + 16 * Aba_offset)]
    ldr Abeq, [sp, #(STACK_BASE_TMP + 16 * Abe_offset)]
    ldr Abiq, [sp, #(STACK_BASE_TMP + 16 * Abi_offset)]
    ldr Aboq, [sp, #(STACK_BASE_TMP + 16 * Abo_offset)]
    ldr Abuq, [sp, #(STACK_BASE_TMP + 16 * Abu_offset)]
    ldr Agaq, [sp, #(STACK_BASE_TMP + 16 * Aga_offset)]
    ldr Ageq, [sp, #(STACK_BASE_TMP + 16 * Age_offset)]
    ldr Agiq, [sp, #(STACK_BASE_TMP + 16 * Agi_offset)]
    ldr Agoq, [sp, #(STACK_BASE_TMP + 16 * Ago_offset)]
    ldr Aguq, [sp, #(STACK_BASE_TMP + 16 * Agu_offset)]
    ldr Akaq, [sp, #(STACK_BASE_TMP + 16 * Aka_offset)]
    ldr Akeq, [sp, #(STACK_BASE_TMP + 16 * Ake_offset)]
    ldr Akiq, [sp, #(STACK_BASE_TMP + 16 * Aki_offset)]
    ldr Akoq, [sp, #(STACK_BASE_TMP + 16 * Ako_offset)]
    ldr Akuq, [sp, #(STACK_BASE_TMP + 16 * Aku_offset)]
    ldr Amaq, [sp, #(STACK_BASE_TMP + 16 * Ama_offset)]
    ldr Ameq, [sp, #(STACK_BASE_TMP + 16 * Ame_offset)]
    ldr Amiq, [sp, #(STACK_BASE_TMP + 16 * Ami_offset)]
    ldr Amoq, [sp, #(STACK_BASE_TMP + 16 * Amo_offset)]
    ldr Amuq, [sp, #(STACK_BASE_TMP + 16 * Amu_offset)]
    ldr Asaq, [sp, #(STACK_BASE_TMP + 16 * Asa_offset)]
    ldr Aseq, [sp, #(STACK_BASE_TMP + 16 * Ase_offset)]
    ldr Asiq, [sp, #(STACK_BASE_TMP + 16 * Asi_offset)]
    ldr Asoq, [sp, #(STACK_BASE_TMP + 16 * Aso_offset)]
    ldr Asuq, [sp, #(STACK_BASE_TMP + 16 * Asu_offset)]

    .unreq tmp

.endm

.text
.align 4
.global keccak_f1600_x2_neon_asm_v2p1
.global _keccak_f1600_x2_neon_asm_v2p1

#define KECCAK_F1600_ROUNDS 24

keccak_f1600_x2_neon_asm_v2p1:
_keccak_f1600_x2_neon_asm_v2p1:
    alloc_stack
    save_vregs
    adr const_addr, round_constants
    load_input

    //mov count, #(KECCAK_F1600_ROUNDS-2)
    mov count, #11
    keccak_f1600_round_pre
loop:
    keccak_f1600_round_core
    keccak_f1600_round_core
    sub count, count, #1
    cbnz count, loop

    keccak_f1600_round_core
    keccak_f1600_round_post
    store_input
    restore_vregs
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