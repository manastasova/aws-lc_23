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

#define KECCAK_F1600_ROUNDS 24

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

$input_addr    =  "x26";
$const_addr    =  "x26";
$cur_const     =  "x26";
$count         =  "w29";

$code.=<<___;

/****************** STACK ALLOCATIONS *******************/
 # Define the stack arrangement for the |SHA3_Absorb_lazy| function
#define STACK_SIZE (16*6 + 3*8 + 8 + 2*8) // GPRs (16*6), count (8), const (8), input (8), padding (8)
#define STACK_BASE_GPRS (3*8+8)
#define STACK_OFFSET_INPUT (0*8)
#define STACK_OFFSET_CONST (1*8)
#define STACK_OFFSET_COUNT (2*8)
#define STACK_OFFSET_x27_A44 (16*6 + 3*8 + 8 + 0*8)
#define STACK_OFFSET_x27_C2_E3 (16*6 + 3*8 + 8 + 1*8)

/****************** MEMORY ACCESSING MACROS *******************/
.macro load_input
    ldr $A[0][0], [$input_addr, 8*0 ]
    ldr $A[0][1], [$input_addr, 8*1 ]
    ldr $A[0][2], [$input_addr, 8*2 ]
    ldr $A[0][3], [$input_addr, 8*3 ]
    ldr $A[0][4], [$input_addr, 8*4 ]
    ldr $A[1][0], [$input_addr, 8*5 ]
    ldr $A[1][1], [$input_addr, 8*6 ]
    ldr $A[1][2], [$input_addr, 8*7 ]
    ldr $A[1][3], [$input_addr, 8*8 ]
    ldr $A[1][4], [$input_addr, 8*9 ]
    ldr $A[2][0], [$input_addr, 8*10]
    ldr $A[2][1], [$input_addr, 8*11]
    ldr $A[2][2], [$input_addr, 8*12]
    ldr $A[2][3], [$input_addr, 8*13]
    ldr $A[2][4], [$input_addr, 8*14]
    ldr $A[3][0], [$input_addr, 8*15]
    ldr $A[3][1], [$input_addr, 8*16]
    ldr $A[3][2], [$input_addr, 8*17]
    ldr $A[3][3], [$input_addr, 8*18]
    ldr $A[3][4], [$input_addr, 8*19]
    ldr $A[4][0], [$input_addr, 8*20]
    ldr $A[4][1], [$input_addr, 8*21]
    ldr $A[4][2], [$input_addr, 8*22]
    ldr $A[4][3], [$input_addr, 8*23]
    ldr $A[4][4], [$input_addr, 8*24]
.endm

.macro store_input
    str $A[0][0], [$input_addr, 8*0 ]
    str $A[0][1], [$input_addr, 8*1 ]
    str $A[0][2], [$input_addr, 8*2 ]
    str $A[0][3], [$input_addr, 8*3 ]
    str $A[0][4], [$input_addr, 8*4 ]
    str $A[1][0], [$input_addr, 8*5 ]
    str $A[1][1], [$input_addr, 8*6 ]
    str $A[1][2], [$input_addr, 8*7 ]
    str $A[1][3], [$input_addr, 8*8 ]
    str $A[1][4], [$input_addr, 8*9 ]
    str $A[2][0], [$input_addr, 8*10]
    str $A[2][1], [$input_addr, 8*11]
    str $A[2][2], [$input_addr, 8*12]
    str $A[2][3], [$input_addr, 8*13]
    str $A[2][4], [$input_addr, 8*14]
    str $A[3][0], [$input_addr, 8*15]
    str $A[3][1], [$input_addr, 8*16]
    str $A[3][2], [$input_addr, 8*17]
    str $A[3][3], [$input_addr, 8*18]
    str $A[3][4], [$input_addr, 8*19]
    str $A[4][0], [$input_addr, 8*20]
    str $A[4][1], [$input_addr, 8*21]
    str $A[4][2], [$input_addr, 8*22]
    str $A[4][3], [$input_addr, 8*23]
    str $A[4][4], [$input_addr, 8*24]
.endm

.macro load_constant_ptr
	adr $const_addr, round_constants
.endm

.macro load_constant_ptr_stack
    ldr $const_addr, [sp, #(STACK_OFFSET_CONST)]
.endm

.macro keccak_f1600_round_initial
    eor $C[4], $A[3][4], $A[4][4]
    str x27, [sp, #STACK_OFFSET_x27_A44]
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
    str $count, [sp, #STACK_OFFSET_COUNT]         
    eor $A[0][0], $A[0][0], $cur_const                  
.endm

.macro keccak_f1600_round_noninitial
    eor $C[4], $A[2][4], $A[1][4], ROR #50   
    eor $C[4], $C[4], $A[3][4], ROR #34      
    eor $C[1], $A[2][1], $A[3][1], ROR #57       
    eor $C[4], $C[4], $A[0][4], ROR #26           
    eor $C[0], $A[0][0], $A[1][0], ROR #61        
    eor $C[4], $C[4], $A[4][4], ROR #15           
    str x27, [sp, STACK_OFFSET_x27_A44]                         
    eor $C[2], $A[4][2], $A[0][2], ROR #52    
    eor $C[3], $A[0][3], $A[2][3], ROR #63    
    eor $C[2], $C[2], $A[2][2], ROR #48    
    eor $C[0], $C[0], $A[3][0], ROR #54    
    eor $C[1], $C[1], $A[0][1], ROR #51    
    eor $C[3], $C[3], $A[3][3], ROR #37    
    eor $C[2], $C[2], $A[3][2], ROR #10    
    eor $C[0], $C[0], $A[2][0], ROR #39    
    eor $C[1], $C[1], $A[4][1], ROR #31    
    eor $C[3], $C[3], $A[1][3], ROR #36     
    eor $C[2], $C[2], $A[1][2], ROR #5        
    eor $C[0], $C[0], $A[4][0], ROR #25    
    eor $C[1], $C[1], $A[1][1], ROR #27    
    eor $C[3], $C[3], $A[4][3], ROR #2     
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
    tmp1 .req x29                                       
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
    bic $tmp1, $A_[0][3], $A_[0][2], ROR #42         
    eor $A[0][0], $A_[0][0], $tmp0, ROR #21         
    bic $tmp0, $A_[0][4], $A_[0][3], ROR #57        
    eor $A[0][1], $tmp1, $A_[0][1], ROR #41            
    bic $tmp1, $A_[0][0], $A_[0][4], ROR #50         
    eor $A[0][2], $tmp0, $A_[0][2], ROR #35               
    bic $tmp0, $A_[0][1], $A_[0][0], ROR #44       
    eor $A[0][3], $tmp1, $A_[0][3], ROR #43       
    eor $A[0][4], $tmp0, $A_[0][4], ROR #30          
    .unreq tmp1                                              
    ldr $count, [sp, #STACK_OFFSET_COUNT]          
    load_constant_ptr_stack                        
    ldr $cur_const, [$const_addr, $count, UXTW #3]         
    add $count, $count, #1                             
	str $count , [sp , #STACK_OFFSET_COUNT]                
    eor $A[0][0], $A[0][0], $cur_const                
.endm

.macro final_rotate_store
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

.macro alloc_stack
    sub sp, sp, #(STACK_SIZE)
.endm

.macro free_stack
    add sp, sp, #(STACK_SIZE)
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

.text
.balign 16
.global keccak_f1600_x1_scalar
.global _keccak_f1600_x1_scalar
keccak_f1600_x1_scalar:
_keccak_f1600_x1_scalar:
    alloc_stack
    save_gprs

    mov $input_addr, x0
    load_input
    str $input_addr, [sp, #STACK_OFFSET_INPUT]

    keccak_f1600_round_initial
loop:
    keccak_f1600_round_noninitial
    cmp $count, #(KECCAK_F1600_ROUNDS-1)
    ble loop

    final_rotate_store
    
    ldr $input_addr, [sp, #STACK_OFFSET_INPUT]
    store_input
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