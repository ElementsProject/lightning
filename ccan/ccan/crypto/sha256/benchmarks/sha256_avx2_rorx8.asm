;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Copyright (c) 2012, Intel Corporation
;
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are
; met:
;
; * Redistributions of source code must retain the above copyright
;   notice, this list of conditions and the following disclaimer.
;
; * Redistributions in binary form must reproduce the above copyright
;   notice, this list of conditions and the following disclaimer in the
;   documentation and/or other materials provided with the
;   distribution.
;
; * Neither the name of the Intel Corporation nor the names of its
;   contributors may be used to endorse or promote products derived from
;   this software without specific prior written permission.
;
;
; THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION "AS IS" AND ANY
; EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
; PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR
; CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
; EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
; PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
; PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
; LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; Example YASM command lines:
; Windows:  yasm -Xvc -f x64 -rnasm -pnasm -o sha256_avx2_rorx8.obj -g cv8 sha256_avx2_rorx8.asm
; Linux:    yasm -f x64 -f elf64 -X gnu -g dwarf2 -D LINUX -o sha256_avx2_rorx8.o sha256_avx2_rorx8.asm
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; This code is described in an Intel White-Paper:
; "Fast SHA-256 Implementations on Intel Architecture Processors"
;
; To find it, surf to http://www.intel.com/p/en_US/embedded
; and search for that title.
; The paper is expected to be released roughly at the end of April, 2012
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; This code schedules 8 blocks at a time, with 1 lane per block
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; Define Macros

%macro addm 2
	add	%2, %1
	mov	%1, %2
%endm

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%define TT0    ymm0
%define TT1    ymm1
%define TT2    ymm2
%define TT3    ymm3
%define TT4    ymm4
%define TT5    ymm5
%define TT6    ymm6
%define TT7    ymm7
%define TTMP1  ymm8
%define TTMP2  ymm9
%define TTMP3 ymm10
%define TTMP4 ymm11
%define TTMP5 ymm12

%ifdef LINUX
%define INP	rdi 	; 1st arg
%define CTX	rsi 	; 2nd arg
%define NUM_BLKS rdx	; 3rd arg
%define c	ecx
%define d	r8d
%define e	edx	; dword version of NUM_BLKS
%define z3	edi	; dword version of INP
%else
%define INP	rcx 	; 1st arg
%define CTX	rdx 	; 2nd arg
%define NUM_BLKS r8	; 3rd arg
%define c	edi
%define d	esi
%define e	r8d	; dword version of NUM_BLKS
%define z3	ecx	; dword version of INP
%endif

%define IDX	rbp
%define TBL	CTX


%define a	eax
%define b	ebx
%define f	r9d
%define g	r10d
%define h	r11d
%xdefine old_h	h

%define T1	r12d
%define z0	r13d
%define z1	r14d
%define z1q	r14
%define z2	r15d

_EXTRA_SIZE	equ 32
_KTMSG_SIZE	equ 16*32	; Second 3/4 of KTMSG overlaps TMSG
_TMSG_SIZE	equ 64*32
%ifdef LINUX
_XMM_SAVE_SIZE	equ 0
%else
_XMM_SAVE_SIZE	equ 7*16
%endif
_INP_END_SIZE	equ 8
_INP_SIZE	equ 8
_RND_SIZE	equ 8
_CTX_SIZE	equ 8
_IDX_LIMIT_SIZE	equ 8
_RSP_SIZE	equ 8

;; KTMSG must overlap TMSG such that the second 3/4 of KTMSG overlaps the
;; first 3/4 of TMSG. (We onl need 16 words of TMSG at any time.)
_KTMSG		equ              _EXTRA_SIZE
_TMSG		equ _KTMSG     + _KTMSG_SIZE
_XMM_SAVE	equ _TMSG      + _TMSG_SIZE
_INP_END	equ _XMM_SAVE  + _XMM_SAVE_SIZE
_INP		equ _INP_END   + _INP_END_SIZE
_RND		equ _INP       + _INP_SIZE
_CTX		equ _RND       + _RND_SIZE
_IDX_LIMIT	equ _CTX       + _CTX_SIZE
_RSP		equ _IDX_LIMIT + _IDX_LIMIT_SIZE
STACK_SIZE	equ _RSP       + _RSP_SIZE

%macro ROTATE_ARGS 0
%xdefine old_h h
%xdefine TMP_ h
%xdefine h g
%xdefine g f
%xdefine f e
%xdefine e d
%xdefine d c
%xdefine c b
%xdefine b a
%xdefine a TMP_
%endm

; PRORD reg, imm, tmp
%macro PRORD 3
%define %%reg %1
%define %%imm %2
%define %%tmp %3
	vpslld	%%tmp, %%reg, (32-(%%imm))
	vpsrld	%%reg, %%reg, %%imm
	vpor	%%reg, %%reg, %%tmp
%endmacro

; non-destructive
; PRORD_nd reg, imm, tmp, src
%macro PRORD_nd 4
%define %%reg %1
%define %%imm %2
%define %%tmp %3
%define %%src %4
	vpslld	%%tmp, %%src, (32-(%%imm))
	vpsrld	%%reg, %%src, %%imm
	vpor	%%reg, %%reg, %%tmp
%endmacro

; PRORD dst/src, amt
%macro PRORD 2
	PRORD	%1, %2, TTMP5
%endmacro

; PRORD_nd dst, src, amt
%macro PRORD_nd 3
	PRORD_nd	%1, %3, TTMP5, %2
%endmacro

; TRANSPOSE8 r0, r1, r2, r3, r4, r5, r6, r7, t0, t1
; "transpose" data in {r0...r7} using temps {t0...t1}
; Input looks like: {r0 r1 r2 r3 r4 r5 r6 r7}
; r0 = {a7 a6 a5 a4   a3 a2 a1 a0}
; r1 = {b7 b6 b5 b4   b3 b2 b1 b0}
; r2 = {c7 c6 c5 c4   c3 c2 c1 c0}
; r3 = {d7 d6 d5 d4   d3 d2 d1 d0}
; r4 = {e7 e6 e5 e4   e3 e2 e1 e0}
; r5 = {f7 f6 f5 f4   f3 f2 f1 f0}
; r6 = {g7 g6 g5 g4   g3 g2 g1 g0}
; r7 = {h7 h6 h5 h4   h3 h2 h1 h0}
;
; Output looks like: {r0 r1 r2 r3 r4 r5 r6 r7}
; r0 = {h0 g0 f0 e0   d0 c0 b0 a0}
; r1 = {h1 g1 f1 e1   d1 c1 b1 a1}
; r2 = {h2 g2 f2 e2   d2 c2 b2 a2}
; r3 = {h3 g3 f3 e3   d3 c3 b3 a3}
; r4 = {h4 g4 f4 e4   d4 c4 b4 a4}
; r5 = {h5 g5 f5 e5   d5 c5 b5 a5}
; r6 = {h6 g6 f6 e6   d6 c6 b6 a6}
; r7 = {h7 g7 f7 e7   d7 c7 b7 a7}
;
%macro TRANSPOSE8 10
%define %%r0 %1
%define %%r1 %2
%define %%r2 %3
%define %%r3 %4
%define %%r4 %5
%define %%r5 %6
%define %%r6 %7
%define %%r7 %8
%define %%t0 %9
%define %%t1 %10
	; process top half (r0..r3) {a...d}
	vshufps	%%t0, %%r0, %%r1, 0x44	; t0 = {b5 b4 a5 a4   b1 b0 a1 a0}
	vshufps	%%r0, %%r0, %%r1, 0xEE	; r0 = {b7 b6 a7 a6   b3 b2 a3 a2}
	vshufps %%t1, %%r2, %%r3, 0x44	; t1 = {d5 d4 c5 c4   d1 d0 c1 c0}
	vshufps	%%r2, %%r2, %%r3, 0xEE	; r2 = {d7 d6 c7 c6   d3 d2 c3 c2}
	vshufps	%%r3, %%t0, %%t1, 0xDD	; r3 = {d5 c5 b5 a5   d1 c1 b1 a1}
	vshufps	%%r1, %%r0, %%r2, 0x88	; r1 = {d6 c6 b6 a6   d2 c2 b2 a2}
	vshufps	%%r0, %%r0, %%r2, 0xDD	; r0 = {d7 c7 b7 a7   d3 c3 b3 a3}
	vshufps	%%t0, %%t0, %%t1, 0x88	; t0 = {d4 c4 b4 a4   d0 c0 b0 a0}

	; use r2 in place of t0
	; process bottom half (r4..r7) {e...h}
	vshufps	%%r2, %%r4, %%r5, 0x44	; r2 = {f5 f4 e5 e4   f1 f0 e1 e0}
	vshufps	%%r4, %%r4, %%r5, 0xEE	; r4 = {f7 f6 e7 e6   f3 f2 e3 e2}
	vshufps %%t1, %%r6, %%r7, 0x44	; t1 = {h5 h4 g5 g4   h1 h0 g1 g0}
	vshufps	%%r6, %%r6, %%r7, 0xEE	; r6 = {h7 h6 g7 g6   h3 h2 g3 g2}
	vshufps	%%r7, %%r2, %%t1, 0xDD	; r7 = {h5 g5 f5 e5   h1 g1 f1 e1}
	vshufps	%%r5, %%r4, %%r6, 0x88	; r5 = {h6 g6 f6 e6   h2 g2 f2 e2}
	vshufps	%%r4, %%r4, %%r6, 0xDD	; r4 = {h7 g7 f7 e7   h3 g3 f3 e3}
	vshufps	%%t1, %%r2, %%t1, 0x88	; t1 = {h4 g4 f4 e4   h0 g0 f0 e0}

	vperm2f128	%%r6, %%r5, %%r1, 0x13	; h6...a6
	vperm2f128	%%r2, %%r5, %%r1, 0x02	; h2...a2
	vperm2f128	%%r5, %%r7, %%r3, 0x13	; h5...a5
	vperm2f128	%%r1, %%r7, %%r3, 0x02	; h1...a1
	vperm2f128	%%r7, %%r4, %%r0, 0x13	; h7...a7
	vperm2f128	%%r3, %%r4, %%r0, 0x02	; h3...a3
	vperm2f128	%%r4, %%t1, %%t0, 0x13	; h4...a4
	vperm2f128	%%r0, %%t1, %%t0, 0x02	; h0...a0
%endmacro

%macro SHA256_X8MS_8RNDS 0

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 0 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i 0

	vmovdqa		TT0,  [rsp + _TMSG + IDX + 32*(i+1)]		;; TT0 = Load W[i-15]
	vmovdqa		TTMP2,[rsp + _TMSG + IDX + 32*(i+14)]		;; TTMP2 = Load W[i-2]
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	PRORD_nd	TTMP1,TT0,7				;; TTMP1 = W[i-15] ror 7
	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	vpsrld		TT0,TT0,3				;; TT0 = W[i-15] shr 3
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*0]				; h = k + w + h


	or	z3, c		; z3 = a|c                                     ; MAJA

	vpxor		TT0,TT0,TTMP1					;; TT0 = (W[i-15] ror 7) xor (W[i-15] shr 3)
	PRORD		TTMP1,18-7			;; TTMP1 = W[i-15] ror 18
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	vpxor		TT0,TTMP1,TT0					;; TT0 = s0
	PRORD_nd	TTMP1,TTMP2,17				;; TTMP1 = W[i-2] ror 17
	vpsrld		TTMP2,TTMP2,10				;; TTMP2 = W[i-2] shr 25
	vpxor		TTMP2,TTMP1,TTMP2				;; TTMP2 = (W[i-2] ror 17) xor (W[i-2] shr 25)
	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	PRORD		TTMP1,19-17			;; TTMP1 = W[i-2] ror 19
	vpxor		TTMP1,TTMP1,TTMP2				;; TTMP1 = s1
	vpaddd		TT0,TT0,TTMP1					;; TT0 = s0 + s1
	vpaddd		TT0,TT0,[rsp + _TMSG + IDX + 32*(i+9)]		;; add W[i-7]
	vpaddd		TT0,TT0,[rsp + _TMSG + IDX + 32*(i+0)]  	;; add W[i-16]
	vmovdqa		[rsp + _TMSG + IDX + 16*32 + i*32], TT0		;; Save TT0 to stack
	vpaddd		TT0, TT0, [TBL + IDX + (i+16)*32]
	vmovdqa		[rsp + _KTMSG + IDX + 16*32 + i*32], TT0	;; Save TT0 to stack

	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 1 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i (i+1)

	vmovdqa		TT1,  [rsp + _TMSG + IDX + 32*(i+1)]		;; TT1 = Load W[i-15]
	vmovdqa		TTMP4,[rsp + _TMSG + IDX + 32*(i+14)]		;; TTMP4 = Load W[i-2]

	add	old_h, z2	; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	PRORD_nd	TTMP3,TT1,7				;; TTMP3 = W[i-15] ror 7
	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --


	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	vpsrld		TT1,TT1,3				;; TT1 = W[i-15] shr 3
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*1]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	vpxor		TT1,TT1,TTMP3					;; TT1 = (W[i-15] ror 7) xor (W[i-15] shr 3)
	PRORD		TTMP3,18-7			;; TTMP3 = W[i-15] ror 18
	vpxor		TT1,TTMP3,TT1					;; TT1 = s0
	PRORD_nd	TTMP3,TTMP4,17				;; TTMP3 = W[i-2] ror 17
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	vpsrld		TTMP4,TTMP4,10				;; TTMP4 = W[i-2] shr 25
	vpxor		TTMP4,TTMP3,TTMP4				;; TTMP4 = (W[i-2] ror 17) xor (W[i-2] shr 25)
	PRORD		TTMP3,19-17			;; TTMP3 = W[i-2] ror 19
	vpxor		TTMP3,TTMP3,TTMP4				;; TTMP3 = s1
	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --

	vpaddd		TT1,TT1,TTMP3					;; TT1 = s0 + s1
	vpaddd		TT1,TT1,[rsp + _TMSG + IDX + 32*(i+9)]		;; add W[i-7]
	vpaddd		TT1,TT1,[rsp + _TMSG + IDX + 32*(i+0)]  	;; add W[i-16]
	vmovdqa		[rsp + _TMSG + IDX + 16*32 + i*32], TT1		;; Save TT1 to stack
	vpaddd		TT1, TT1, [TBL + IDX + (i+16)*32]
	vmovdqa		[rsp + _KTMSG + IDX + 16*32 + i*32], TT1	;; Save TT1 to stack

	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 2 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i (i+1)

	vmovdqa		TT2,  [rsp + _TMSG + IDX + 32*(i+1)]		;; TT2 = Load W[i-15]
	vmovdqa		TTMP2,[rsp + _TMSG + IDX + 32*(i+14)]		;; TTMP2 = Load W[i-2]
	add	old_h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	PRORD_nd	TTMP1,TT2,7				;; TTMP1 = W[i-15] ror 7
	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	vpsrld		TT2,TT2,3				;; TT2 = W[i-15] shr 3
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*2]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	vpxor		TT2,TT2,TTMP1					;; TT2 = (W[i-15] ror 7) xor (W[i-15] shr 3)
	PRORD		TTMP1,18-7			;; TTMP1 = W[i-15] ror 18
	vpxor		TT2,TTMP1,TT2					;; TT2 = s0
	PRORD_nd	TTMP1,TTMP2,17				;; TTMP1 = W[i-2] ror 17
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	vpsrld		TTMP2,TTMP2,10				;; TTMP2 = W[i-2] shr 25
	vpxor		TTMP2,TTMP1,TTMP2				;; TTMP2 = (W[i-2] ror 17) xor (W[i-2] shr 25)
	PRORD		TTMP1,19-17			;; TTMP1 = W[i-2] ror 19
	vpxor		TTMP1,TTMP1,TTMP2				;; TTMP1 = s1
	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	vpaddd		TT2,TT2,TTMP1					;; TT2 = s0 + s1
	vpaddd		TT2,TT2,[rsp + _TMSG + IDX + 32*(i+9)]		;; add W[i-7]
	vpaddd		TT2,TT2,[rsp + _TMSG + IDX + 32*(i+0)]  	;; add W[i-16]
	vmovdqa		[rsp + _TMSG + IDX + 16*32 + i*32], TT2		;; Save TT2 to stack
	vpaddd		TT2, TT2, [TBL + IDX + (i+16)*32]
	vmovdqa		[rsp + _KTMSG + IDX + 16*32 + i*32], TT2	;; Save TT2 to stack
	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --


	ROTATE_ARGS

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 3 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i (i+1)

	vmovdqa		TT3,  [rsp + _TMSG + IDX + 32*(i+1)]		;; TT3 = Load W[i-15]
	vmovdqa		TTMP4,[rsp + _TMSG + IDX + 32*(i+14)]		;; TTMP4 = Load W[i-2]
	add	old_h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	PRORD_nd	TTMP3,TT3,7				;; TTMP3 = W[i-15] ror 7
	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --


	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	vpsrld		TT3,TT3,3				;; TT3 = W[i-15] shr 3
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*3]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	vpxor		TT3,TT3,TTMP3					;; TT3 = (W[i-15] ror 7) xor (W[i-15] shr 3)
	PRORD		TTMP3,18-7			;; TTMP3 = W[i-15] ror 18
	vpxor		TT3,TTMP3,TT3					;; TT3 = s0
	PRORD_nd	TTMP3,TTMP4,17				;; TTMP3 = W[i-2] ror 17
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	vpsrld		TTMP4,TTMP4,10				;; TTMP4 = W[i-2] shr 25
	vpxor		TTMP4,TTMP3,TTMP4				;; TTMP4 = (W[i-2] ror 17) xor (W[i-2] shr 25)
	PRORD		TTMP3,19-17			;; TTMP3 = W[i-2] ror 19
	vpxor		TTMP3,TTMP3,TTMP4				;; TTMP3 = s1
	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	vpaddd		TT3,TT3,TTMP3					;; TT3 = s0 + s1
	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	vpaddd		TT3,TT3,[rsp + _TMSG + IDX + 32*(i+9)]		;; add W[i-7]
	vpaddd		TT3,TT3,[rsp + _TMSG + IDX + 32*(i+0)]  	;; add W[i-16]
	vmovdqa		[rsp + _TMSG + IDX + 16*32 + i*32], TT3		;; Save TT3 to stack
	vpaddd		TT3, TT3, [TBL + IDX + (i+16)*32]
	vmovdqa		[rsp + _KTMSG + IDX + 16*32 + i*32], TT3	;; Save TT3 to stack

	add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 4 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i (i+1)

	vmovdqa		TT4,  [rsp + _TMSG + IDX + 32*(i+1)]		;; TT4 = Load W[i-15]
	vmovdqa		TTMP2,[rsp + _TMSG + IDX + 32*(i+14)]		;; TTMP2 = Load W[i-2]
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	PRORD_nd	TTMP1,TT4,7				;; TTMP1 = W[i-15] ror 7
	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	vpsrld		TT4,TT4,3				;; TT4 = W[i-15] shr 3
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*4]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	vpxor		TT4,TT4,TTMP1					;; TT4 = (W[i-15] ror 7) xor (W[i-15] shr 3)
	PRORD		TTMP1,18-7			;; TTMP1 = W[i-15] ror 18
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	vpxor		TT4,TTMP1,TT4					;; TT4 = s0
	PRORD_nd	TTMP1,TTMP2,17				;; TTMP1 = W[i-2] ror 17
	vpsrld		TTMP2,TTMP2,10				;; TTMP2 = W[i-2] shr 25
	vpxor		TTMP2,TTMP1,TTMP2				;; TTMP2 = (W[i-2] ror 17) xor (W[i-2] shr 25)
	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	PRORD		TTMP1,19-17			;; TTMP1 = W[i-2] ror 19
	vpxor		TTMP1,TTMP1,TTMP2				;; TTMP1 = s1
	vpaddd		TT4,TT4,TTMP1					;; TT4 = s0 + s1
	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	vpaddd		TT4,TT4,[rsp + _TMSG + IDX + 32*(i+9)]		;; add W[i-7]
	vpaddd		TT4,TT4,[rsp + _TMSG + IDX + 32*(i+0)]  	;; add W[i-16]
	vmovdqa		[rsp + _TMSG + IDX + 16*32 + i*32], TT4		;; Save TT4 to stack
	vpaddd		TT4, TT4, [TBL + IDX + (i+16)*32]
	vmovdqa		[rsp + _KTMSG + IDX + 16*32 + i*32], TT4	;; Save TT4 to stack

	ROTATE_ARGS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 5 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i (i+1)

	vmovdqa		TT5,  [rsp + _TMSG + IDX + 32*(i+1)]		;; TT5 = Load W[i-15]
	vmovdqa		TTMP4,[rsp + _TMSG + IDX + 32*(i+14)]		;; TTMP4 = Load W[i-2]
	add	old_h, z2	; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	PRORD_nd	TTMP3,TT5,7				;; TTMP3 = W[i-15] ror 7
	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --


	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	vpsrld		TT5,TT5,3				;; TT5 = W[i-15] shr 3
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*5]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	vpxor		TT5,TT5,TTMP3					;; TT5 = (W[i-15] ror 7) xor (W[i-15] shr 3)
	PRORD		TTMP3,18-7			;; TTMP3 = W[i-15] ror 18
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	vpxor		TT5,TTMP3,TT5					;; TT5 = s0
	PRORD_nd	TTMP3,TTMP4,17				;; TTMP3 = W[i-2] ror 17
	vpsrld		TTMP4,TTMP4,10				;; TTMP4 = W[i-2] shr 25
	vpxor		TTMP4,TTMP3,TTMP4				;; TTMP4 = (W[i-2] ror 17) xor (W[i-2] shr 25)
	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	PRORD		TTMP3,19-17			;; TTMP3 = W[i-2] ror 19
	vpxor		TTMP3,TTMP3,TTMP4				;; TTMP3 = s1
	vpaddd		TT5,TT5,TTMP3					;; TT5 = s0 + s1
	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	vpaddd		TT5,TT5,[rsp + _TMSG + IDX + 32*(i+9)]		;; add W[i-7]
	vpaddd		TT5,TT5,[rsp + _TMSG + IDX + 32*(i+0)]  	;; add W[i-16]
	vmovdqa		[rsp + _TMSG + IDX + 16*32 + i*32], TT5		;; Save TT5 to stack
	vpaddd		TT5, TT5, [TBL + IDX + (i+16)*32]
	vmovdqa		[rsp + _KTMSG + IDX + 16*32 + i*32], TT5	;; Save TT5 to stack

	ROTATE_ARGS

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 6 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i (i+1)

	vmovdqa		TT6,  [rsp + _TMSG + IDX + 32*(i+1)]		;; TT6 = Load W[i-15]
	vmovdqa		TTMP2,[rsp + _TMSG + IDX + 32*(i+14)]		;; TTMP2 = Load W[i-2]

	add	old_h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	PRORD_nd	TTMP1,TT6,7				;; TTMP1 = W[i-15] ror 7
	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	vpsrld		TT6,TT6,3				;; TT6 = W[i-15] shr 3
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*6]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	vpxor		TT6,TT6,TTMP1					;; TT6 = (W[i-15] ror 7) xor (W[i-15] shr 3)
	PRORD		TTMP1,18-7			;; TTMP1 = W[i-15] ror 18
	vpxor		TT6,TTMP1,TT6					;; TT6 = s0
	PRORD_nd	TTMP1,TTMP2,17				;; TTMP1 = W[i-2] ror 17
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	vpsrld		TTMP2,TTMP2,10				;; TTMP2 = W[i-2] shr 25
	vpxor		TTMP2,TTMP1,TTMP2				;; TTMP2 = (W[i-2] ror 17) xor (W[i-2] shr 25)
	PRORD		TTMP1,19-17			;; TTMP1 = W[i-2] ror 19
	vpxor		TTMP1,TTMP1,TTMP2				;; TTMP1 = s1
	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	vpaddd		TT6,TT6,TTMP1					;; TT6 = s0 + s1
	vpaddd		TT6,TT6,[rsp + _TMSG + IDX + 32*(i+9)]		;; add W[i-7]
	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	vpaddd		TT6,TT6,[rsp + _TMSG + IDX + 32*(i+0)]  	;; add W[i-16]
	vmovdqa		[rsp + _TMSG + IDX + 16*32 + i*32], TT6		;; Save TT6 to stack
	vpaddd		TT6, TT6, [TBL + IDX + (i+16)*32]
	vmovdqa		[rsp + _KTMSG + IDX + 16*32 + i*32], TT6	;; Save TT6 to stack

	ROTATE_ARGS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 7 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%assign i (i+1)

	vmovdqa		TT7,  [rsp + _TMSG + IDX + 32*(i+1)]		;; TT7 = Load W[i-15]
	vmovdqa		TTMP4,[rsp + _TMSG + IDX + 32*(i+14)]		;; TTMP4 = Load W[i-2]

	add	old_h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	PRORD_nd	TTMP3,TT7,7				;; TTMP3 = W[i-15] ror 7
	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --


	vpsrld		TT7,TT7,3				;; TT7 = W[i-15] shr 3
	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	vpxor		TT7,TT7,TTMP3					;; TT7 = (W[i-15] ror 7) xor (W[i-15] shr 3)
	PRORD		TTMP3,18-7			;; TTMP3 = W[i-15] ror 18
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*7]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	vpxor		TT7,TTMP3,TT7					;; TT7 = s0
	PRORD_nd	TTMP3,TTMP4,17				;; TTMP3 = W[i-2] ror 17
	vpsrld		TTMP4,TTMP4,10				;; TTMP4 = W[i-2] shr 25
	vpxor		TTMP4,TTMP3,TTMP4				;; TTMP4 = (W[i-2] ror 17) xor (W[i-2] shr 25)
	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	PRORD		TTMP3,19-17			;; TTMP3 = W[i-2] ror 19
	vpxor		TTMP3,TTMP3,TTMP4				;; TTMP3 = s1
	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	vpaddd		TT7,TT7,TTMP3					;; TT7 = s0 + s1
	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	vpaddd		TT7,TT7,[rsp + _TMSG + IDX + 32*(i+9)]		;; add W[i-7]
	add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	vpaddd		TT7,TT7,[rsp + _TMSG + IDX + 32*(i+0)]  	;; add W[i-16]
	add	h, z3		; h = t1 + S0 + MAJ                            ; --

	vmovdqa		[rsp + _TMSG + IDX + 16*32 + i*32], TT7		;; Save TT7 to stack
	vpaddd		TT7, TT7, [TBL + IDX + (i+16)*32]
	vmovdqa		[rsp + _KTMSG + IDX + 16*32 + i*32], TT7	;; Save TT7 to stack
	ROTATE_ARGS


%endm

%macro DO_8ROUNDS 0

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 0 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA


	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*0]				; h = k + w + h

	or	z3, c		; z3 = a|c                                     ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 1 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	add	old_h, z2	; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*1]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 2 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	add	old_h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*2]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 3 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	add	old_h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --


	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*3]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 4 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*4]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 5 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	add	old_h, z2	; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --


	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*5]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 6 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	add	old_h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --


	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*6]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	;add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	;add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 7 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	add	old_h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --
	mov	z2, f		; z2 = f                                       ; CH
	rorx	z0, e, 25	; z0 = e >> 25					; S1A
	rorx	z1, e, 11	; z1 = e >> 11					; S1B
	xor	z2, g		; z2 = f^g                                     ; CH

	xor	z0, z1		; z0 = (e>>25) ^ (e>>11)			; S1
	rorx	z1, e, 6	; z1 = (e >> 6)					; S1
	and	z2, e		; z2 = (f^g)&e                                 ; CH
	add	old_h, z3	; h = t1 + S0 + MAJ                            ; --


	xor	z0, z1		; z0 = (e>>25) ^ (e>>11) ^ (e>>6)		; S1
	rorx	T1, a, 13	; T1 = a >> 13					; S0B
	xor	z2, g		; z2 = CH = ((f^g)&e)^g                        ; CH
	rorx	z1, a, 22	; z1 = a >> 22					; S0A
	mov	z3, a		; z3 = a                                       ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13)			; S0
	rorx	T1, a, 2	; T1 = (a >> 2)					; S0
	add	h, dword[rsp + _KTMSG + IDX + 32*7]				; h = k + w + h
	or	z3, c		; z3 = a|c                                     ; MAJA

	xor	z1, T1		; z1 = (a>>22) ^ (a>>13) ^ (a>>2)		; S0
	mov	T1, a		; T1 = a                                       ; MAJB
	and	z3, b		; z3 = (a|c)&b                                 ; MAJA
	and	T1, c		; T1 = a&c                                     ; MAJB
	add	z2, z0		; z2 = S1 + CH                                 ; --


	add	d, h		; d = k + w + h + d                            ; --
	or	z3, T1		; z3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ
	add	h, z1		; h = k + w + h + S0                           ; --

	add	d, z2		; d = k + w + h + d + S1 + CH = d + t1         ; --


	add	h, z2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --

	add	h, z3		; h = t1 + S0 + MAJ                            ; --

	ROTATE_ARGS


%endm

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha256_rorx_x8ms(void *input_data, UINT32 digest[8], UINT64 num_blks)
;; arg 1 : pointer to input data
;; arg 2 : pointer to digest
;; arg 3 : Num blocks
section .text
global sha256_rorx_x8ms
align 32
sha256_rorx_x8ms:
	push	rbx
%ifndef LINUX
	push	rsi
	push	rdi
%endif
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15

	mov	rax, rsp
	sub	rsp,STACK_SIZE
	and	rsp,-32
	mov	[rsp + _RSP], rax

	mov	qword [rsp + _IDX_LIMIT], 32

%ifndef LINUX
	vmovdqa	[rsp + _XMM_SAVE + 0*16],xmm6
	vmovdqa	[rsp + _XMM_SAVE + 1*16],xmm7
	vmovdqa	[rsp + _XMM_SAVE + 2*16],xmm8
	vmovdqa	[rsp + _XMM_SAVE + 3*16],xmm9
	vmovdqa	[rsp + _XMM_SAVE + 4*16],xmm10
	vmovdqa	[rsp + _XMM_SAVE + 5*16],xmm11
	vmovdqa	[rsp + _XMM_SAVE + 6*16],xmm12
%endif

	shl	NUM_BLKS, 6	; convert to bytes
	jz	done_hash
	lea	NUM_BLKS, [NUM_BLKS + INP - 8*64]
	mov	[rsp + _INP_END], NUM_BLKS
	mov	[rsp + _CTX], CTX

	cmp	NUM_BLKS, INP
	jb	less_than_8_blocks

	;; load initial digest
	mov	a,[4*0 + CTX]
	mov	b,[4*1 + CTX]
	mov	c,[4*2 + CTX]
	mov	d,[4*3 + CTX]
	mov	e,[4*4 + CTX]
	mov	f,[4*5 + CTX]
	mov	g,[4*6 + CTX]
	mov	h,[4*7 + CTX]


eight_blocks_loop:

align 32

	lea	TBL,[K256_SIMD wrt rip]

	vmovdqa	TTMP3, [PSHUFFLE_BYTE_FLIP_MASK wrt rip]
;; Load 8 blocks of message and transpose and save to stack
%assign i 0
%rep 2
	vmovups	TT0,[INP+0*64+i*32]
	vpshufb	TT0, TT0, TTMP3
	vmovups	TT1,[INP+1*64+i*32]
	vpshufb	TT1, TT1, TTMP3
	vmovups	TT2,[INP+2*64+i*32]
	vpshufb	TT2, TT2, TTMP3
	vmovups	TT3,[INP+3*64+i*32]
	vpshufb	TT3, TT3, TTMP3
	vmovups	TT4,[INP+4*64+i*32]
	vpshufb	TT4, TT4, TTMP3
	vmovups	TT5,[INP+5*64+i*32]
	vpshufb	TT5, TT5, TTMP3
	vmovups	TT6,[INP+6*64+i*32]
	vpshufb	TT6, TT6, TTMP3
	vmovups	TT7,[INP+7*64+i*32]
	vpshufb	TT7, TT7, TTMP3

	TRANSPOSE8	TT0, TT1, TT2, TT3, TT4, TT5, TT6, TT7, TTMP1, TTMP2

	vmovdqa	[rsp + _TMSG + 0*32 + i*8*32], TT0
	vpaddd	TT0, TT0, [TBL + 0*32 + i*8*32]
	vmovdqa	[rsp + _KTMSG + 0*32 + i*8*32], TT0

	vmovdqa	[rsp + _TMSG + 1*32 + i*8*32], TT1
	vpaddd	TT1, TT1, [TBL + 1*32 + i*8*32]
	vmovdqa	[rsp + _KTMSG + 1*32 + i*8*32], TT1

	vmovdqa	[rsp + _TMSG + 2*32 + i*8*32], TT2
	vpaddd	TT2, TT2, [TBL + 2*32 + i*8*32]
	vmovdqa	[rsp + _KTMSG + 2*32 + i*8*32], TT2

	vmovdqa	[rsp + _TMSG + 3*32 + i*8*32], TT3
	vpaddd	TT3, TT3, [TBL + 3*32 + i*8*32]
	vmovdqa	[rsp + _KTMSG + 3*32 + i*8*32], TT3

	vmovdqa	[rsp + _TMSG + 4*32 + i*8*32], TT4
	vpaddd	TT4, TT4, [TBL + 4*32 + i*8*32]
	vmovdqa	[rsp + _KTMSG + 4*32 + i*8*32], TT4

	vmovdqa	[rsp + _TMSG + 5*32 + i*8*32], TT5
	vpaddd	TT5, TT5, [TBL + 5*32 + i*8*32]
	vmovdqa	[rsp + _KTMSG + 5*32 + i*8*32], TT5

	vmovdqa	[rsp + _TMSG + 6*32 + i*8*32], TT6
	vpaddd	TT6, TT6, [TBL + 6*32 + i*8*32]
	vmovdqa	[rsp + _KTMSG + 6*32 + i*8*32], TT6

	vmovdqa	[rsp + _TMSG + 7*32 + i*8*32], TT7
	vpaddd	TT7, TT7, [TBL + 7*32 + i*8*32]
	vmovdqa	[rsp + _KTMSG + 7*32 + i*8*32], TT7


%assign i (i+1)
%endrep

after_load:

	;; Save Input Msg pointer to stack
	add	INP, 8*64
	mov	[rsp + _INP], INP

	;; Initialize Msg Index to Zero
	xor	IDX, IDX

sha256_x8ms_8rnds_loop:

	;; Perform Message Scheduling of the next 8 rounds (from round 17 to 64)
	;; Also perform compress function for first block from round 1 to 16.
	SHA256_X8MS_8RNDS


	;; Check how many rounds have been performed
	add IDX, 8*32
	cmp IDX, 6 * 8*32
	jne sha256_x8ms_8rnds_loop

	mov	CTX, [rsp + _CTX]

compress_block_loop:

	;; Perform 8 rounds of compression
	DO_8ROUNDS

	add	IDX, 8*32
	cmp	IDX, 8 * 8*32
	jb	compress_block_loop

	;; Update the State when block compression has been completed
	addm	[4*0 + CTX],a
	addm	[4*1 + CTX],b
	addm	[4*2 + CTX],c
	addm	[4*3 + CTX],d
	addm	[4*4 + CTX],e
	addm	[4*5 + CTX],f
	addm	[4*6 + CTX],g
	addm	[4*7 + CTX],h

	sub	IDX, (8 * 8*32) - 4


	;; Check if the 8th block has been compressed
	cmp	IDX, [rsp + _IDX_LIMIT]
	jne	compress_block_loop

	;; Check if the last set of 8 blocks has been processed
	mov	INP, [rsp + _INP]
	cmp	INP, [rsp + _INP_END]
	jbe	eight_blocks_loop

near_end_of_page:
	mov	z1q, [rsp + _INP_END]
	sub	z1q, INP
	; z1q is minus number of NULL blocks left out of 8
	cmp	z1q, -(8*64)
	jle	done_hash

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	; z1q is -1...-7 (*64) meaning we need to process 7...1 more blocks
	add	INP, z1q

	lea	TBL,[K256_SIMD wrt rip]
	sar	z1q, 4			; convert to blks * 4

	vmovdqa	TTMP3, [PSHUFFLE_BYTE_FLIP_MASK wrt rip]
;; Load 8 blocks of message and transpose and save to stack
%assign i 0
%rep 2
	vmovups	TT0,[INP+0*64+i*32]
	vpshufb	TT0, TT0, TTMP3
	vmovups	TT1,[INP+1*64+i*32]
	vpshufb	TT1, TT1, TTMP3
	vmovups	TT2,[INP+2*64+i*32]
	vpshufb	TT2, TT2, TTMP3
	vmovups	TT3,[INP+3*64+i*32]
	vpshufb	TT3, TT3, TTMP3
	vmovups	TT4,[INP+4*64+i*32]
	vpshufb	TT4, TT4, TTMP3
	vmovups	TT5,[INP+5*64+i*32]
	vpshufb	TT5, TT5, TTMP3
	vmovups	TT6,[INP+6*64+i*32]
	vpshufb	TT6, TT6, TTMP3
	vmovups	TT7,[INP+7*64+i*32]
	vpshufb	TT7, TT7, TTMP3

	TRANSPOSE8	TT0, TT1, TT2, TT3, TT4, TT5, TT6, TT7, TTMP1, TTMP2

	vmovdqu	[rsp + z1q + _TMSG + 0*32 + i*8*32], TT0
	vpaddd	TT0, TT0, [TBL + 0*32 + i*8*32]
	vmovdqu	[rsp + z1q + _KTMSG + 0*32 + i*8*32], TT0

	vmovdqu	[rsp + z1q + _TMSG + 1*32 + i*8*32], TT1
	vpaddd	TT1, TT1, [TBL + 1*32 + i*8*32]
	vmovdqu	[rsp + z1q + _KTMSG + 1*32 + i*8*32], TT1

	vmovdqu	[rsp + z1q + _TMSG + 2*32 + i*8*32], TT2
	vpaddd	TT2, TT2, [TBL + 2*32 + i*8*32]
	vmovdqu	[rsp + z1q + _KTMSG + 2*32 + i*8*32], TT2

	vmovdqu	[rsp + z1q + _TMSG + 3*32 + i*8*32], TT3
	vpaddd	TT3, TT3, [TBL + 3*32 + i*8*32]
	vmovdqu	[rsp + z1q + _KTMSG + 3*32 + i*8*32], TT3

	vmovdqu	[rsp + z1q + _TMSG + 4*32 + i*8*32], TT4
	vpaddd	TT4, TT4, [TBL + 4*32 + i*8*32]
	vmovdqu	[rsp + z1q + _KTMSG + 4*32 + i*8*32], TT4

	vmovdqu	[rsp + z1q + _TMSG + 5*32 + i*8*32], TT5
	vpaddd	TT5, TT5, [TBL + 5*32 + i*8*32]
	vmovdqu	[rsp + z1q + _KTMSG + 5*32 + i*8*32], TT5

	vmovdqu	[rsp + z1q + _TMSG + 6*32 + i*8*32], TT6
	vpaddd	TT6, TT6, [TBL + 6*32 + i*8*32]
	vmovdqu	[rsp + z1q + _KTMSG + 6*32 + i*8*32], TT6

	vmovdqu	[rsp + z1q + _TMSG + 7*32 + i*8*32], TT7
	vpaddd	TT7, TT7, [TBL + 7*32 + i*8*32]
	vmovdqu	[rsp + z1q + _KTMSG + 7*32 + i*8*32], TT7

%assign i (i+1)
%endrep

	add	z1q, 4*8		; z1q = 4 * (number of blocks to proc)
	mov	[rsp + _IDX_LIMIT], z1q

	jmp	after_load


less_than_8_blocks:
	;; load initial digest
	mov	a,[4*0 + CTX]
	mov	b,[4*1 + CTX]
	mov	c,[4*2 + CTX]
	mov	d,[4*3 + CTX]
	mov	e,[4*4 + CTX]
	mov	f,[4*5 + CTX]
	mov	g,[4*6 + CTX]
	mov	h,[4*7 + CTX]

	mov	z1q, INP
	and	z1q, 4095	; offset into page
	cmp	z1q, 4096 - (8*64)
	ja	near_end_of_page

near_start_of_page:
	mov	z1q, [rsp + _INP_END]
	sub	z1q, INP
	sar	z1q, 4			; convert to blks * 4
	add	z1q, 4*8		; z1q = 4 * (number of blocks to proc)
	mov	[rsp + _IDX_LIMIT], z1q
	jmp	eight_blocks_loop

done_hash:
%ifndef LINUX
	vmovdqa	xmm6,[rsp + _XMM_SAVE + 0*16]
	vmovdqa	xmm7,[rsp + _XMM_SAVE + 1*16]
	vmovdqa	xmm8,[rsp + _XMM_SAVE + 2*16]
	vmovdqa	xmm9,[rsp + _XMM_SAVE + 3*16]
	vmovdqa	xmm10,[rsp + _XMM_SAVE + 4*16]
	vmovdqa	xmm11,[rsp + _XMM_SAVE + 5*16]
	vmovdqa	xmm12,[rsp + _XMM_SAVE + 6*16]
%endif

	mov	rsp, [rsp + _RSP]

	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
%ifndef LINUX
	pop	rdi
	pop	rsi
%endif
	pop	rbx

	ret

section .data
align 64
K256_SIMD:
	ddq 0x428a2f98428a2f98428a2f98428a2f98,0x428a2f98428a2f98428a2f98428a2f98
	ddq 0x71374491713744917137449171374491,0x71374491713744917137449171374491
	ddq 0xb5c0fbcfb5c0fbcfb5c0fbcfb5c0fbcf,0xb5c0fbcfb5c0fbcfb5c0fbcfb5c0fbcf
	ddq 0xe9b5dba5e9b5dba5e9b5dba5e9b5dba5,0xe9b5dba5e9b5dba5e9b5dba5e9b5dba5
	ddq 0x3956c25b3956c25b3956c25b3956c25b,0x3956c25b3956c25b3956c25b3956c25b
	ddq 0x59f111f159f111f159f111f159f111f1,0x59f111f159f111f159f111f159f111f1
	ddq 0x923f82a4923f82a4923f82a4923f82a4,0x923f82a4923f82a4923f82a4923f82a4
	ddq 0xab1c5ed5ab1c5ed5ab1c5ed5ab1c5ed5,0xab1c5ed5ab1c5ed5ab1c5ed5ab1c5ed5
	ddq 0xd807aa98d807aa98d807aa98d807aa98,0xd807aa98d807aa98d807aa98d807aa98
	ddq 0x12835b0112835b0112835b0112835b01,0x12835b0112835b0112835b0112835b01
	ddq 0x243185be243185be243185be243185be,0x243185be243185be243185be243185be
	ddq 0x550c7dc3550c7dc3550c7dc3550c7dc3,0x550c7dc3550c7dc3550c7dc3550c7dc3
	ddq 0x72be5d7472be5d7472be5d7472be5d74,0x72be5d7472be5d7472be5d7472be5d74
	ddq 0x80deb1fe80deb1fe80deb1fe80deb1fe,0x80deb1fe80deb1fe80deb1fe80deb1fe
	ddq 0x9bdc06a79bdc06a79bdc06a79bdc06a7,0x9bdc06a79bdc06a79bdc06a79bdc06a7
	ddq 0xc19bf174c19bf174c19bf174c19bf174,0xc19bf174c19bf174c19bf174c19bf174
	ddq 0xe49b69c1e49b69c1e49b69c1e49b69c1,0xe49b69c1e49b69c1e49b69c1e49b69c1
	ddq 0xefbe4786efbe4786efbe4786efbe4786,0xefbe4786efbe4786efbe4786efbe4786
	ddq 0x0fc19dc60fc19dc60fc19dc60fc19dc6,0x0fc19dc60fc19dc60fc19dc60fc19dc6
	ddq 0x240ca1cc240ca1cc240ca1cc240ca1cc,0x240ca1cc240ca1cc240ca1cc240ca1cc
	ddq 0x2de92c6f2de92c6f2de92c6f2de92c6f,0x2de92c6f2de92c6f2de92c6f2de92c6f
	ddq 0x4a7484aa4a7484aa4a7484aa4a7484aa,0x4a7484aa4a7484aa4a7484aa4a7484aa
	ddq 0x5cb0a9dc5cb0a9dc5cb0a9dc5cb0a9dc,0x5cb0a9dc5cb0a9dc5cb0a9dc5cb0a9dc
	ddq 0x76f988da76f988da76f988da76f988da,0x76f988da76f988da76f988da76f988da
	ddq 0x983e5152983e5152983e5152983e5152,0x983e5152983e5152983e5152983e5152
	ddq 0xa831c66da831c66da831c66da831c66d,0xa831c66da831c66da831c66da831c66d
	ddq 0xb00327c8b00327c8b00327c8b00327c8,0xb00327c8b00327c8b00327c8b00327c8
	ddq 0xbf597fc7bf597fc7bf597fc7bf597fc7,0xbf597fc7bf597fc7bf597fc7bf597fc7
	ddq 0xc6e00bf3c6e00bf3c6e00bf3c6e00bf3,0xc6e00bf3c6e00bf3c6e00bf3c6e00bf3
	ddq 0xd5a79147d5a79147d5a79147d5a79147,0xd5a79147d5a79147d5a79147d5a79147
	ddq 0x06ca635106ca635106ca635106ca6351,0x06ca635106ca635106ca635106ca6351
	ddq 0x14292967142929671429296714292967,0x14292967142929671429296714292967
	ddq 0x27b70a8527b70a8527b70a8527b70a85,0x27b70a8527b70a8527b70a8527b70a85
	ddq 0x2e1b21382e1b21382e1b21382e1b2138,0x2e1b21382e1b21382e1b21382e1b2138
	ddq 0x4d2c6dfc4d2c6dfc4d2c6dfc4d2c6dfc,0x4d2c6dfc4d2c6dfc4d2c6dfc4d2c6dfc
	ddq 0x53380d1353380d1353380d1353380d13,0x53380d1353380d1353380d1353380d13
	ddq 0x650a7354650a7354650a7354650a7354,0x650a7354650a7354650a7354650a7354
	ddq 0x766a0abb766a0abb766a0abb766a0abb,0x766a0abb766a0abb766a0abb766a0abb
	ddq 0x81c2c92e81c2c92e81c2c92e81c2c92e,0x81c2c92e81c2c92e81c2c92e81c2c92e
	ddq 0x92722c8592722c8592722c8592722c85,0x92722c8592722c8592722c8592722c85
	ddq 0xa2bfe8a1a2bfe8a1a2bfe8a1a2bfe8a1,0xa2bfe8a1a2bfe8a1a2bfe8a1a2bfe8a1
	ddq 0xa81a664ba81a664ba81a664ba81a664b,0xa81a664ba81a664ba81a664ba81a664b
	ddq 0xc24b8b70c24b8b70c24b8b70c24b8b70,0xc24b8b70c24b8b70c24b8b70c24b8b70
	ddq 0xc76c51a3c76c51a3c76c51a3c76c51a3,0xc76c51a3c76c51a3c76c51a3c76c51a3
	ddq 0xd192e819d192e819d192e819d192e819,0xd192e819d192e819d192e819d192e819
	ddq 0xd6990624d6990624d6990624d6990624,0xd6990624d6990624d6990624d6990624
	ddq 0xf40e3585f40e3585f40e3585f40e3585,0xf40e3585f40e3585f40e3585f40e3585
	ddq 0x106aa070106aa070106aa070106aa070,0x106aa070106aa070106aa070106aa070
	ddq 0x19a4c11619a4c11619a4c11619a4c116,0x19a4c11619a4c11619a4c11619a4c116
	ddq 0x1e376c081e376c081e376c081e376c08,0x1e376c081e376c081e376c081e376c08
	ddq 0x2748774c2748774c2748774c2748774c,0x2748774c2748774c2748774c2748774c
	ddq 0x34b0bcb534b0bcb534b0bcb534b0bcb5,0x34b0bcb534b0bcb534b0bcb534b0bcb5
	ddq 0x391c0cb3391c0cb3391c0cb3391c0cb3,0x391c0cb3391c0cb3391c0cb3391c0cb3
	ddq 0x4ed8aa4a4ed8aa4a4ed8aa4a4ed8aa4a,0x4ed8aa4a4ed8aa4a4ed8aa4a4ed8aa4a
	ddq 0x5b9cca4f5b9cca4f5b9cca4f5b9cca4f,0x5b9cca4f5b9cca4f5b9cca4f5b9cca4f
	ddq 0x682e6ff3682e6ff3682e6ff3682e6ff3,0x682e6ff3682e6ff3682e6ff3682e6ff3
	ddq 0x748f82ee748f82ee748f82ee748f82ee,0x748f82ee748f82ee748f82ee748f82ee
	ddq 0x78a5636f78a5636f78a5636f78a5636f,0x78a5636f78a5636f78a5636f78a5636f
	ddq 0x84c8781484c8781484c8781484c87814,0x84c8781484c8781484c8781484c87814
	ddq 0x8cc702088cc702088cc702088cc70208,0x8cc702088cc702088cc702088cc70208
	ddq 0x90befffa90befffa90befffa90befffa,0x90befffa90befffa90befffa90befffa
	ddq 0xa4506ceba4506ceba4506ceba4506ceb,0xa4506ceba4506ceba4506ceba4506ceb
	ddq 0xbef9a3f7bef9a3f7bef9a3f7bef9a3f7,0xbef9a3f7bef9a3f7bef9a3f7bef9a3f7
	ddq 0xc67178f2c67178f2c67178f2c67178f2,0xc67178f2c67178f2c67178f2c67178f2

PSHUFFLE_BYTE_FLIP_MASK: ddq 0x0c0d0e0f08090a0b0405060700010203
                         ddq 0x0c0d0e0f08090a0b0405060700010203
