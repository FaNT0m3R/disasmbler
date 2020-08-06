;a:				;arg
;	.reg	= 2		;8/16/32
;	.mm	= 3
;	.mmx	= 4
;	.sreg	= 5
;	.ee1	= 6
;	.ee2	= 7

;	
;;CArg - определяет тип аргумента
;TNo	= 0
;TRegMem = 1		;читать из modrm 
;TReg	= 2		;читать из reg
;TImm	= 3
;TRel8	= 4	;относительный
;TRel1632 = 5	;относительный 16/32
;TOffs	= 6
;TMem	= 7
;TSReg	= 8	;указатель на SReg
;TPnt	= 9	;указатель на строку


MODE_32 equ 1
MODE_16 equ 0

struc SReg Preg16,Preg32
{
	._sig	dd 0
	.reg16	dd Preg16
	.reg32	dd Preg32
}

struct TSReg
	_sig	dd 0
	reg16	dd ?
	reg32	dd ?
ends

struct OpCode; Pmnem,Parg1,Parg2,Parg3

	mnemonic dd ?;Pmnem
	arg1	dd ?;Parg1
	arg2	dd ?;Parg2
	arg3	dd ?;Parg3
ends

struc CMnem Psz0,Psz1,Psz2,Psz3,Psz4,Psz5,Psz6,Psz7	;разное имя для разных значений reg в modrm
{	
	._sig	dd 1
	.sz0	dd Psz0
	.sz1	dd Psz1
	.sz2	dd Psz2
	.sz3	dd Psz3
	.sz4	dd Psz4
	.sz5	dd Psz5
	.sz6	dd Psz6
	.sz7	dd Psz7
}

struc CDMnem Psz0,Psz1			;разное имя для 16бит или 32бит
{
	._sig	dd 2
	.sz0	dd Psz0	;для 16
	.sz1	dd Psz1	;для 32
}
	

struc COpCode Psz0,Psz1,Psz2,Psz3,Psz4,Psz5,Psz6,Psz7		;разные оппкоды для разных значений reg в modrm
{
	._sig	dd 3
	.sz0	dd Psz0	;указатели на OpCode
	.sz1	dd Psz1
	.sz2	dd Psz2
	.sz3	dd Psz3
	.sz4	dd Psz4
	.sz5	dd Psz5
	.sz6	dd Psz6
	.sz7	dd Psz7
}



;------------------------------------------------------------------------------
;------------------------------------------------------------------------------
;------------------------------------------------------------------------------
;------------------------------------------------------------------------------
;------------------------------------------------------------------------------
a:
	.no		= 0 
	.r8		= 1	;reg
	.r1632		= 2	;reg
	.r16		= 3	;reg
	.mmi		= 4	;reg
	.xmmi		= 5	;reg
	.sreg		= 6	;reg
	.sti		= 7	;reg
	
	.rm8		= 8	;modrm
	.rm16		= 9	;modrm
	.rm1632		= 0Ah	;modrm
	;.m8		= 8	;1b	[XXh]
	;.m16		= 9	;2b	[XXXXh]
	;.m32		= 10	;4b
	;.m1632		= 11	;2/4b
	.m16P16X32	= 0Bh   ;4b
	.imm8		= 0Ch	;1b
	.imm16		= 0Dh	;2b
	.imm1632	= 0Eh	;2/4b
	.rel8		= 0Fh	;читать 1b со знаком
	.rel1632	= 10h	;читать 2/4b со знаком
	.moffs		= 11h	;[XXXXh]/[XXXXXXXXh]
	
	.m16int         = 12h
	.m32int         = 13h
	.m64int         = 14h
	.m32real        = 15h
	.m64real        = 16h
	.m80real        = 17h
	.m1428          = 18h
	.m94108         = 19h
	.m80dec         = 1Ah
	.16P16X32       = 1Bh   ;смещение 16:16 либо 32; 4b
	
	.STi_m32real	= 28h

BEG_MODRM_ARG	= 8
END_MODRM_ARG	= 0Ah

;0 
;1 
;2 
;3 
;4 
;5 
;6 
;7 
;8 
;9 
;10
;11
;12
;13
;14
;15
;16
;17
;18
;19
;20
;21
;22
;23
;24
;25
;26
;27
;28
;29
;30
;31
;32
;33
;34
;35
;36
;37
;38
;39
;40
;41







