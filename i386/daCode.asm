;ошибка в 0F jz

FORMAT PE DLL
;format PE CONSOLE 4.0

ENTRY DllEntryPoint
;extrn _LOGStr
;extrn _LOGStrLn
;extrn _LOGInt
;extrn _LOGIntLn
;extrn _LOGHex 
;extrn _LOGHexLn
;extrn _LOGLn


;enum TYPE {al,ah,bl,bh..(все reg), address} 
; 
;struct oppdata
;{
;	char* prfxs
;	char* oppcode
;	char* reg1
;	char* reg2
;	char* reg3
;	DWORD addr1
;	DWORD addr2
;	DWORD addr3
;} 



include "%fasminc%\Win32a.inc"
include "daConst.inc"

debug equ 1

struct FILESTRUC
	hFile 	dd ?
	Pointer dd ?	
	BtsWR   dd ?
ends

struct _DisRet
	bLabel1	dd ?  ;есть ли метка
	bLabel2	dd ?  ;есть ли метка
	NLabel1	dd ?   ;значение метки
	NLabel2	dd ?   ;значение метки
ends

macro int3
{
    if debug
        int3
    end if
}

macro m2m a1,a2
{
	push	a2
	pop	a1
}

section '.reloc' data readable discardable fixups
section '.idata' export readable
export 'daix86',\
	ReadCommand, 'DAReadCommand',\
	GetLengCommand, 'DAGetLengCommand'


section '.text' code readable writeable executable

proc DllEntryPoint, hinstDLL, fdwReason, lpvReserved 
	
;	stdcall ReadCommand,_test_,strres,32
;	add esp,4*3
;	stdcall ReadCommand,eax,strres,32
;	add esp,4*3
;	stdcall ReadCommand,eax,strres,32
;	add esp,4*3

	mov	eax,1
	ret
	
strres rb 32	

	
_test_:	
      out     0A1h,eax                                 ; I/O command
      fdiv    st0,st6
      lock add byte [ebx+0FFE18108h],cl             ; LOCK prefix
      add     byte [eax],al
      add     byte [ebx+0F0F6D815h],cl




;jmp	dword[fs:esi*4+3]
	
endp
;######################################################################
;######################################################################


include "funcs.inc"

;region GetLengCommand
;inp: откуда читать комманду 
;ret: длина всей команды(с адресами, прeфиксами...)
GetLengCommand:
 PCode equ ebp+8
 maxLen equ ebp+12
	push	ebp
 	mov	ebp,esp
	push	ebx esi edi 

	mov	esi,[PCode]
	mov	edi,bytes
	mov	ecx,[maxLen]
	cmp	ecx,64
	jbe	@f
	mov	ecx,64
      @@:
	rep movsb
	
	mov	eax,[mode]
	mov	[regSize],eax
	mov	[addrSize],eax

	xor	eax,eax
	mov	[prfxLock],eax
	mov	[prfxRep],eax
	mov	[prfxSegm],eax

	mov	[bModrm],al
	mov	[bSib],al
	
	;mov	[disResult.bLabel1],eax
	;mov	[disResult.bLabel2],eax
	
	mov	[arg1],eax
	mov	[arg2],eax
	mov	[arg3],eax
	
	mov	ebx,bytes
 .TestPrfx:				;разбираем префиксы
	mov	al,byte[ebx]
	inc	ebx
	
	cmp	al,0F3h                 ;repe
	je	.l1
	cmp	al,0F2h			;repne
	je	.l2
	cmp	al,0F0h			;lock
	je	.l3
	cmp	al,02Eh			;cs
	je	.l4
	cmp	al,03Eh			;ds
	je	.l5
	cmp	al,026h			;es
	je	.l6
	cmp	al,036h			;ss
	je	.l7
	cmp	al,064h			;fs
	je	.l8
	cmp	al,065h			;gs
	je	.l9
	cmp	al,066h			;size op
	je	.l10
	cmp	al,067h			;size addr
	je	.l11
	
	dec	ebx
	jmp	.lEnd
     .l1:
     	mov	[prfxRep],szPrfxRepe
	jmp	.TestPrfx
     .l2:
	mov	[prfxRep],szPrfxRepne
	jmp	.TestPrfx
     .l3:
	mov	[prfxLock],1
	jmp	.TestPrfx
     .l4:
	mov	[prfxSegm],szPrfxCS
	jmp	.TestPrfx
     .l5:
	mov	[prfxSegm],szPrfxDS
	jmp	.TestPrfx
     .l6:
	mov	[prfxSegm],szPrfxES
	jmp	.TestPrfx
     .l7:
	mov	[prfxSegm],szPrfxSS
	jmp	.TestPrfx
     .l8:
	mov	[prfxSegm],szPrfxFS
	jmp	.TestPrfx
     .l9:
	mov	[prfxSegm],szPrfxGS
	jmp	.TestPrfx
     .l10:
	xor	[regSize],1
	jmp	.TestPrfx
     .l11:
	xor	[addrSize],1
	jmp	.TestPrfx
   .lEnd:	

	
; 
;------------------------------------------------------------------------------
					;оппкод - нужно ли читать modrm, зависит ли от reg значение оппкода = результат 
	xor	edx,edx				
	mov	dl,[ebx]
	cmp	dl,0Fh
	jne	.OneByteOC
	inc	ebx
	mov	dl,[ebx]
	mov	edi,[b2OpCod+edx*4]
	jmp	.NextWorkOC	
.OneByteOC:
	mov	edi,[b1OpCod+edx*4]
.NextWorkOC:					;dl = oppcod
						;edi = Pointer to struc oppcod
						;ebx = Pointer to code
;int3
	cmp	edi,0			;проверка, есть ли такой опкод
	jne	@f
	
	mov	eax,1		;----------если такого кода нет
	pop	edi esi ebx
	leave
	ret
	
      @@:
	mov	[PEndOC],ebx
	inc	[PEndOC]

	mov	eax,dword[edi+OpCode.mnemonic]
	cmp	dword[eax],1
	je	.StrucCMnem
	cmp	dword[eax],2
	je	.StrucCDMnem
	cmp	dword[eax],3
	je	.StrucCOpCode
	jmp	.DecodeArgs
	
.StrucCMnem:
	mov	[bModrm],1
	inc	[PEndOC]
	xor	edx,edx
	mov	dl,[ebx+1]
	shr	dl,3
	and	dl,111b
	mov	eax,[eax+edx*4+4]
	test	eax,eax
	jnz	.DecodeArgs

	mov	eax,1		;----------если такого кода нет
	pop	edi esi ebx
	leave
	ret
	
.StrucCDMnem:
	cmp	[regSize],32
	je	@f
	mov	eax,[eax+TSReg.reg16]
	jmp	.DecodeArgs
	
    @@:	mov	eax,[eax+TSReg.reg32]
	jmp	.DecodeArgs
	
.StrucCOpCode:
	mov	[bModrm],1
	inc	[PEndOC]
	xor	edx,edx
	mov	dl,[ebx+1]
	shr	dl,3
	and	dl,111b
	mov	edi,[eax+edx*4+4]
	test	edi,edi
	jnz	@f
	mov	eax,1		;----------если такого кода нет
	pop	edi esi ebx
	leave
	ret
	@@:
	mov	eax,[edi]

	;jmp	.NextWorkOC
	
.DecodeArgs:	
	xor	eax,eax
	
	cmp	dword[edi+OpCode.arg2],BEG_MODRM_ARG
	jb	@f
	cmp	dword[edi+OpCode.arg2],END_MODRM_ARG
	ja	@f
	or	eax,-1
     @@:

;int3
	test	eax,eax
	jnz	@f
	mov	eax,dword[edi+OpCode.arg1]
	stdcall ComputeArg, arg1,szArg1
	mov	eax,dword[edi+OpCode.arg2]
	stdcall ComputeArg, arg2,szArg2
	jmp	.DA
      @@:	
      	mov	eax,dword[edi+OpCode.arg2]
	stdcall ComputeArg, arg2,szArg2
	mov	eax,dword[edi+OpCode.arg1]
	stdcall ComputeArg, arg1,szArg1
      .DA:	
      	mov	eax,dword[edi+OpCode.arg3]
	stdcall ComputeArg, arg3,szArg3	
	
	
	mov	eax,[PEndOC]
	sub	eax,bytes
	cmp	eax,[maxLen]
	jbe	@f
	mov	eax,[maxLen]
      @@:	
	
	pop	edi esi ebx
	leave
	ret
restore PCode

;endregion


;region ReadCommand
;inp: указатель на код и указатель на строку для результата
;ret: новый указатель на код и заполненная строка
ReadCommand:
 PCode equ ebp+8
 PString equ ebp+12
 maxLen equ ebp+16
 
 	push	ebp
 	mov	ebp,esp
	
	cmp	dword[maxLen],0
	jne	@f
	mov	eax,[PCode]
	mov	esp,ebp
	pop	ebp
	ret
      @@:
      
	push	ebx esi edi 

	mov	esi,[PCode]
	mov	[begAddr],esi
	mov	edi,bytes
	mov	ecx,[maxLen]
	cmp	ecx,32
	jbe	@f
	mov	ecx,32
      @@:
	rep movsb

	mov	eax,[mode]
	
	mov	[regSize],eax
	mov	[addrSize],eax
	xor	eax,eax
	mov	[prfxLock],eax
	mov	[prfxRep],eax
	mov	[prfxSegm],eax

	mov	[bModrm],al
	mov	[bSib],al
	
;	mov	[disResult.bLabel1],eax
;	mov	[disResult.bLabel2],eax
	
	mov	[arg1],eax
	mov	[arg2],eax
	mov	[arg3],eax
	
	mov	ebx,bytes

  .TestPrfx:				;разбираем префиксы
	mov	al,byte[ebx]
	inc	ebx
	
	cmp	al,0F3h                 ;repe
	je	.l1
	cmp	al,0F2h			;repne
	je	.l2
	cmp	al,0F0h			;lock
	je	.l3
	cmp	al,02Eh			;cs
	je	.l4
	cmp	al,03Eh			;ds
	je	.l5
	cmp	al,026h			;es
	je	.l6
	cmp	al,036h			;ss
	je	.l7
	cmp	al,064h			;fs
	je	.l8
	cmp	al,065h			;gs
	je	.l9
	cmp	al,066h			;size op
	je	.l10
	cmp	al,067h			;size addr
	je	.l11
	
	dec	ebx
	jmp	.lEnd
     .l1:
     	mov	[prfxRep],szPrfxRepe
	jmp	.TestPrfx
     .l2:
	mov	[prfxRep],szPrfxRepne
	jmp	.TestPrfx
     .l3:
	mov	[prfxLock],1
	jmp	.TestPrfx
     .l4:
	mov	[prfxSegm],szPrfxCS
	jmp	.TestPrfx
     .l5:
	mov	[prfxSegm],szPrfxDS
	jmp	.TestPrfx
     .l6:
	mov	[prfxSegm],szPrfxES
	jmp	.TestPrfx
     .l7:
	mov	[prfxSegm],szPrfxSS
	jmp	.TestPrfx
     .l8:
	mov	[prfxSegm],szPrfxFS
	jmp	.TestPrfx
     .l9:
	mov	[prfxSegm],szPrfxGS
	jmp	.TestPrfx
     .l10:
	xor	[regSize],1
	jmp	.TestPrfx
     .l11:
	xor	[addrSize],1
	jmp	.TestPrfx
   .lEnd:	

; 
;------------------------------------------------------------------------------
					;оппкод - нужно ли читать modrm, зависит ли от reg значение оппкода = результат 
	xor	edx,edx				
	mov	dl,[ebx]
	cmp	dl,0Fh
	jne	.OneByteOC
	inc	ebx
	mov	dl,[ebx]
	mov	edi,[b2OpCod+edx*4]
	jmp	.NextWorkOC	
.OneByteOC:
	mov	edi,[b1OpCod+edx*4]
.NextWorkOC:					;dl = oppcod
						;edi = Pointer to struc oppcod
						;ebx = Pointer to code
	cmp	edi,0			;проверка, есть ли такой опкод
	jne	@f
;в строку результата записать что-то вроде 'db 30h'
	mov	edi,[PString]
	mov	byte[edi],'d'
	mov	byte[edi+1],'b'
	mov	byte[edi+2],' '
	add	edi,3
	mov	ebx,[PCode]
	stdcall	Intl.HToStr1b,[ebx],edi
	mov	eax,[PCode]
	inc	eax
	pop	edi esi ebx
	leave
	ret
	
      @@:
	inc	ebx
	mov	[PEndOC],ebx

	mov	eax,dword[edi+OpCode.mnemonic]
	cmp	dword[eax],1
	je	.StrucCMnem
	cmp	dword[eax],2
	je	.StrucCDMnem
	cmp	dword[eax],3
	je	.StrucCOpCode
	jmp	.NoStruct
	
.StrucCMnem:
	mov	[bModrm],1
	inc	[PEndOC]
	xor	edx,edx
	mov	dl,[ebx]
	shr	dl,3
	and	dl,111b
	mov	eax,[eax+edx*4+4]
	test	eax,eax
	jnz	.NoStruct
;в строку результата записать что-то вроде 'db 30h'
;int3	
	mov	edi,[PString]
	mov	byte[edi],'d'
	mov	byte[edi+1],'b'
	mov	byte[edi+2],' '
	add	edi,3
	mov	ebx,[PCode]
	stdcall	Intl.HToStr1b,[ebx],edi
	
	mov	eax,[PCode]
	inc	eax
	pop	edi esi ebx
	leave
	ret
	
.StrucCDMnem:
	cmp	[regSize],32
	je	@f
	mov	eax,[eax+TSReg.reg16]
	jmp	.NoStruct
	
    @@:	mov	eax,[eax+TSReg.reg32]
	jmp	.NoStruct
	
.StrucCOpCode:
	mov	[bModrm],1
	inc	[PEndOC]
	xor	edx,edx
	mov	dl,[ebx]
	shr	dl,3
	and	dl,111b
	mov	edi,[eax+edx*4+4]
	test	edi,edi
	jnz	@f
	
	mov	edi,[PString]
	mov	byte[edi],'d'
	mov	byte[edi+1],'b'
	mov	byte[edi+2],' ' 
	add	edi,3
	mov	ebx,[PCode]
	stdcall	Intl.HToStr1b,[ebx],edi
	mov	eax,[PCode]
	inc	eax
	pop	edi esi ebx
	leave
	ret
	@@:
	mov	eax,[edi]
	

	;jmp	.NextWorkOC
	
.NoStruct:
	
	cmp	byte[eax],0
	jne	.DecodeArgs
	
	mov	edi,[PString]
	mov	byte[edi],'d'
	mov	byte[edi+1],'b'
	mov	byte[edi+2],' '
	add	edi,3
	mov	ebx,[PCode]
	stdcall	Intl.HToStr1b,[ebx],edi
	mov	eax,[PCode]
	inc	eax
	pop	edi esi ebx
	leave
	ret
.DecodeArgs:	
	mov	dword[mnem],eax

	
	cmp	dword[edi+OpCode.arg2],BEG_MODRM_ARG	;сначала надо читать modrm байт, а потом уже адрес и прочее
	jb	@f
	cmp	dword[edi+OpCode.arg2],END_MODRM_ARG
	ja	@f
	
	mov	eax,dword[edi+OpCode.arg2]
	stdcall ComputeArg, arg2,szArg2
	mov	eax,dword[edi+OpCode.arg1]
	stdcall ComputeArg, arg1,szArg1
	jmp	.DA
	
     @@:
	mov	eax,dword[edi+OpCode.arg1]
	stdcall ComputeArg, arg1,szArg1
	mov	eax,dword[edi+OpCode.arg2]
	stdcall ComputeArg, arg2,szArg2
	
    .DA:	
      	mov	eax,dword[edi+OpCode.arg3]
	stdcall ComputeArg, arg3,szArg3	
	
	
.GenerateString:
	mov	edi,[PString]
	
	cmp	[prfxLock],0
	je	@f
	mov	esi,szPrfxLock
 .gsCp2:
 	lodsb
	stosb
	test	al,al
	jnz	.gsCp2
	dec	edi
    @@:
	
	mov	esi,[prfxRep]
	test	esi,esi
	je	@f
 .gsCp1:
 	lodsb
	stosb
	test	al,al
	jnz	.gsCp1
	dec	edi
    @@:
	
	
	mov	esi,[mnem]		;MNEMONIC
    @@:	lodsb
	stosb
	test	al,al
	jnz	@b
	dec	edi
	
	mov	byte[edi],' ';9		;TAB
	inc	edi
	
	mov	esi,[arg1]
	test	esi,esi
	jz	.endGS
	
    @@:	lodsb
	stosb
	test	al,al
	jnz	@b
	dec	edi
	
	mov	esi,[arg2]
	test	esi,esi
	jz	.endGS
	
	mov	byte[edi],','
	inc	edi
    @@:	lodsb
	stosb
	test	al,al
	jnz	@b
	dec	edi
	
	mov	esi,[arg3]
	test	esi,esi
	jz	.endGS
	
	mov	byte[edi],','
	inc	edi
    @@:	lodsb
	stosb
	test	al,al
	jnz	@b
	
.endGS:
	mov	byte[edi],0
	mov	eax,[PEndOC]
	sub	eax,bytes
	cmp	eax,[maxLen]
	jbe	@f

	mov	edi,[PString]
	mov	byte[edi],'d'
	mov	byte[edi+1],'b'
	mov	byte[edi+2],' '
	add	edi,3
	mov	ebx,[PCode]
	stdcall	Intl.HToStr1b,[ebx],edi
	xor	eax,eax
	inc	eax
     @@:
	add	eax,[PCode]
	pop	edi esi ebx
	leave
	ret
restore PCode 
restore PString

;endregion


;region ReadCommandNew
;inp: указатель на код и указатель на строку для результата
;ret: длина команды и заполненная структура oppdata

;ReadCommandNew:
; PCode equ ebp+8
; PString equ ebp+12 ;ret eax=end command ,  PEndOC      /disResult,
; maxLen equ ebp+16
; 
; 	push	ebp
; 	mov	ebp,esp
;	
;	cmp	dword[maxLen],0
;	jne	@f
;	mov	eax,[PCode]
;	leave	
;	ret
;      @@:
;      
;	push	ebx esi edi 
;
;
;	mov	esi,[PCode]
;	mov	edi,bytes
;	mov	ecx,[maxLen]
;	cmp	ecx,64
;	jbe	@f
;	mov	ecx,64
;      @@:
;	rep movsb
;
;	mov	eax,[mode]
;	
;	mov	[regSize],eax
;	mov	[addrSize],eax
;	xor	eax,eax
;	mov	[prfxLock],eax
;	mov	[prfxRep],eax
;	mov	[prfxSegm],eax
;
;	mov	[bModrm],al
;	mov	[bSib],al
;	
;;	mov	[disResult.bLabel1],eax
;;	mov	[disResult.bLabel2],eax
;	
;	mov	[arg1],eax
;	mov	[arg2],eax
;	mov	[arg3],eax
;	
;	mov	ebx,bytes
;
;  .TestPrfx:				;разбираем префиксы
;	mov	al,byte[ebx]
;	inc	ebx
;	
;	cmp	al,0F3h                 ;repe
;	je	.l1
;	cmp	al,0F2h			;repne
;	je	.l2
;	cmp	al,0F0h			;lock
;	je	.l3
;	cmp	al,02Eh			;cs
;	je	.l4
;	cmp	al,03Eh			;ds
;	je	.l5
;	cmp	al,026h			;es
;	je	.l6
;	cmp	al,036h			;ss
;	je	.l7
;	cmp	al,064h			;fs
;	je	.l8
;	cmp	al,065h			;gs
;	je	.l9
;	cmp	al,066h			;size op
;	je	.l10
;	cmp	al,067h			;size addr
;	je	.l11
;	
;	dec	ebx
;	jmp	.lEnd
;     .l1:
;     	mov	[prfxRep],szPrfxRepe
;	jmp	.TestPrfx
;     .l2:
;	mov	[prfxRep],szPrfxRepne
;	jmp	.TestPrfx
;     .l3:
;	mov	[prfxLock],1
;	jmp	.TestPrfx
;     .l4:
;	mov	[prfxSegm],szPrfxCS
;	jmp	.TestPrfx
;     .l5:
;	mov	[prfxSegm],szPrfxDS
;	jmp	.TestPrfx
;     .l6:
;	mov	[prfxSegm],szPrfxES
;	jmp	.TestPrfx
;     .l7:
;	mov	[prfxSegm],szPrfxSS
;	jmp	.TestPrfx
;     .l8:
;	mov	[prfxSegm],szPrfxFS
;	jmp	.TestPrfx
;     .l9:
;	mov	[prfxSegm],szPrfxGS
;	jmp	.TestPrfx
;     .l10:
;	xor	[regSize],1
;	jmp	.TestPrfx
;     .l11:
;	xor	[addrSize],1
;	jmp	.TestPrfx
;   .lEnd:	
;
;; 
;;------------------------------------------------------------------------------
;					;оппкод - нужно ли читать modrm, зависит ли от reg значение оппкода = результат 
;	xor	edx,edx				
;	mov	dl,[ebx]
;	cmp	dl,0Fh
;	jne	.OneByteOC
;	inc	ebx
;	mov	dl,[ebx]
;	mov	edi,[b2OpCod+edx*4]
;	jmp	.NextWorkOC	
;.OneByteOC:
;	mov	edi,[b1OpCod+edx*4]
;.NextWorkOC:					;dl = oppcod
;						;edi = Pointer to struc oppcod
;						;ebx = Pointer to code
;	cmp	edi,0			;проверка, есть ли такой опкод
;	jne	@f
;;в строку результата записать что-то вроде 'db 30h'
;	mov	edi,[PString]
;	mov	byte[edi],'d'
;	mov	byte[edi+1],'b'
;	mov	byte[edi+2],' '
;	add	edi,3
;	mov	ebx,[PCode]
;	stdcall	Intl.HToStr1b,[ebx],edi
;	
;	mov	eax,[PCode]
;	inc	eax
;	
;	pop	edi esi ebx
;	leave
;	ret
;	
;      @@:
;	mov	[PEndOC],ebx
;	inc	[PEndOC]
;
;	mov	eax,dword[edi+OpCode.mnemonic]
;	cmp	dword[eax],1
;	je	.StrucCMnem
;	cmp	dword[eax],2
;	je	.StrucCDMnem
;	cmp	dword[eax],3
;	je	.StrucCOpCode
;	jmp	.DecodeArgs
;	
;.StrucCMnem:
;	mov	[bModrm],1
;	inc	[PEndOC]
;	xor	edx,edx
;	mov	dl,[ebx+1]
;	shr	dl,3
;	and	dl,111b
;	mov	eax,[eax+edx*4+4]
;	test	eax,eax
;	jnz	.DecodeArgs
;;в строку результата записать что-то вроде 'db 30h'
;;int3	
;	mov	edi,[PString]
;	mov	byte[edi],'d'
;	mov	byte[edi+1],'b'
;	mov	byte[edi+2],' '
;	add	edi,3
;	mov	ebx,[PCode]
;	stdcall	Intl.HToStr1b,[ebx],edi
;	
;	mov	eax,[PCode]
;	inc	eax
;	pop	edi esi ebx
;	leave
;	ret
;	
;.StrucCDMnem:
;	cmp	[regSize],32
;	je	@f
;	mov	eax,[eax+TSReg.reg16]
;	jmp	.DecodeArgs
;	
;    @@:	mov	eax,[eax+TSReg.reg32]
;	jmp	.DecodeArgs
;	
;.StrucCOpCode:
;	mov	[bModrm],1
;	inc	[PEndOC]
;	xor	edx,edx
;	mov	dl,[ebx+1]
;	shr	dl,3
;	and	dl,111b
;	mov	edi,[eax+edx*4+4]
;	test	edi,edi
;	jnz	@f
;	
;	mov	edi,[PString]
;	mov	byte[edi],'d'
;	mov	byte[edi+1],'b'
;	mov	byte[edi+2],' '
;	add	edi,3
;	mov	ebx,[PCode]
;	stdcall	Intl.HToStr1b,[ebx],edi
;	add	eax,[PCode]
;	inc	eax
;	pop	edi esi ebx
;	leave
;	ret
;	@@:
;	mov	eax,[edi]
;	
;
;	;jmp	.NextWorkOC
;	
;.DecodeArgs:
;	mov	dword[mnem],eax
;
;
; 
;	xor	eax,eax
;	
;	cmp	dword[edi+OpCode.arg2],BEG_MODRM_ARG
;	jb	@f
;	cmp	dword[edi+OpCode.arg2],END_MODRM_ARG
;	ja	@f
;	or	eax,-1
;     @@:
;
;	
;	test	eax,eax
;	jnz	@f
;	mov	eax,dword[edi+OpCode.arg1]
;	stdcall ComputeArg, arg1,szArg1
;	mov	eax,dword[edi+OpCode.arg2]
;	stdcall ComputeArg, arg2,szArg2
;	jmp	.DA
;      @@:	
;      	mov	eax,dword[edi+OpCode.arg2]
;	stdcall ComputeArg, arg2,szArg2
;	mov	eax,dword[edi+OpCode.arg1]
;	stdcall ComputeArg, arg1,szArg1
;      .DA:	
;      	mov	eax,dword[edi+OpCode.arg3]
;	stdcall ComputeArg, arg3,szArg3	
;	
;	
;.GenerateString:
;	mov	edi,[PString]
;	
;	cmp	[prfxLock],0
;	je	@f
;	mov	esi,szPrfxLock
; .gsCp2:
; 	lodsb
;	stosb
;	test	al,al
;	jnz	.gsCp2
;	dec	edi
;    @@:
;	
;	mov	esi,[prfxRep]
;	test	esi,esi
;	je	@f
; .gsCp1:
; 	lodsb
;	stosb
;	test	al,al
;	jnz	.gsCp1
;	dec	edi
;    @@:
;	
;	
;	mov	esi,[mnem]		;MNEMONIC
;    @@:	lodsb
;	stosb
;	test	al,al
;	jnz	@b
;	dec	edi
;	
;	mov	byte[edi],' ';9		;TAB
;	inc	edi
;	
;	mov	esi,[arg1]
;	test	esi,esi
;	jz	.endGS
;	
;    @@:	lodsb
;	stosb
;	test	al,al
;	jnz	@b
;	dec	edi
;	
;	mov	esi,[arg2]
;	test	esi,esi
;	jz	.endGS
;	
;	mov	byte[edi],','
;	inc	edi
;    @@:	lodsb
;	stosb
;	test	al,al
;	jnz	@b
;	dec	edi
;	
;	mov	esi,[arg3]
;	test	esi,esi
;	jz	.endGS
;	
;	mov	byte[edi],','
;	inc	edi
;    @@:	lodsb
;	stosb
;	test	al,al
;	jnz	@b
;	
;.endGS:
;	mov	byte[edi],0
;	mov	eax,[PEndOC]
;	sub	eax,bytes
;	cmp	eax,[maxLen]
;	jbe	@f
;
;	mov	edi,[PString]
;	mov	byte[edi],'d'
;	mov	byte[edi+1],'b'
;	mov	byte[edi+2],' '
;	add	edi,3
;	mov	ebx,[PCode]
;	stdcall	Intl.HToStr1b,[ebx],edi
;	xor	eax,eax
;	inc	eax
;     @@:
;	add	eax,[PCode]
;	pop	edi esi ebx
;	leave
;	ret
;restore PCode 
;restore PString

;endregion


;region ComputeArg
;inp: eax = arg, ebx = указатель байт после оппкода
;     pOut = указатель на результат
;     szOut = буфер для строки, если будет нужен
;ret: заполненные pOut и szOut и сдвинутый PEndOC

proc ComputeArg pOut,szOut   

	push	ebx edi esi
 	
	;mov	eax,[arg]
	cmp	eax,a.no
	jne	.l1
	mov	[pOut],0
	jmp	.lEnd
.l1:	
	cmp	eax,a.r8		;reg
	jne	.l2
	xor	eax,eax
	mov	al,[ebx]
	shr	al,3
	and	al,0111b

	mov	edx,[namesReg8+eax*4]
	mov	ebx,[pOut]
	mov	[ebx],edx
	
	cmp	[bModrm],1
	je	@f
	inc	[PEndOC]
	mov	[bModrm],1
      @@:
      	

	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l2:	
	cmp	eax,a.r1632		;reg
	jne	.l3
	xor	eax,eax
	mov	al,[ebx]
	shr	al,3
	and	al,0111b
	cmp	[regSize],MODE_32
	je	@f
	mov	edx,[namesReg16+eax*4]
	jmp	.l_1
    @@: mov	edx,[namesReg32+eax*4]
  .l_1:	mov	ebx,[pOut]
	mov	[ebx],edx
	
	cmp	[bModrm],1
	je	@f
	inc	[PEndOC]
	mov	[bModrm],1
      @@:
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l3:	
	cmp	eax,a.r16		;reg
	jne	.l4
	xor	eax,eax
	mov	al,[ebx]
	shr	al,3
	and	al,0111b
	mov	edx,[namesReg16+eax*4]
	mov	ebx,[pOut]
	mov	[ebx],edx
	
	cmp	[bModrm],1
	je	@f
	inc	[PEndOC]
	mov	[bModrm],1
      @@:
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l4:	
	cmp	eax,a.mmi		;reg
	jne	.l5
	
	cmp	[bModrm],1
	je	@f
	inc	[PEndOC]
	mov	[bModrm],1
      @@:
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l5:	
	cmp	eax,a.xmmi		;reg
	jne	.l6
	
	cmp	[bModrm],1
	je	@f
	inc	[PEndOC]
	mov	[bModrm],1
      @@:
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l6:	
	cmp	eax,a.sreg		;reg
	jne	.l7
	xor	eax,eax
	mov	al,[ebx]
	shr	al,3
	and	al,0111b
	mov	edx,[namesSReg+eax*4]
	mov	ebx,[pOut]
	mov	[ebx],edx
	
	cmp	[bModrm],1
	je	@f
	inc	[PEndOC]
	mov	[bModrm],1
      @@:
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l7:	
	cmp	eax,a.sti		;reg
	jne	.l8
	
	
	cmp	[bModrm],1
	je	@f
	inc	[PEndOC]
	mov	[bModrm],1
      @@:
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l8:	
	cmp	eax,a.rm8		;modrm
	jne	.l9
	xor	eax,eax
	mov	al,[ebx]
	mov	dl,al
	and	al,0111b
	shr	dl,3
	and	dl,11000b
	or	al,dl
	
	cmp	eax,24
	jb	@f
	mov	esi,[modrm8+eax*4]	
	jmp	.l8_1
    @@:	
	cmp	[regSize],MODE_32
	je	@f
	mov	esi,[modrm16+eax*4]
	jmp	.l8_1
    @@:	mov	esi,[modrm32+eax*4]
 .l8_1:
	mov	edx,[szOut]
	mov	ebx,[pOut]
	mov	[ebx],edx
	
	cmp	[bModrm],1
	je	@f
	inc	[PEndOC]
	mov	[bModrm],1
      @@:
      
	stdcall	convertXX,[szOut]
	
      	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l9:	
	cmp	eax,a.rm16		;modrm
	jne	.lA
	xor	eax,eax
	mov	al,[ebx]
	mov	dl,al
	and	al,0111b
	shr	dl,3
	and	dl,11000b
	or	al,dl
	mov	esi,[modrm16+eax*4]
	mov	edx,[szOut]
	mov	ebx,[pOut]
	mov	[ebx],edx

	
	cmp	[bModrm],1
	je	@f
	inc	[PEndOC]
	mov	[bModrm],1
      @@:
	
	stdcall	convertXX,[szOut]
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------	
.lA:	

	cmp	eax,a.rm1632		;modrm
	jne	.lB
	xor	eax,eax
	mov	al,[ebx]
	mov	dl,al
	and	al,0111b
	shr	dl,3
	and	dl,11000b
	or	al,dl
	
	;cmp	[regSize],MODE_32
	cmp	[addrSize],MODE_32
	je	@f
	mov	esi,[modrm16+eax*4]
	jmp	.lA_1
    @@:	
    	mov	esi,[modrm32+eax*4]
 .lA_1:	
 	mov	edx,[szOut]
	mov	ebx,[pOut]
	mov	[ebx],edx
	
     ;-------------
     	push	esi			;for convertXX

	mov	edi,edx
     	
     	cmp	eax,24			;после 24 в таблице modrm не адреса, а регистры
     	jae	.noAddSize
     		
	cmp	[regSize],MODE_32	;приписываем word/dword
	je	@f
	mov	esi,szWord
	jmp	.lA_11
    @@:
	mov	esi,szDword
     .lA_11:
    @@:	lodsb
	stosb
	test	al,al
	jnz	@b
	dec	edi

  .noAddSize:
	mov	eax,edi
	pop	esi
     ;-------------
	
	cmp	[bModrm],1
	je	@f
	inc	[PEndOC]
	mov	[bModrm],1
      @@:

	cmp	esi,mr2_21
	je	.SIB32
	cmp	esi,mr2_13
	je	.SIB8
 	cmp	esi,mr2_5
 	je	.SIBnoaddr
 	
      	stdcall	convertXX,eax
      	mov	byte[eax+1],0
	jmp	.lEnd

  .SIBnoaddr:
  	call	readSIB
	
	mov	byte[edi],']'
	mov	byte[edi+1],0
	jmp	.lEnd
	
  .SIB32:	
  	call	readSIB

	mov	byte[edi],'+'
	inc	edi

	mov	ebx,[PEndOC]
	add	[PEndOC],4
	stdcall	Intl.HToStr4b,dword[ebx],edi
	mov	byte[eax],']'
	mov	byte[eax+1],0
	jmp	.lEnd

   .SIB8:	
  	call	readSIB
	
	mov	byte[edi],'+'
	inc	edi

	mov	ebx,[PEndOC]
	add	[PEndOC],1
	stdcall	Intl.HToStr1b,dword[ebx],edi
	mov	byte[eax],']'
	mov	byte[eax+1],0
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------	
.lB:	
	cmp	eax,a.m16P16X32		;4b
	jne	.lC
	
	mov	ebx,[PEndOC]
	mov	eax,[szOut]
	mov	edx,[pOut]
	mov	[edx],eax
	stdcall	Intl.HToStr2b,dword[ebx],eax	
     	add	[PEndOC],2	
	mov	byte[eax],':'	;0XXXXh:
	inc	eax
	
	mov	ebx,[PEndOC]
	cmp	[addrSize],MODE_32
	je	@f

	stdcall	Intl.HToStr4b,dword[ebx],eax	
	add	[PEndOC],4
	jmp	.lB0
  @@:
	stdcall	Intl.HToStr2b,dword[ebx],eax	
	add	[PEndOC],2
  .lB0:
	jmp	.lEnd
;------------------------------------------------------------------------------------------------	
.lC:	
	cmp	eax,a.imm8		;1b
	jne	.lD
	mov	ebx,[PEndOC]
	mov	eax,[szOut]
	mov	edx,[pOut]
	mov	[edx],eax
	stdcall	Intl.HToStr1b,dword[ebx],eax	
     	inc	[PEndOC]
	jmp	.lEnd
;------------------------------------------------------------------------------------------------	
.lD:	
	cmp	eax,a.imm16		;2b
	jne	.lE
	mov	ebx,[PEndOC]
	mov	eax,[szOut]
	mov	edx,[pOut]
	mov	[edx],eax
	stdcall	Intl.HToStr2b,dword[ebx],eax
	add	[PEndOC],2
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.lE:	
	cmp	eax,a.imm1632		;2/4b
	jne	.lF
	mov	ebx,[PEndOC]
	mov	eax,[szOut]
	mov	edx,[pOut]
	mov	[edx],eax
	cmp	[regSize],MODE_32
	je	@f
	stdcall	Intl.HToStr2b,dword[ebx],eax
	add	[PEndOC],2
	jmp	.lEnd
    @@:
    	stdcall	Intl.HToStr4b,dword[ebx],eax
    	add	[PEndOC],4
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.lF:	
	cmp	eax,a.rel8		;читать 1b со знаком
	jne	.l10
	mov	ebx,[PEndOC]
	mov	eax,[szOut]
	mov	edx,[pOut]
	mov	[edx],eax
	
	inc	[PEndOC]
	
	movsx	edx,byte[ebx]
	add	edx,[PEndOC]
	sub	edx,bytes
	add	edx,[begAddr]
	mov	byte[eax],'l'
	inc	eax
	stdcall	Intl.HToStr4bNN,edx,eax
	
	;stdcall	Intl.SignHToStr1b,dword[ebx],eax
	
	jmp	.lEnd
	
;------------------------------------------------------------------------------------------------	
.l10:	
	cmp	eax,a.rel1632		;rel16/32	читать 2/4b со знаком
	jne	.l11
	
	mov	ebx,[PEndOC]  ;байт за командой(там относ. адрес должен быть)
	
	mov	eax,[szOut]	;записали, что результат во временной строке
	mov	edx,[pOut]
	mov	[edx],eax
	
	cmp	[addrSize],MODE_32	;читаем слово/дв слово
	je	.l10_01
	add	[PEndOC],2	;тут уже конец команды
	movsx	edx,word[ebx]
	
	jmp	@f
    .l10_01:
    	add	[PEndOC],4	;тут уже конец команды
    	
    	mov	edx,dword[ebx]
      @@:
	
	sub	edx,bytes
	add	edx,[begAddr]
	add	edx,[PEndOC]
	mov	byte[eax],'l'
	inc	eax
	
	cmp	[addrSize],MODE_32
	je	.l10_1
	
;	mov	ecx,4
;   @@:	
;   	mov	byte[eax],'0'
;   	inc	eax
;   	loop	@b
	stdcall	Intl.HToStr2bNN,edx,eax
	jmp	.lEnd
    .l10_1:
	stdcall	Intl.HToStr4bNN,edx,eax
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l11:	
	cmp	eax,a.moffs		;[XXXXh]/[XXXXXXXXh]
	jne	.l12
	
  .l11_1:
	mov	ebx,[PEndOC]
	mov	eax,[szOut]
	mov	edx,[pOut]
	mov	[edx],eax
	
	cmp	[addrSize],MODE_32   ;приписываем word/dword
	je	@f
	mov	esi,szWord
	jmp	.l11_11
     @@:
	mov	esi,szDword
     .l11_11:


	mov	edi,eax
    @@:	lodsb
	stosb
	test	al,al
	jnz	@b
	mov	eax,edi
	
	mov	byte[eax-1],'['
	
	mov	esi,[prfxSegm]
	cmp	esi,0
	je	.l11_12
	
	mov	edi,eax
    @@:	lodsb
	stosb
	test	al,al
	jnz	@b
	
	mov	eax,edi
	dec	eax
	
     .l11_12:	
	cmp	[addrSize],MODE_32
	je	@f
	stdcall	Intl.HToStr2b,dword[ebx],eax
	add	[PEndOC],2
	jmp	.l11_2
     @@:
	stdcall	Intl.HToStr4b,dword[ebx],eax
	add	[PEndOC],4
   .l11_2:
	mov	byte[eax],']'
	mov	byte[eax+1],0
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l12:
	cmp	eax,a.m16int
	jne	.l13
	
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l13:
	cmp	eax,a.m32int
	jne	.l14
	
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l14:
	cmp	eax,a.m64int
	jne	.l15
	
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l15:
	cmp	eax,a.m32real
	jne	.l16
	
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l16:
	cmp	eax,a.m64real
	jne	.l17
	
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l17:
	cmp	eax,a.m80real
	jne	.l18
	
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l18:
	cmp	eax,a.m1428
	jne	.l19
	
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l19:
	cmp	eax,a.m94108
	jne	.l1A
	
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l1A:	
	cmp	eax,a.m80dec
	jne	.l1B
	
	
	jmp	.lEnd

	
	
;------------------------------------------------------------------------------------------------
.l1B:
	cmp	eax,a.16P16X32		
	jne	.l28
	
	mov	ebx,[PEndOC]
	mov	eax,[szOut]
	mov	edx,[pOut]
	mov	[edx],eax
	stdcall	Intl.HToStr2b,dword[ebx],eax	
     	add	[PEndOC],2	
	mov	byte[eax],':'	;0XXXXh:
	inc	eax
	
	mov	ebx,[PEndOC]
	cmp	[addrSize],MODE_32
	jne	@f

	stdcall	Intl.HToStr4b,dword[ebx],eax	
	add	[PEndOC],4
	jmp	.l1B0
  @@:
	stdcall	Intl.HToStr2b,dword[ebx],eax	
	add	[PEndOC],2
  .l1B0:
	
	jmp	.lEnd
;------------------------------------------------------------------------------------------------
.l28:
	cmp	eax,a.STi_m32real
	jne	.lPointer
	
	jmp	.lEnd

.lPointer:
	mov	ebx,[pOut]
	cmp	dword[eax],0
	jne	@f
	cmp	[regSize],MODE_32
	je	.lP32
	mov	eax,[eax+TSReg.reg16]
	jmp	@f
   .lP32:
	mov	eax,[eax+TSReg.reg32]
      @@:	
	mov	[ebx],eax
	
.lEnd:	
	
	pop	esi edi ebx

	ret
endp
;endregion

;esi -> XXXX
proc convertXX,szOut
	mov	edi,[szOut]	;преобразовываем XXXXXXX в адрес
	xor	edx,edx
	xor	ebx,ebx
   .lCcp:
    	lodsb
    	stosb
	cmp	al,'X'
	jne	@f
	test	ebx,ebx
	jnz	.lCcp1
	mov	ebx,edi
	dec	ebx
     .lCcp1:	
	inc	edx
      @@:	
	test	al,al
	jnz	.lCcp
	
				;[ebx] -> X[X][XX][XXXX] , edx = n
	cmp	edx,2
	jne	@f
	mov	edx,[PEndOC]
	inc	[PEndOC]
	stdcall	Intl.HToStr1b,dword[edx],ebx
	mov	byte[eax],']'
	mov	byte[eax+1],0
	ret
    @@:	
    	cmp	edx,4
	jne	@f
	mov	edx,[PEndOC]
	add	[PEndOC],2
	stdcall	Intl.HToStr2b,dword[edx],ebx
	mov	byte[eax],']'
	mov	byte[eax+1],0
	ret
    @@:	
	test	edx,edx
	jz	@f
	
	mov	edx,[PEndOC]
	add	[PEndOC],4
	stdcall	Intl.HToStr4b,dword[edx],ebx
	mov	byte[eax],']'
	mov	byte[eax+1],0
    @@:

	ret
endp

;читает байт из PEndOC, интерпретирует как SIB, записывает в edi результат
; завершающую ] не ставит. PEndOC сдвигает. возвращает в edi байт за строкой результата
proc readSIB
	mov	ebx,[PEndOC]		;mul(2bits)reg1(3)reg2(3) 
	mov	dl,[ebx]
	inc	[PEndOC]
	mov	edi,eax
	mov	byte[edi],'['
	inc	edi
	xor	eax,eax
	mov	al,dl
	shr	eax,3
	and	eax,0111b

	cmp	al,4		;если 4,то пропускаем
	je	.noreg1
	
	mov	esi,[modrm32+8*3*4+eax*4]
    @@:	lodsb			;copy reg		 ;reg*mul+reg_offs
	stosb
	test	al,al
	jnz	@b
	dec	edi
	
	mov	al,dl		;copy mul
	shr	eax,6
	mov	cl,al
	mov	al,1
	shl	al,cl
	add	al,'0'
	cmp	al,'1'		;если множитель = 1 ,то не пишем ничего
	je	@f

	mov	byte[edi],'*'
	inc	edi
	mov	[edi],al
	inc	edi
   @@:
	
	mov	byte[edi],'+'
	inc	edi
.noreg1:
	mov	al,dl
	and	al,0111b
	mov	esi,[modrm32+8*3*4+eax*4]
    @@:	lodsb			;copy reg_offs
	stosb
	test	al,al
	jnz	@b
	dec	edi

	ret
endp

;#################################################################
include "daData.inc"
include "daUData.inc"