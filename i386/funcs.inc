 
;для всех - ret eax -> завершающий строку 0 
proc Mtrl.HToStr1b,inp,Psz
	push	edi
	
	mov	eax,[inp]
	shr	eax,4
	and	eax,0Fh
	
	mov	edi,[Psz]
	cmp	eax,10
	jae	@f
	add	al,30h
	
	mov	byte[edi],al
	
	jmp	.Next
     @@:
	add	al,41h-10
    	mov	byte[edi],'0'
    	mov	[edi+1],al
    	inc	edi
    .Next:
    	inc	edi
    	
    	mov	eax,[inp]
	and	eax,0Fh
	cmp	eax,10
	jae	@f
	add	al,30h
	jmp	.Next1
     @@:
	add	al,41h-10
    .Next1:
	mov	byte[edi],al
	mov	byte[edi+1],'h'
	mov	byte[edi+2],0
	
	lea	eax,[edi+2]
	pop	edi
	ret
endp

proc Mtrl.HToStr2b,inp,Psz
	push	edi
	
	mov	edi,[Psz]
   	
	mov	eax,[inp]
	shr	eax,12
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	
	mov	byte[edi],al
	
	jmp	.Next
     @@:
	add	al,41h-10
    	mov	byte[edi],'0'
    	mov	[edi+1],al
    	inc	edi
    .Next:
    	inc	edi
    	
    	mov	ecx,3
   .Conv:    	
    	mov	eax,[inp]
	 push	ecx
	dec	ecx
	shl	ecx,2
	shr	eax,cl
	 pop	ecx
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	jmp	.Next1
     @@:
	add	al,41h-10
    .Next1:
	mov	byte[edi],al
	inc	edi
	loop	.Conv
	
	mov	byte[edi],'h'
	mov	byte[edi+1],0
	
	lea	eax,[edi+1]
	pop	edi
	ret
endp

proc Mtrl.HToStr4b,inp,Psz
	push	edi
	
	mov	edi,[Psz]
   	
	mov	eax,[inp]
	shr	eax,12
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	
	mov	byte[edi],al
	
	jmp	.Next
     @@:
	add	al,41h-10
    	mov	byte[edi],'0'
    	mov	[edi+1],al
    	inc	edi
    .Next:
    	inc	edi
    	
    	mov	ecx,7
   .Conv:    	
    	mov	eax,[inp]
	 push	ecx
	dec	ecx
	shl	ecx,2
	shr	eax,cl
	 pop	ecx
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	jmp	.Next1
     @@:
	add	al,41h-10
    .Next1:
	mov	byte[edi],al
	inc	edi
	loop	.Conv
	
	mov	byte[edi],'h'
	mov	byte[edi+1],0
	
	lea	eax,[edi+1]
	pop	edi
	ret
endp

proc Mtrl.SignHToStr1b,inp,Psz
	mov	eax,[inp]
	test	al,80h
	jz	@f
	mov	edx,[Psz]
	mov	byte[edx],'-'
	inc	dword[Psz]
	neg	al
	mov	[inp],eax
      @@:
      	stdcall	HToStr1b,[inp],[Psz]	
	ret
endp


proc Intl.HToStr1b,inp,Psz
	push	edi
;int3	
	mov	eax,[inp]
	shr	eax,4
	and	eax,0Fh
	
	mov	edi,[Psz]
	cmp	eax,10
	jae	@f
	add	al,30h
	
	mov	byte[edi],al
	
	jmp	.Next
     @@:
	add	al,41h-10
    	mov	byte[edi],'0'
    	mov	[edi+1],al
    	inc	edi
    .Next:
    	inc	edi
    	
    	mov	eax,[inp]
	
	and	eax,0Fh
	cmp	eax,10
	jae	@f
	add	al,30h
	jmp	.Next1
     @@:
	add	al,41h-10
    .Next1:
	mov	byte[edi],al
	mov	byte[edi+1],'h'
	mov	byte[edi+2],0
	
	lea	eax,[edi+2]
	pop	edi
	ret
endp

proc Intl.HToStr2b,inp,Psz
	push	edi
	
	mov	edi,[Psz]
   	
	mov	eax,[inp]
	shr	eax,12
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	
	mov	byte[edi],al
	
	jmp	.Next
     @@:
	add	al,41h-10
    	mov	byte[edi],'0'
    	mov	[edi+1],al
    	inc	edi
    .Next:
    	inc	edi
    	
    	mov	ecx,3
   .Conv:    	
    	mov	eax,[inp]
	 push	ecx
	dec	ecx
	shl	ecx,2
	shr	eax,cl
	 pop	ecx
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	jmp	.Next1
     @@:
	add	al,41h-10
    .Next1:
	mov	byte[edi],al
	inc	edi
	loop	.Conv
	
	mov	byte[edi],'h'
	mov	byte[edi+1],0
	
	lea	eax,[edi+1]
	pop	edi
	ret
endp

proc Intl.HToStr4b,inp,Psz
	push	edi
	
	mov	edi,[Psz]
   	
	mov	eax,[inp]
	shr	eax,28
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	
	mov	byte[edi],al
	
	jmp	.Next
     @@:
	add	al,41h-10
    	mov	byte[edi],'0'
    	mov	[edi+1],al
    	inc	edi
    .Next:
    	inc	edi
    	
    	mov	ecx,7
   .Conv:    	
    	mov	eax,[inp]
	 push	ecx
	dec	ecx
	shl	ecx,2
	shr	eax,cl
	 pop	ecx
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	jmp	.Next1
     @@:
	add	al,41h-10
    .Next1:
	mov	byte[edi],al
	inc	edi
	loop	.Conv
	
	mov	byte[edi],'h'
	mov	byte[edi+1],0
	
	lea	eax,[edi+1]
	pop	edi
	
	ret
endp

proc Intl.SignHToStr1b,inp,Psz
	mov	eax,[inp]
	test	al,80h
	jz	@f
	mov	edx,[Psz]
	mov	byte[edx],'-'
	inc	dword[Psz]
	neg	al
	mov	[inp],eax
      @@:
      	stdcall	Intl.HToStr1b,[inp],[Psz]	
	ret
endp

proc Intl.SignHToStr2b,inp,Psz
	mov	eax,[inp]
	test	ax,8000h
	jz	@f
	mov	edx,[Psz]
	mov	byte[edx],'-'
	inc	dword[Psz]
	neg	ax
	mov	[inp],eax
      @@:
      	stdcall	Intl.HToStr2b,[inp],[Psz]	
	ret
endp

proc Intl.SignHToStr4b,inp,Psz
	mov	eax,[inp]
	test	eax,80000000h
	jz	@f
	mov	edx,[Psz]
	mov	byte[edx],'-'
	inc	dword[Psz]
	neg	eax
	mov	[inp],eax
      @@:
      	stdcall	Intl.HToStr2b,[inp],[Psz]	
	ret
endp

;не добавляют в случае необходимости 0 перед числом
proc Intl.HToStr1bNN,inp,Psz
	push	edi

	mov	eax,[inp]
	shr	eax,4
	and	eax,0Fh
	
	mov	edi,[Psz]
	cmp	eax,10
	jae	@f
	add	al,30h
	
	mov	byte[edi],al
	
	jmp	.Next
     @@:
	add	al,41h-10
    	mov	[edi],al
    .Next:
    	inc	edi
    	
    	mov	eax,[inp]
	
	and	eax,0Fh
	cmp	eax,10
	jae	@f
	add	al,30h
	jmp	.Next1
     @@:
	add	al,41h-10
    .Next1:
	mov	byte[edi],al
	mov	byte[edi+1],'h'
	mov	byte[edi+2],0
	
	lea	eax,[edi+2]
	pop	edi
	ret
endp

proc Intl.HToStr2bNN,inp,Psz
	push	edi
	
	mov	edi,[Psz]
   	
	mov	eax,[inp]
	shr	eax,12
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	
	mov	byte[edi],al
	
	jmp	.Next
     @@:
	add	al,41h-10
    	mov	[edi],al
    .Next:
    	inc	edi
    	
    	mov	ecx,3
   .Conv:    	
    	mov	eax,[inp]
	 push	ecx
	dec	ecx
	shl	ecx,2
	shr	eax,cl
	 pop	ecx
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	jmp	.Next1
     @@:
	add	al,41h-10
    .Next1:
	mov	byte[edi],al
	inc	edi
	loop	.Conv
	
	mov	byte[edi],'h'
	mov	byte[edi+1],0
	
	lea	eax,[edi+1]
	pop	edi
	
	ret
endp

proc Intl.HToStr4bNN,inp,Psz
push	edi
	
	mov	edi,[Psz]
   	
	mov	eax,[inp]
	shr	eax,28
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	
	mov	byte[edi],al
	
	jmp	.Next
     @@:
	add	al,41h-10
    	mov	[edi],al
    .Next:
    	inc	edi
    	
    	mov	ecx,7
   .Conv:    	
    	mov	eax,[inp]
	 push	ecx
	dec	ecx
	shl	ecx,2
	shr	eax,cl
	 pop	ecx
	and	eax,0Fh
	
	cmp	eax,10
	jae	@f
	add	al,30h
	jmp	.Next1
     @@:
	add	al,41h-10
    .Next1:
	mov	byte[edi],al
	inc	edi
	loop	.Conv
	
	mov	byte[edi],'h'
	mov	byte[edi+1],0
	
	lea	eax,[edi+1]
	pop	edi
	ret
endp


;/////////////////////////////////////////////////////////////////////
;/////////////////////////////////////////////////////////////////////
;/////////////////////////////////////////////////////////////////////

CCallHToStr4b:
	push	ebp
	mov	ebp,esp
	push	dword[ebp+12]
	push	dword[ebp+8]
	call Intl.HToStr4b
	leave
	ret

