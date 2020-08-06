use32
              cmp     dword  [ebp-0C4h],23h
              ja      l00F149CC
              mov     ecx,dword  [ebp-0C4h]
              xor     eax,eax
              mov     al,byte  [ecx+0F150BAh]
              jmp     dword  [eax*4+0F150AAh]
              cmp     dword  [esp+4],1730372h
              jmp     l00F149F3
l00F149CC:    mov     dword  [0F11C08h],2
              mov     dx,word  [0F03000h]
              and     dx,0FFFEh
              mov     word  [0F03000h],dx
              jmp     l00F14B92
              jmp     l00F13038
              jpe     l00F149F8
              jpo     l00F149F8
              call    0784D877Fh
              lock add byte  [eax],al                      ; LOCK prefix
              je      l00F14A3B
              jb      l00F14A06
              jnb     l00F14A06
              call    far 8300:00FD95E8h                       ; Far call
              clc
              add     dh,byte  [ebp+2Bh]
              jl      l00F14A15
              jge     l00F14A15
              call    1CF94FE0h
              int 1
              add     byte  [eax],dl
              add     byte  [eax],al
        
l00F149F8:
l00F14A06:
l00F14A15:
l00F13038:
l00F14B92:
l00F149F3:
l00F14A3B: