section '.data' data readable writeable
mode		dd MODE_32	;0/1 <=> 16/32


;в 8C неточность

szByte		db 'byte',0
szWord		db 'word',0
szDword		db 'dword',0

szPrfxCS	db 'cs:',0
szPrfxDS	db 'ds:',0
szPrfxSS	db 'ss:',0
szPrfxES	db 'es:',0
szPrfxFS	db 'fs:',0
szPrfxGS	db 'gs:',0
szPrfxLock	db 'lock ',0
szPrfxRepe	db 'repe ',0		;в этих пробелы обязательно
szPrfxRepne	db 'repne ',0

mr1	db '[bx+si]',0
mr2	db '[bx+di]',0
mr3	db '[bp+si]',0
mr4	db '[bp+si]',0
mr5	db '[si]',0
mr6	db '[di]',0
mr7	db '[XXXXh]',0
mr8	db '[bx]',0
mr9	db '[bx+si+XXh]',0
mr10	db '[bx+di+XXh]',0
mr11	db '[bp+si+XXh]',0
mr12	db '[bp+si+XXh]',0
mr13	db '[si+XXh]',0
mr14	db '[di+XXh]',0
mr15	db '[bp+XXh]',0
mr16	db '[bx+XXh]',0
mr17	db '[bx+si+XXXXh]',0
mr18	db '[bx+di+XXXXh]',0
mr19	db '[bp+si+XXXXh]',0
mr20	db '[bp+si+XXXXh]',0
mr21	db '[si+XXXXh]',0
mr22	db '[di+XXXXh]',0
mr23	db '[bp+XXXXh]',0
mr24	db '[bx+XXXXh]',0

mr25	db 'ax',0
mr26	db 'cx',0
mr27	db 'dx',0
mr28	db 'bx',0
mr29	db 'sp',0
mr30	db 'bp',0
mr31	db 'si',0
mr32	db 'di',0

mr8_25	db 'al',0
mr8_26	db 'cl',0
mr8_27	db 'dl',0
mr8_28	db 'bl',0
mr8_29	db 'ah',0
mr8_30	db 'ch',0
mr8_31	db 'dh',0
mr8_32	db 'bh',0

mr2_1	db '[eax]'	    ,0		;XXXXXXXXh] должно быть только в конце строки
mr2_2	db '[ecx]'	    ,0
mr2_3	db '[edx]'	    ,0
mr2_4	db '[ebx]'	    ,0
mr2_5	db '[sib]'	    ,0
mr2_6	db '[XXXXXXXXh]'    ,0		;PS: можно убрать ']'
mr2_7	db '[esi]'	    ,0
mr2_8	db '[edi]'	    ,0
mr2_9	db '[eax+XXh]'      ,0
mr2_10	db '[ecx+XXh]'      ,0
mr2_11	db '[edx+XXh]'      ,0
mr2_12	db '[ebx+XXh]'      ,0
mr2_13	db '[sib+XXh]'      ,0
mr2_14	db '[ebp+XXh]'      ,0
mr2_15	db '[esi+XXh]'      ,0
mr2_16	db '[edi+XXh]'      ,0
mr2_17	db '[eax+XXXXXXXXh]',0
mr2_18	db '[ecx+XXXXXXXXh]',0
mr2_19	db '[edx+XXXXXXXXh]',0
mr2_20	db '[ebx+XXXXXXXXh]',0
mr2_21	db '[sib+XXXXXXXXh]',0
mr2_22	db '[ebp+XXXXXXXXh]',0
mr2_23	db '[esi+XXXXXXXXh]',0
mr2_24	db '[edi+XXXXXXXXh]',0
mr2_25	db 'eax'	    ,0
mr2_26	db 'ecx'	    ,0
mr2_27	db 'edx'	    ,0
mr2_28	db 'ebx'	    ,0
mr2_29	db 'esp'	    ,0
mr2_30	db 'ebp'	    ,0
mr2_31	db 'esi'	    ,0
mr2_32	db 'edi'	    ,0

szCS	db 'cs',0
szDS	db 'ds',0
szSS	db 'ss',0
szES	db 'es',0
szFS	db 'fs',0
szGS	db 'gs',0
szST	db 'st',0
szST1	db 'st1',0

szAL	db 'al',0
szCL	db 'cl',0
szDL	db 'dl',0
szBL	db 'bl',0
szAH	db 'ah',0
szCH	db 'ch',0
szDH	db 'dh',0
szBH	db 'bh',0

szAX	db 'ax',0
szCX	db 'cx',0
szDX	db 'dx',0
szBX	db 'bx',0
szSP	db 'sp',0
szBP	db 'bp',0
szSI	db 'si',0
szDI	db 'di',0

szEAX	db 'eax',0
szECX	db 'ecx',0
szEDX	db 'edx',0
szEBX	db 'ebx',0
szESP	db 'esp',0
szEBP	db 'ebp',0
szESI	db 'esi',0
szEDI	db 'edi',0



modrm8	dd mr1,mr2,mr3,mr4,mr5,mr6,mr7,mr8,\
	   mr9,mr10,mr11,mr12,mr13,mr14,mr15,mr16,\
	   mr17,mr18,mr19,mr20,mr21,mr22,mr23,mr24,\
	   mr8_25,mr8_26,mr8_27,mr8_28,mr8_29,mr8_30,mr8_31,mr8_32


modrm16 dd mr1,mr2,mr3,mr4,mr5,mr6,mr7,mr8,\
	   mr9,mr10,mr11,mr12,mr13,mr14,mr15,mr16,\
	   mr17,mr18,mr19,mr20,mr21,mr22,mr23,mr24,\
	   mr25,mr26,mr27,mr28,mr29,mr30,mr31,mr32


modrm32 dd mr2_1,mr2_2,mr2_3,mr2_4,mr2_5,mr2_6,mr2_7,mr2_8,\
	   mr2_9,mr2_10,mr2_11,mr2_12,mr2_13,mr2_14,mr2_15,mr2_16,\
	   mr2_17,mr2_18,mr2_19,mr2_20,mr2_21,mr2_22,mr2_23,mr2_24,\
	   mr2_25,mr2_26,mr2_27,mr2_28,mr2_29,mr2_30,mr2_31,mr2_32


namesReg8  dd szAL,szCL,szDL,szBL,szAH,szCH,szDH,szBH
namesReg16 dd szAX,szCX,szDX,szBX,szSP,szBP,szSI,szDI
namesReg32 dd szEAX,szECX,szEDX,szEBX,szESP,szEBP,szESI,szEDI
namesSReg   dd szES,szCS,szSS,szDS,szFS,szGS,0,0

include 'opNames.inc'

sz db 0

SReAX	SReg szAX,szEAX
SReCX	SReg szCX,szECX
SReDX	SReg szDX,szEDX
SReBX	SReg szBX,szEBX
SReSP	SReg szSP,szESP
SReBP	SReg szBP,szEBP
SReSI	SReg szSI,szESI
SReDI	SReg szDI,szEDI


Q	CMnem szAdd,szOr,szAdc,szSbb,szAnd,szSub,szXor,szCmp
QPop	CMnem szPop,0,0,0,0,0,0,0
QR	CMnem szRol,szRor,szRcl,szRcr,szShl,szShr,szSal,szSar
QMov	CMnem szMov,0,0,0,0,0,0,0
QF1	CMnem szFadd,szFmul,szFcom,szFcomp,szFsub,szFsubr,szFdiv,szFdivr
QF2	CMnem szFld,szFxch,szFst,szFstp,szFldenv,szFldcw,szFnstenv,szFnstcw
QFE	CMnem szInc,szDec,0,0,0,0,0,0

WCbw	CDMnem szCbw,szCwde
WCwd	CDMnem szCwd,szCdq
WPushf	CDMnem szPushf,szPushfd
WPopf	CDMnem szPopf,szPopfd
WPusha	CDMnem szPusha,szPushad
WPopa	CDMnem szPopa,szPopad
WIns	CDMnem szInsw,szInsd
WOuts	CDMnem szOutw,szOutd
WMovsw	CDMnem szMovsw,szMovsd
WCmpsw	CDMnem szCmpsw,szCmpsd
WStosw	CDMnem szStosw,szStosd
WLodsw	CDMnem szLodsw,szLodsd
WScasw	CDMnem szScasw,szScasd
WIret	CDMnem szIret,szIretd
WJcxz	CDMnem szJcxz,szJecxz

cc0	OpCode	szTest	,a.rm8		,a.imm8		,a.no
cc1	OpCode	szTest	,a.rm8		,a.imm8		,a.no
cc2	OpCode	szNot	,a.rm8		,a.no		,a.no
cc3	OpCode	szNeg   ,a.rm8		,a.no		,a.no
cc4	OpCode	szMul	,a.rm8		,a.no		,a.no
cc5	OpCode	szImul	,a.rm8		,a.no		,a.no
cc6	OpCode	szDiv	,a.rm8		,a.no		,a.no
cc7	OpCode	szIdiv	,a.rm8		,a.no		,a.no

cc8	OpCode	szTest	,a.rm1632	,a.imm1632	,a.no
cc9	OpCode	szTest	,a.rm1632	,a.imm1632	,a.no
cc10	OpCode	szNot	,a.rm1632	,a.no		,a.no
cc11	OpCode	szNeg   ,a.rm1632	,a.no		,a.no
cc12	OpCode	szMul	,a.rm1632	,a.no		,a.no
cc13	OpCode	szImul	,a.rm1632	,a.no		,a.no
cc14	OpCode	szDiv	,a.rm1632	,a.no		,a.no
cc15	OpCode	szIdiv	,a.rm1632	,a.no		,a.no

cff0	OpCode	szInc	,a.rm1632	,a.no		,a.no
cff1	OpCode	szDec	,a.rm1632	,a.no		,a.no
cff2	OpCode	szCall	,a.rm1632	,a.no		,a.no
cff3	OpCode	szCall	,a.m16P16X32	,a.no		,a.no
cff4	OpCode	szJmp	,a.rm1632	,a.no		,a.no
cff5	OpCode	szJmp	,a.m16P16X32	,a.no		,a.no
cff6	OpCode	szPush	,a.rm1632	,a.no		,a.no


CF6	COpCode cc0,cc1,cc2,cc3,cc4,cc5,cc6,cc7
CF7	COpCode cc8,cc9,cc10,cc11,cc12,cc13,cc14,cc15

CFF	COpCode cff0,cff1,cff2,cff3,cff4,cff5,cff6,0


c0      OpCode	szAdd   ,a.rm8		,a.r8		,a.no
c1      OpCode	szAdd   ,a.rm1632	,a.r1632	,a.no
c2      OpCode	szAdd   ,a.r8		,a.rm8		,a.no
c3      OpCode	szAdd   ,a.r1632	,a.rm1632	,a.no
c4      OpCode 	szAdd   ,szAL		,a.imm8		,a.no
c5      OpCode 	szAdd   ,SReAX		,a.imm1632	,a.no
c6      OpCode 	szPush  ,szES		,a.no		,a.no
c7      OpCode  szPop   ,szES		,a.no		,a.no
c8      OpCode  szOr    ,a.rm8          ,a.r8           ,a.no
c9      OpCode  szOr    ,a.rm1632       ,a.r1632        ,a.no
c10     OpCode  szOr    ,a.r8           ,a.rm8          ,a.no
c11     OpCode  szOr    ,a.r1632        ,a.rm1632       ,a.no
c12     OpCode  szOr    ,szAL           ,a.imm8         ,a.no
c13     OpCode  szOr    ,SReAX          ,a.imm1632      ,a.no
c14     OpCode  szPush  ,szCS		,a.no		,a.no
;c15     OpCode         
c16     OpCode  szAdc   ,a.rm8          ,a.r8           ,a.no
c17     OpCode  szAdc   ,a.rm1632       ,a.r1632        ,a.no
c18     OpCode  szAdc   ,a.r8           ,a.rm8          ,a.no
c19     OpCode  szAdc   ,a.r1632        ,a.rm1632       ,a.no
c20     OpCode  szAdc   ,szAL           ,a.imm8         ,a.no
c21     OpCode  szAdc   ,SReAX          ,a.imm1632      ,a.no
c22     OpCode  szPush  ,szSS		,a.no		,a.no
c23     OpCode  szPop   ,szSS		,a.no		,a.no
c24     OpCode  szSbb   ,a.rm8          ,a.r8           ,a.no
c25     OpCode  szSbb   ,a.rm1632       ,a.r1632        ,a.no
c26     OpCode  szSbb   ,a.r8           ,a.rm8          ,a.no
c27     OpCode  szSbb   ,a.r1632        ,a.rm1632       ,a.no
c28     OpCode  szSbb   ,szAL           ,a.imm8         ,a.no
c29     OpCode  szSbb   ,SReAX          ,a.imm1632      ,a.no
c30     OpCode  szPush  ,szDS		,a.no		,a.no
c31     OpCode  szPop   ,szDS		,a.no		,a.no
c32     OpCode  szAnd   ,a.rm8          ,a.r8           ,a.no
c33     OpCode  szAnd   ,a.rm1632       ,a.r1632        ,a.no
c34     OpCode  szAnd   ,a.r8           ,a.rm8          ,a.no
c35     OpCode  szAnd   ,a.r1632        ,a.rm1632       ,a.no
c36     OpCode  szAnd   ,szAL           ,a.imm8         ,a.no
c37     OpCode  szAnd   ,SReAX          ,a.imm1632      ,a.no
;c38    OpCode  sz      ,
c39     OpCode  szDaa   ,a.no		,a.no		,a.no
c40     OpCode  szSub   ,a.rm8          ,a.r8           ,a.no
c41     OpCode  szSub   ,a.rm1632       ,a.r1632        ,a.no
c42     OpCode  szSub   ,a.r8           ,a.rm8          ,a.no
c43     OpCode  szSub   ,a.r1632        ,a.rm1632       ,a.no
c44     OpCode  szSub   ,szAL           ,a.imm8         ,a.no
c45     OpCode  szSub   ,SReAX          ,a.imm1632      ,a.no
;c46    OpCode  sz      ,
c47     OpCode  szDas   ,a.no		,a.no		,a.no
c48     OpCode  szXor   ,a.rm8          ,a.r8           ,a.no
c49     OpCode  szXor   ,a.rm1632       ,a.r1632        ,a.no
c50     OpCode  szXor   ,a.r8           ,a.rm8          ,a.no
c51     OpCode  szXor   ,a.r1632        ,a.rm1632       ,a.no
c52     OpCode  szXor   ,szAL           ,a.imm8         ,a.no
c53     OpCode  szXor   ,SReAX          ,a.imm1632      ,a.no
;c54    OpCode  sz      ,
c55     OpCode  szAaa   ,a.no		,a.no		,a.no
c56     OpCode  szCmp   ,a.rm8          ,a.r8           ,a.no
c57     OpCode  szCmp   ,a.rm1632       ,a.r1632        ,a.no
c58     OpCode  szCmp   ,a.r8           ,a.rm8          ,a.no
c59     OpCode  szCmp   ,a.r1632        ,a.rm1632       ,a.no
c60     OpCode  szCmp   ,szAL           ,a.imm8         ,a.no
c61     OpCode  szCmp   ,SReAX          ,a.imm1632      ,a.no
;c62    OpCode  sz      ,
c63     OpCode  szAas	,a.no		,a.no		,a.no
c64     OpCode  szInc   ,SReAX		,a.no		,a.no
c65     OpCode  szInc   ,SReCX		,a.no		,a.no
c66     OpCode  szInc   ,SReDX		,a.no		,a.no
c67     OpCode  szInc   ,SReBX		,a.no		,a.no
c68     OpCode  szInc   ,SReSP		,a.no		,a.no
c69     OpCode  szInc   ,SReBP		,a.no		,a.no
c70     OpCode  szInc   ,SReSI		,a.no		,a.no
c71     OpCode  szInc   ,SReDI		,a.no		,a.no
c72     OpCode  szDec   ,SReAX		,a.no		,a.no
c73     OpCode  szDec   ,SReCX		,a.no		,a.no
c74     OpCode  szDec   ,SReDX		,a.no		,a.no
c75     OpCode  szDec   ,SReBX		,a.no		,a.no
c76     OpCode  szDec   ,SReSP		,a.no		,a.no
c77     OpCode  szDec   ,SReBP		,a.no		,a.no
c78     OpCode  szDec   ,SReSI		,a.no		,a.no
c79     OpCode  szDec   ,SReDI		,a.no		,a.no
c80     OpCode  szPush  ,SReAX		,a.no		,a.no
c81     OpCode  szPush  ,SReCX		,a.no		,a.no
c82     OpCode  szPush  ,SReDX		,a.no		,a.no
c83     OpCode  szPush  ,SReBX		,a.no		,a.no
c84     OpCode  szPush  ,SReSP		,a.no		,a.no
c85     OpCode  szPush  ,SReBP		,a.no		,a.no
c86     OpCode  szPush  ,SReSI		,a.no		,a.no
c87     OpCode  szPush  ,SReDI		,a.no		,a.no
c88     OpCode  szPop   ,SReAX		,a.no		,a.no
c89     OpCode  szPop   ,SReCX		,a.no		,a.no
c90     OpCode  szPop   ,SReDX		,a.no		,a.no
c91     OpCode  szPop   ,SReBX		,a.no		,a.no
c92     OpCode  szPop   ,SReSP		,a.no		,a.no
c93     OpCode  szPop   ,SReBP		,a.no		,a.no
c94     OpCode  szPop   ,SReSI		,a.no		,a.no
c95     OpCode  szPop   ,SReDI		,a.no		,a.no
c96     OpCode  WPusha	,a.no		,a.no		,a.no
c97     OpCode  WPopa	,a.no		,a.no		,a.no
c98     OpCode  szBound ,a.no		,a.no		,a.no
c99     OpCode  szArpl  ,a.rm16		,a.r16		,a.no
;c100   OpCode  sz      ,
;c101   OpCode  sz      ,
;c102   OpCode  sz      ,
;c103   OpCode  sz      ,
c104	OpCode	szPush  ,a.imm1632	,a.no		,a.no                                          
c105    OpCode  szImul  ,a.r1632        ,a.rm1632	,a.imm1632  
c106    OpCode  szPush  ,a.imm8		,a.no		,a.no
c107    OpCode  szImul	,a.r1632        ,a.rm1632       ,a.imm8     
c108    OpCode  szInsb	,a.no		,a.no		,a.no
c109    OpCode  WIns	,a.no		,a.no		,a.no
c110    OpCode  szOutsb	,a.no		,a.no		,a.no
c111    OpCode  WOuts	,a.no		,a.no		,a.no
c112    OpCode  szJo	,a.rel8		,a.no		,a.no
c113    OpCode  szJno	,a.rel8		,a.no		,a.no
c114    OpCode  szJc    ,a.rel8		,a.no		,a.no
c115    OpCode  szJnc   ,a.rel8		,a.no		,a.no
c116    OpCode  szJz    ,a.rel8		,a.no		,a.no
c117    OpCode  szJnz   ,a.rel8		,a.no		,a.no
c118    OpCode  szJbe   ,a.rel8		,a.no		,a.no
c119    OpCode  szJa    ,a.rel8		,a.no		,a.no
c120    OpCode  szJs    ,a.rel8		,a.no		,a.no
c121    OpCode  szJns   ,a.rel8		,a.no		,a.no
c122    OpCode  szJp	,a.rel8		,a.no		,a.no
c123    OpCode  szJnp	,a.rel8		,a.no		,a.no
c124    OpCode  szJl	,a.rel8		,a.no		,a.no
c125    OpCode  szJnl	,a.rel8		,a.no		,a.no
c126    OpCode  szJle	,a.rel8		,a.no		,a.no
c127    OpCode  szJg	,a.rel8		,a.no		,a.no
c128    OpCode  Q       ,a.rm8		,a.imm8		,a.no
c129    OpCode  Q       ,a.rm1632	,a.imm1632	,a.no
c130    OpCode  Q       ,a.rm8		,a.imm8		,a.no
c131    OpCode  Q       ,a.rm1632	,a.imm8		,a.no
c132    OpCode  szTest	,a.rm8		,a.r8		,a.no
c133    OpCode  szTest	,a.rm1632	,a.r1632	,a.no
c134    OpCode  szXchg	,a.r8		,a.rm8		,a.no
c135    OpCode  szXchg	,a.r1632	,a.rm1632	,a.no
c136    OpCode  szMov	,a.rm8		,a.r8		,a.no
c137    OpCode  szMov	,a.rm1632	,a.r1632	,a.no
c138    OpCode  szMov	,a.r8		,a.rm8		,a.no
c139    OpCode  szMov	,a.r1632	,a.rm1632	,a.no
c140    OpCode  szMov	,a.rm1632	,a.sreg		,a.no
c141    OpCode  szLea	,a.r1632	,a.rm1632	,a.no	;moffs	,a.no
c142    OpCode  szMov   ,a.sreg		,a.rm16		,a.no
c143    OpCode  QPop	,a.rm1632	,a.no		,a.no
c144    OpCode  szNop	,a.no		,a.no		,a.no
c145    OpCode  szXchg	,SReCX		,SReAX		,a.no
c146    OpCode  szXchg	,SReDX		,SReAX		,a.no
c147    OpCode  szXchg	,SReBX		,SReAX		,a.no
c148    OpCode  szXchg	,SReSP		,SReAX		,a.no
c149    OpCode  szXchg	,SReBP		,SReAX		,a.no
c150    OpCode  szXchg	,SReSI		,SReAX		,a.no
c151    OpCode  szXchg	,SReDI		,SReAX		,a.no
c152    OpCode  WCbw	,a.no		,a.no		,a.no
c153    OpCode  WCwd	,a.no		,a.no		,a.no
c154    OpCode  szCall	,a.16P16X32	,a.no		,a.no
c155    OpCode  szWait	,a.no		,a.no		,a.no
c156    OpCode  WPushf	,a.no		,a.no		,a.no
c157    OpCode  WPopf	,a.no		,a.no		,a.no
c158    OpCode  szSahf	,a.no		,a.no		,a.no
c159    OpCode  szLahf	,a.no		,a.no		,a.no
c160    OpCode  szMov	,szAL		,a.moffs	,a.no
c161    OpCode  szMov	,SReAX		,a.moffs	,a.no
c162    OpCode  szMov	,a.moffs	,szAL		,a.no
c163    OpCode  szMov	,a.moffs	,SReAX		,a.no
c164    OpCode  szMovsb	,a.no		,a.no		,a.no
c165    OpCode  WMovsw	,a.no		,a.no		,a.no
c166    OpCode  szCmpsb	,a.no		,a.no		,a.no
c167    OpCode  WCmpsw	,a.no		,a.no		,a.no
c168    OpCode  szTest	,szAL		,a.imm8		,a.no
c169    OpCode  szTest	,SReAX		,a.imm1632	,a.no
c170    OpCode  szStosb	,a.no		,a.no		,a.no
c171    OpCode  WStosw	,a.no		,a.no		,a.no
c172    OpCode  szLodsb	,a.no		,a.no		,a.no
c173    OpCode  WLodsw	,a.no		,a.no		,a.no
c174    OpCode  szScasb	,a.no		,a.no		,a.no
c175    OpCode  WScasw	,a.no		,a.no		,a.no
c176    OpCode  szMov	,szAL		,a.imm8		,a.no
c177    OpCode  szMov	,szCL		,a.imm8		,a.no
c178    OpCode  szMov	,szDL		,a.imm8		,a.no
c179    OpCode  szMov	,szBL		,a.imm8		,a.no
c180    OpCode  szMov	,szAH		,a.imm8		,a.no
c181    OpCode  szMov	,szCH		,a.imm8		,a.no
c182    OpCode  szMov	,szDH		,a.imm8		,a.no
c183    OpCode  szMov	,szBH		,a.imm8		,a.no
c184    OpCode  szMov	,SReAX		,a.imm1632	,a.no
c185    OpCode  szMov	,SReCX		,a.imm1632	,a.no
c186    OpCode  szMov	,SReDX		,a.imm1632	,a.no
c187    OpCode  szMov	,SReBX		,a.imm1632	,a.no
c188    OpCode  szMov	,SReSP		,a.imm1632	,a.no
c189    OpCode  szMov	,SReBP		,a.imm1632	,a.no
c190    OpCode  szMov	,SReSI		,a.imm1632	,a.no
c191    OpCode  szMov	,SReDI		,a.imm1632	,a.no
c192    OpCode  QR	,a.rm8		,a.imm8		,a.no
c193    OpCode  QR	,a.rm1632	,a.imm8		,a.no
c194    OpCode  szRet	,a.imm16	,a.no		,a.no
c195    OpCode  szRet	,a.no		,a.no		,a.no
c196    OpCode  szLes	,a.r1632	,a.m16P16X32	,a.no
c197    OpCode  szLds	,a.r1632	,a.m16P16X32	,a.no
c198    OpCode  QMov	,a.rm8		,a.imm8		,a.no
c199    OpCode  QMov	,a.rm1632	,a.imm1632	,a.no
c200    OpCode  szEnter	,a.imm16	,a.imm8		,a.no
c201    OpCode  szLeave	,a.no		,a.no		,a.no
c202    OpCode  szRet	,a.imm16	,a.no		,a.no
c203    OpCode  szRet	,a.no		,a.no		,a.no
c204    OpCode  szInt	,sz3		,a.no		,a.no
c205    OpCode  szInt	,a.imm8		,a.no		,a.no
c206    OpCode  szInto	,a.no		,a.no		,a.no
c207    OpCode  WIret	,a.no		,a.no		,a.no
c208    OpCode  QR	,a.rm8		,sz1		,a.no
c209    OpCode  QR	,a.rm1632	,sz1		,a.no
c210    OpCode  QR	,a.rm8		,szCL		,a.no
c211    OpCode  QR	,a.rm1632	,szCL		,a.no
c212    OpCode  szAam	,a.imm8		,a.no		,a.no
c213    OpCode  szAad	,a.imm8		,a.no		,a.no
c214    OpCode  szSalc	,a.no		,a.no		,a.no
c215    OpCode  szXlatb	,a.no		,a.no		,a.no
c216    OpCode  QF1	,szST		,a.STi_m32real	,a.no
c217    OpCode  QF2	,a.no		,a.no		,a.no
c218    OpCode  sz	,a.no		,a.no		,a.no
c219    OpCode  sz	,a.no		,a.no		,a.no
c220    OpCode  sz	,a.no		,a.no		,a.no
c221    OpCode  sz	,a.no		,a.no		,a.no
c222    OpCode  sz	,a.no		,a.no		,a.no
c223    OpCode  sz	,a.no		,a.no		,a.no
c224    OpCode  szLoopnz,a.rel8		,a.no		,a.no
c225    OpCode  szLoopz	,a.rel8		,a.no		,a.no
c226    OpCode  szLoop	,a.rel8		,a.no		,a.no
c227    OpCode  WJcxz	,a.rel8		,SReCX		,a.no
c228    OpCode  szIn	,szAX		,a.imm8		,a.no
c229    OpCode  szIn	,szEAX		,a.imm8		,a.no
c230    OpCode  szOut	,a.imm8		,szAX		,a.no
c231    OpCode  szOut	,a.imm8		,szEAX		,a.no
c232    OpCode  szCall	,a.rel1632	,a.no		,a.no
c233    OpCode  szJmp	,a.rel1632	,a.no		,a.no
c234    OpCode  szJmp	,a.16P16X32	,a.no		,a.no
c235    OpCode  szJmp	,a.rel8		,a.no		,a.no
c236    OpCode  szIn	,szAX		,szDX		,a.no
c237    OpCode  szIn	,szEAX		,szDX		,a.no
c238    OpCode  szOut	,szDX		,szAX		,a.no
c239    OpCode  szOut	,szDX		,szEAX		,a.no
;c240    OpCode  sz	,a.no		,a.no		,a.no
c241    OpCode  szInt	,sz1		,a.no		,a.no
;c242    OpCode  sz	,a.no		,a.no		,a.no
;c243    OpCode  sz	,a.no		,a.no		,a.no
c244    OpCode  szHlt	,a.no		,a.no		,a.no
c245    OpCode  szCmc	,a.no		,a.no		,a.no
c246    OpCode  CF6	,a.no		,a.no		,a.no
c247    OpCode  CF7	,a.no		,a.no		,a.no
c248    OpCode  szClc	,a.no		,a.no		,a.no
c249    OpCode  szStc	,a.no		,a.no		,a.no
c250    OpCode  szCli	,a.no		,a.no		,a.no
c251    OpCode  szSti	,a.no		,a.no		,a.no
c252    OpCode  szCld	,a.no		,a.no		,a.no
c253    OpCode  szStd	,a.no		,a.no		,a.no
c254    OpCode  QFE	,a.rm8		,a.no		,a.no
c255    OpCode  CFF	,a.no		,a.no		,a.no
               
;cf0 OpCode
;cf1 OpCode
;cf2 OpCode
;cf3 OpCode
;cf4 OpCode
;cf5 OpCode
;cf6 OpCode
;cf7 OpCode
;cf8 OpCode
;cf9 OpCode
;cf10 OpCode
;cf11 OpCode
;cf12 OpCode
;cf13 OpCode
;cf14 OpCode
;cf15 OpCode
;cf16 OpCode
;cf17 OpCode
;cf18 OpCode
;cf19 OpCode
;cf20 OpCode
;cf21 OpCode
;cf22 OpCode
;cf23 OpCode
;cf24 OpCode
;cf25 OpCode
;cf26 OpCode
;cf27 OpCode
;cf28 OpCode
;cf29 OpCode
;cf30 OpCode
;cf31 OpCode
;cf32 OpCode
;cf33 OpCode
;cf34 OpCode
;cf35 OpCode
;cf36 OpCode
;cf37 OpCode
;cf38 OpCode
;cf39 OpCode
;cf40 OpCode
;cf41 OpCode
;cf42 OpCode
;cf43 OpCode
;cf44 OpCode
;cf45 OpCode
;cf46 OpCode
;cf47 OpCode
;cf48 OpCode
;cf49 OpCode
;cf50 OpCode
;cf51 OpCode
;cf52 OpCode
;cf53 OpCode
;cf54 OpCode
;cf55 OpCode
;cf56 OpCode
;cf57 OpCode
;cf58 OpCode
;cf59 OpCode
;cf60 OpCode
;cf61 OpCode
;cf62 OpCode
;cf63 OpCode
;cf64 OpCode
;cf65 OpCode
;cf66 OpCode
;cf67 OpCode
;cf68 OpCode
;cf69 OpCode
;cf70 OpCode
;cf71 OpCode
;cf72 OpCode
;cf73 OpCode
;cf74 OpCode
;cf75 OpCode
;cf76 OpCode
;cf77 OpCode
;cf78 OpCode
;cf79 OpCode
;cf80 OpCode
;cf81 OpCode
;cf82 OpCode
;cf83 OpCode
;cf84 OpCode
;cf85 OpCode
;cf86 OpCode
;cf87 OpCode
;cf88 OpCode
;cf89 OpCode
;cf90 OpCode
;cf91 OpCode
;cf92 OpCode
;cf93 OpCode
;cf94 OpCode
;cf95 OpCode
;cf96 OpCode
;cf97 OpCode
;cf98 OpCode
;cf99 OpCode
;cf100 OpCode
;cf101 OpCode
;cf102 OpCode
;cf103 OpCode
;cf104 OpCode
;cf105 OpCode
;cf106 OpCode
;cf107 OpCode
;cf108 OpCode
;cf109 OpCode
;cf110 OpCode
;cf111 OpCode
;cf112 OpCode
;cf113 OpCode
;cf114 OpCode
;cf115 OpCode
;cf116 OpCode
;cf117 OpCode
;cf118 OpCode
;cf119 OpCode
;cf120 OpCode
;cf121 OpCode
;cf122 OpCode
;cf123 OpCode
;cf124 OpCode
;cf125 OpCode
;cf126 OpCode
;cf127 OpCode
cf128 OpCode	szJo	,a.rel1632	,a.no	,a.no
cf129 OpCode	szJno	,a.rel1632	,a.no	,a.no
cf130 OpCode	szJc	,a.rel1632	,a.no	,a.no
cf131 OpCode	szJnc	,a.rel1632	,a.no	,a.no
cf132 OpCode	szJz	,a.rel1632	,a.no	,a.no
cf133 OpCode	szJnz	,a.rel1632	,a.no	,a.no
cf134 OpCode	szJbe	,a.rel1632	,a.no	,a.no
cf135 OpCode	szJa	,a.rel1632	,a.no	,a.no
cf136 OpCode	szJs	,a.rel1632	,a.no	,a.no
cf137 OpCode	szJns	,a.rel1632	,a.no	,a.no
cf138 OpCode	szJp	,a.rel1632	,a.no	,a.no
cf139 OpCode	szJnp	,a.rel1632	,a.no	,a.no
cf140 OpCode	szJl	,a.rel1632	,a.no	,a.no
cf141 OpCode	szJnl	,a.rel1632	,a.no	,a.no
cf142 OpCode	szJle	,a.rel1632	,a.no	,a.no
cf143 OpCode	szJg	,a.rel1632	,a.no	,a.no
;cf144 OpCode
;cf145 OpCode
;cf146 OpCode
;cf147 OpCode
;cf148 OpCode
;cf149 OpCode
;cf150 OpCode
;cf151 OpCode
;cf152 OpCode
;cf153 OpCode
;cf154 OpCode
;cf155 OpCode
;cf156 OpCode
;cf157 OpCode
;cf158 OpCode
;cf159 OpCode
;cf160 OpCode
;cf161 OpCode
;cf162 OpCode
;cf163 OpCode
;cf164 OpCode
;cf165 OpCode
;cf166 OpCode
;cf167 OpCode
;cf168 OpCode
;cf169 OpCode
;cf170 OpCode
;cf171 OpCode
;cf172 OpCode
;cf173 OpCode
;cf174 OpCode
;cf175 OpCode
;cf176 OpCode
;cf177 OpCode
;cf178 OpCode
;cf179 OpCode
;cf180 OpCode
;cf181 OpCode
;cf182 OpCode
;cf183 OpCode
;cf184 OpCode
;cf185 OpCode
;cf186 OpCode
;cf187 OpCode
;cf188 OpCode
;cf189 OpCode
;cf190 OpCode
;cf191 OpCode
;cf192 OpCode
;cf193 OpCode
;cf194 OpCode
;cf195 OpCode
;cf196 OpCode
;cf197 OpCode
;cf198 OpCode
;cf199 OpCode
;cf200 OpCode
;cf201 OpCode
;cf202 OpCode
;cf203 OpCode
;cf204 OpCode
;cf205 OpCode
;cf206 OpCode
;cf207 OpCode
;cf208 OpCode
;cf209 OpCode
;cf210 OpCode
;cf211 OpCode
;cf212 OpCode
;cf213 OpCode
;cf214 OpCode
;cf215 OpCode
;cf216 OpCode
;cf217 OpCode
;cf218 OpCode
;cf219 OpCode
;cf220 OpCode
;cf221 OpCode
;cf222 OpCode
;cf223 OpCode
;cf224 OpCode
;cf225 OpCode
;cf226 OpCode
;cf227 OpCode
;cf228 OpCode
;cf229 OpCode
;cf230 OpCode
;cf231 OpCode
;cf232 OpCode
;cf233 OpCode
;cf234 OpCode
;cf235 OpCode
;cf236 OpCode
;cf237 OpCode
;cf238 OpCode
;cf239 OpCode
;cf240 OpCode
;cf241 OpCode
;cf242 OpCode
;cf243 OpCode
;cf244 OpCode
;cf245 OpCode
;cf246 OpCode
;cf247 OpCode
;cf248 OpCode
;cf249 OpCode
;cf250 OpCode
;cf251 OpCode
;cf252 OpCode
;cf253 OpCode
;cf254 OpCode
;cf255 OpCode


b1OpCod:
	dd   c0,   c1,   c2,   c3,   c4,   c5,   c6,   c7,   c8,   c9,  c10,  c11,  c12,  c13,  c14,    0 
	dd  c16,  c17,  c18,  c19,  c20,  c21,  c22,  c23,  c24,  c25,  c26,  c27,  c28,  c29,  c30,  c31 
	dd  c32,  c33,  c34,  c35,  c36,  c37,    0,  c39,  c40,  c41,  c42,  c43,  c44,  c45,    0,  c47 
	dd  c48,  c49,  c50,  c51,  c52,  c53,    0,  c55,  c56,  c57,  c58,  c59,  c60,  c61,    0,  c63 
	dd  c64,  c65,  c66,  c67,  c68,  c69,  c70,  c71,  c72,  c73,  c74,  c75,  c76,  c77,  c78,  c79 
	dd  c80,  c81,  c82,  c83,  c84,  c85,  c86,  c87,  c88,  c89,  c90,  c91,  c92,  c93,  c94,  c95 
	dd  c96,  c97,  c98,  c99,    0,    0,    0,    0, c104, c105, c106, c107, c108, c109, c110, c111 
	dd c112, c113, c114, c115, c116, c117, c118, c119, c120, c121, c122, c123, c124, c125, c126, c127 
	dd c128, c129, c130, c131, c132, c133, c134, c135, c136, c137, c138, c139, c140, c141, c142, c143 
	dd c144, c145, c146, c147, c148, c149, c150, c151, c152, c153, c154, c155, c156, c157, c158, c159 
	dd c160, c161, c162, c163, c164, c165, c166, c167, c168, c169, c170, c171, c172, c173, c174, c175 
	dd c176, c177, c178, c179, c180, c181, c182, c183, c184, c185, c186, c187, c188, c189, c190, c191 
	dd c192, c193, c194, c195, c196, c197, c198, c199, c200, c201, c202, c203, c204, c205, c206, c207 
	dd c208, c209, c210, c211, c212, c213, c214, c215, c216, c217, c218, c219, c220, c221, c222, c223 
	dd c224, c225, c226, c227, c228, c229, c230, c231, c232, c233, c234, c235, c236, c237, c238, c239 
	dd    0, c241,    0,    0, c244, c245, c246, c247, c248, c249, c250, c251, c252, c253, c254, c255

b2OpCod:
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0

	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0

	dd cf128,cf129,cf130,cf131 ,cf132,cf133,cf134,cf135 ,cf136,cf137,cf138,cf139 ,cf140,cf141,cf142,cf143
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0

	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	dd 0,0,0,0 ,0,0,0,0 ,0,0,0,0 ,0,0,0,0
	


;c0	OpCode szAdd   ,TRegMem        ,TReg    	,TNo	,a.reg	,a.reg	
;c1	OpCode szAdd   ,TRegMem        ,TReg    	,TNo	,a.reg	,a.reg	
;c2	OpCode szAdd   ,TReg           ,TRegMem 	,TNo	,a.reg	,a.reg	
;c3	OpCode szAdd   ,TReg           ,TRegMem 	,TNo	,a.reg	,a.reg	
;c4	OpCode szAdd   ,TPnt           ,TImm    	,TNo	,szAL	,0
;c5	OpCode szAdd   ,TSReg          ,TImm    	,TNo    ,SReAX	,0
;c6	OpCode szPush  ,TPnt           ,TNo       	,TNo    ,szES	,0	
;c7	OpCode szPop   ,TPnt           ,TNo       	,TNo    ,szES	,0
;c8	OpCode szOr    ,TRegMem        ,TReg    	,TNo    ,a.reg	,a.reg	
;c9	OpCode szOr    ,TRegMem        ,TReg    	,TNo    ,a.reg	,a.reg	
;c10	OpCode szOr    ,TReg           ,TRegMem 	,TNo    ,a.reg	,a.reg	
;c11	OpCode szOr    ,TReg           ,TRegMem 	,TNo    ,a.reg	,a.reg	
;c12	OpCode szOr    ,TPnt           ,TImm    	,TNo    ,szAL	,0	
;c13	OpCode szOr    ,TPnt           ,TImm    	,TNo    ,SReAX	,0	
;c14	OpCode szPush  ,TPnt           ,TNo       	,TNo    ,szCS	,0	
;;c15     OpCode                                 
;c16	OpCode szAdc   ,TRegMem        ,TReg    	,TNo    ,a.reg	,a.reg	
;c17	OpCode szAdc   ,TRegMem        ,TReg    	,TNo    ,a.reg	,a.reg	
;c18	OpCode szAdc   ,TReg           ,TRegMem 	,TNo    ,a.reg	,a.reg	
;c19	OpCode szAdc   ,TReg           ,TRegMem 	,TNo    ,a.reg	,a.reg	
;c20	OpCode szAdc   ,TPnt           ,TImm    	,TNo    ,szAL	,0	
;c21	OpCode szAdc   ,TPnt           ,TImm    	,TNo    ,SReAX	,0	
;c22	OpCode szPush  ,TPnt           ,0       	,TNo    ,szSS	,0	
;c23	OpCode szPop   ,TPnt           ,0       	,TNo    ,szSS	,0	
;c24	OpCode szSbb   ,TRegMem        ,TReg    	,TNo    ,a.reg  ,a.reg  
;c25	OpCode szSbb   ,TRegMem        ,TReg    	,TNo    ,a.reg  ,a.reg  
;c26	OpCode szSbb   ,TReg           ,TRegMem 	,TNo    ,a.reg  ,a.reg   
;c27	OpCode szSbb   ,TReg           ,TRegMem 	,TNo    ,a.reg  ,a.reg   
;c28	OpCode szSbb   ,TPnt           ,TImm    	,TNo    ,szAL   ,0  
;c29	OpCode szSbb   ,TPnt           ,TImm    	,TNo    ,SReAX  ,0  
;c30	OpCode szPush  ,TPnt           ,0        	,TNo    ,szDS   ,0   
;c31	OpCode szPop   ,TPnt           ,0        	,TNo    ,szDS   ,0   
;c32	OpCode szAnd   ,TRegMem        ,TReg    	,TNo    ,a.reg	,a.reg  
;c33	OpCode szAnd   ,TRegMem        ,TReg    	,TNo    ,a.reg	,a.reg  
;c34	OpCode szAnd   ,TReg           ,TRegMem 	,TNo    ,a.reg  ,a.reg   
;c35	OpCode szAnd   ,TReg           ,TRegMem 	,TNo    ,a.reg  ,a.reg   
;c36	OpCode szAnd   ,TPnt           ,TImm    	,TNo    ,szAL   ,0  
;c37	OpCode szAnd   ,TPnt           ,TImm    	,TNo    ,SReAX  ,0  
;;c38	OpCode sz      ,               ,        	,TNo    ,	,	
;c39	OpCode szDaa   ,0              ,0       	,TNo    ,0	,0	
;c40	OpCode szSub   ,TRegMem        ,TReg     	,TNo    ,a.reg   ,a.reg   
;c41	OpCode szSub   ,TRegMem        ,TReg     	,TNo    ,a.reg   ,a.reg   
;c42	OpCode szSub   ,TReg           ,TRegMem  	,TNo    ,a.reg  ,a.reg    
;c43	OpCode szSub   ,TReg           ,TRegMem  	,TNo    ,a.reg  ,a.reg    
;c44	OpCode szSub   ,TPnt           ,TImm     	,TNo    ,szAL   ,0   
;c45	OpCode szSub   ,TPnt           ,TImm     	,TNo    ,SReAX  ,0   
;;c46	OpCode sz      ,               ,        	,TNo    ,	,	
;c47	OpCode szDas   ,0              ,0       	,TNo    ,0	,0	
;c48	OpCode szXor   ,TRegMem        ,TReg    	,TNo    ,a.reg   ,a.reg   
;c49	OpCode szXor   ,TRegMem        ,TReg    	,TNo    ,a.reg   ,a.reg   
;c50	OpCode szXor   ,TReg           ,TRegMem 	,TNo    ,a.reg  ,a.reg    
;c51	OpCode szXor   ,TReg           ,TRegMem 	,TNo    ,a.reg  ,a.reg    
;c52	OpCode szXor   ,TPnt           ,TImm    	,TNo    ,szAL   ,0   
;c53	OpCode szXor   ,TPnt           ,TImm    	,TNo    ,SReAX  ,0   
;;c54	OpCode sz      ,               ,        	,TNo    ,	,	
;c55	OpCode szAaa   ,0              ,0       	,TNo    ,0	,0	
;c56	OpCode szCmp   ,TRegMem        ,TReg    	,TNo    ,a.reg   ,a.reg   
;c57	OpCode szCmp   ,TRegMem        ,TReg    	,TNo    ,a.reg   ,a.reg   
;c58	OpCode szCmp   ,TReg           ,TRegMem 	,TNo    ,a.reg  ,a.reg    
;c59	OpCode szCmp   ,TReg           ,TRegMem 	,TNo    ,a.reg  ,a.reg    
;c60	OpCode szCmp   ,TPnt           ,TImm    	,TNo    ,szAL   ,0   
;c61	OpCode szCmp   ,TPnt           ,TImm    	,TNo    ,SReAX  ,0   
;;c62	OpCode sz      ,               ,        	,TNo    ,	,	
;c63	OpCode szAas   ,0              ,0       	,TNo    ,0	,0	
;c64	OpCode szInc   ,TReg           ,0       	,TNo    ,SReAX	,0	
;c65	OpCode szInc   ,TReg           ,0       	,TNo    ,SReCX	,0	
;c66	OpCode szInc   ,TReg           ,0       	,TNo    ,SReDX	,0	
;c67	OpCode szInc   ,TReg           ,0       	,TNo    ,SReBX	,0	
;c68	OpCode szInc   ,TReg           ,0       	,TNo    ,SReSP	,0	
;c69	OpCode szInc   ,TReg           ,0       	,TNo    ,SReBP	,0	
;c70	OpCode szInc   ,TReg           ,0       	,TNo    ,SReSI	,0	
;c71	OpCode szInc   ,TReg           ,0       	,TNo    ,SReDI	,0	
;c72	OpCode szDec   ,TReg           ,0       	,TNo    ,SReAX	,0	
;c73	OpCode szDec   ,TReg           ,0       	,TNo    ,SReCX	,0	
;c74	OpCode szDec   ,TReg           ,0       	,TNo    ,SReDX	,0	
;c75	OpCode szDec   ,TReg           ,0       	,TNo    ,SReBX	,0	
;c76	OpCode szDec   ,TReg           ,0       	,TNo    ,SReSP	,0	
;c77	OpCode szDec   ,TReg           ,0       	,TNo    ,SReBP	,0	
;c78	OpCode szDec   ,TReg           ,0       	,TNo    ,SReSI	,0 	
;c79	OpCode szDec   ,TReg           ,0       	,TNo    ,SReDI	,0 	
;c80	OpCode szPush  ,TReg           ,0       	,TNo    ,SReAX	,0	
;c81	OpCode szPush  ,TReg           ,0       	,TNo    ,SReCX	,0	
;c82	OpCode szPush  ,TReg           ,0       	,TNo    ,SReDX	,0	
;c83	OpCode szPush  ,TReg           ,0       	,TNo    ,SReBX	,0	
;c84	OpCode szPush  ,TReg           ,0       	,TNo    ,SReSP	,0	
;c85	OpCode szPush  ,TReg           ,0       	,TNo    ,SReBP	,0	
;c86	OpCode szPush  ,TReg           ,0       	,TNo    ,SReSI	,0	
;c87	OpCode szPush  ,TReg           ,0       	,TNo    ,SReDI	,0	
;c88	OpCode szPop   ,TReg           ,0       	,TNo    ,SReAX	,0	
;c89	OpCode szPop   ,TReg           ,0       	,TNo    ,SReCX	,0	
;c90	OpCode szPop   ,TReg           ,0       	,TNo    ,SReDX	,0	
;c91	OpCode szPop   ,TReg           ,0       	,TNo    ,SReBX	,0	
;c92	OpCode szPop   ,TReg           ,0       	,TNo    ,SReSP	,0	
;c93	OpCode szPop   ,TReg           ,0       	,TNo    ,SReBP	,0	
;c94	OpCode szPop   ,TReg           ,0       	,TNo    ,SReSI	,0	
;c95	OpCode szPop   ,TReg           ,0       	,TNo    ,SReDI	,0	
;c96	OpCode szPushA ,0              ,0       	,TNo    ,0	,0	
;c97	OpCode szPopA  ,0              ,0       	,TNo    ,0	,0	
;c98	OpCode szBound ,TReg           ,TRegMem 	,TNo    ,a.reg  ,a.reg   
;c99	OpCode szArpl  ,TRegMem        ,TReg    	,TNo    ,a.reg	,a.reg	
;;c100	OpCode sz      ,               ,        	,TNo    ,	,	
;;c101	OpCode sz      ,               ,        	,TNo    ,	,	
;;c102	OpCode sz      ,               ,        	,TNo    ,	,	
;;c103	OpCode sz      ,               ,        	,TNo    ,	,	
;;c104	OpCode sz      ,               ,        	,TNo    ,	,	
;c105	OpCode szPush  ,TImm           ,0       	,TNo    ,0	,0	
;c106	OpCode szImul  ,               ,        	,TNo    ,	,	
;c107	OpCode szPush  ,               ,        	,TNo    ,	,	
;c108	OpCode szImul  ,               ,        	,TNo    ,	,	
;c109	OpCode sz      ,               ,        	,TNo    ,	,	
;c110	OpCode sz      ,               ,        	,TNo    ,	,	
;c111	OpCode sz      ,               ,        	,TNo    ,	,	
;c112	OpCode sz      ,               ,        	,TNo    ,	,	
;c113	OpCode sz      ,               ,        	,TNo    ,	,	
;c114	OpCode sz      ,               ,        	,TNo    ,	,	
;c115	OpCode sz      ,               ,        	,TNo    ,	,	
;c116	OpCode sz      ,               ,        	,TNo    ,	,	
;c117	OpCode sz      ,               ,        	,TNo    ,	,	
;c118	OpCode sz      ,               ,        	,TNo    ,	,	
;c119	OpCode sz      ,               ,        	,TNo    ,	,	
;c120	OpCode sz      ,               ,        	,TNo    ,	,	
;c121	OpCode sz      ,               ,        	,TNo    ,	,	
;c122	OpCode sz      ,               ,        	,TNo    ,	,	
;c123	OpCode sz      ,               ,        	,TNo    ,	,	
;c124	OpCode sz      ,               ,        	,TNo    ,	,	
;c125	OpCode sz      ,               ,        	,TNo    ,	,	
;c126	OpCode sz      ,               ,        	,TNo    ,	,	
;c127	OpCode sz      ,               ,        	,TNo    ,	,	
;c128	OpCode sz      ,               ,        	,TNo    ,	,	
;c129	OpCode sz      ,               ,        	,TNo    ,	,	
;c130	OpCode sz      ,               ,        	,TNo    ,	,	
;c131	OpCode sz      ,               ,        	,TNo    ,	,	
;c132	OpCode sz      ,               ,        	,TNo    ,	,	
;c133	OpCode sz      ,               ,        	,TNo    ,	,	
;c134	OpCode sz      ,               ,        	,TNo    ,	,	
;c135	OpCode sz      ,               ,        	,TNo    ,	,	
;c136	OpCode sz      ,               ,        	,TNo    ,	,	
;c137	OpCode sz      ,               ,        	,TNo    ,	,	
;c138	OpCode sz      ,               ,        	,TNo    ,	,	
;c139	OpCode sz      ,               ,        	,TNo    ,	,	
;c140	OpCode sz      ,               ,        	,TNo    ,	,	
;c141	OpCode sz      ,               ,        	,TNo    ,	,	
;c142	OpCode sz      ,               ,        	,TNo    ,	,	
;c143	OpCode sz      ,               ,        	,TNo    ,	,	
;c144	OpCode sz      ,               ,        	,TNo    ,	,	
;c145	OpCode sz      ,               ,        	,TNo    ,	,	
;c146	OpCode sz      ,               ,        	,TNo    ,	,	
;c147	OpCode sz      ,               ,        	,TNo    ,	,	
;c148	OpCode sz      ,               ,        	,TNo    ,	,	
;c149	OpCode sz      ,               ,        	,TNo    ,	,	
;c150	OpCode sz      ,               ,        	,TNo    ,	,	
;c151	OpCode sz      ,               ,        	,TNo    ,	,	
;c152	OpCode sz      ,               ,        	,TNo    ,	,	
;c153	OpCode sz      ,               ,        	,TNo    ,	,	
;c154	OpCode sz      ,               ,        	,TNo    ,	,	
;c155	OpCode sz      ,               ,        	,TNo    ,	,	
;c156	OpCode sz      ,               ,        	,TNo    ,	,	
;c157	OpCode sz      ,               ,        	,TNo    ,	,	
;c158	OpCode sz      ,               ,        	,TNo    ,	,	
;c159	OpCode sz      ,               ,        	,TNo    ,	,	
;c160	OpCode sz      ,               ,        	,TNo    ,	,	
;c161	OpCode sz      ,               ,        	,TNo    ,	,	
;c162	OpCode sz      ,               ,        	,TNo    ,	,	
;c163	OpCode sz      ,               ,        	,TNo    ,	,	
;c164	OpCode sz      ,               ,        	,TNo    ,	,	
;c165	OpCode sz      ,               ,        	,TNo    ,	,	
;c166	OpCode sz      ,               ,        	,TNo    ,	,	
;c167	OpCode sz      ,               ,        	,TNo    ,	,	
;c168	OpCode sz      ,               ,        	,TNo    ,	,	
;c169	OpCode sz      ,               ,        	,TNo    ,	,	
;c170	OpCode sz      ,               ,        	,TNo    ,	,	
;c171	OpCode sz      ,               ,        	,TNo    ,	,	
;c172	OpCode sz      ,               ,        	,TNo    ,	,	
;c173	OpCode sz      ,               ,        	,TNo    ,	,	
;c174	OpCode sz      ,               ,        	,TNo    ,	,	
;c175	OpCode sz      ,               ,        	,TNo    ,	,	
;c176	OpCode sz      ,               ,        	,TNo    ,	,	
;c177	OpCode sz      ,               ,        	,TNo    ,	,	
;c178	OpCode sz      ,               ,        	,TNo    ,	,	
;c179	OpCode sz      ,               ,        	,TNo    ,	,	
;c180	OpCode sz      ,               ,        	,TNo    ,	,	
;c181	OpCode sz      ,               ,        	,TNo    ,	,	
;c182	OpCode sz      ,               ,        	,TNo    ,	,	
;c183	OpCode sz      ,               ,        	,TNo    ,	,	
;c184	OpCode sz      ,               ,        	,TNo    ,	,	
;c185	OpCode sz      ,               ,        	,TNo    ,	,	
;c186	OpCode sz      ,               ,        	,TNo    ,	,	
;c187	OpCode sz      ,               ,        	,TNo    ,	,	
;c188	OpCode sz      ,               ,        	,TNo    ,	,	
;c189	OpCode sz      ,               ,        	,TNo    ,	,	
;c190	OpCode sz      ,               ,        	,TNo    ,	,	
;c191	OpCode sz      ,               ,        	,TNo    ,	,	
;c192	OpCode sz      ,               ,        	,TNo    ,	,	
;c193	OpCode sz      ,               ,        	,TNo    ,	,	
;c194	OpCode sz      ,               ,        	,TNo    ,	,	
;c195	OpCode sz      ,               ,        	,TNo    ,	,	
;c196	OpCode sz      ,               ,        	,TNo    ,	,	
;c197	OpCode sz      ,               ,        	,TNo    ,	,	
;c198	OpCode sz      ,               ,        	,TNo    ,	,	
;c199	OpCode sz      ,               ,        	,TNo    ,	,	
;c200	OpCode sz      ,               ,        	,TNo    ,	,	
;c201	OpCode sz      ,               ,        	,TNo    ,	,	
;c202	OpCode sz      ,               ,        	,TNo    ,	,	
;c203	OpCode sz      ,               ,        	,TNo    ,	,	
;c204	OpCode sz      ,               ,        	,TNo    ,	,	
;c205	OpCode sz      ,               ,        	,TNo    ,	,	
;c206	OpCode sz      ,               ,        	,TNo    ,	,	
;c207	OpCode sz      ,               ,        	,TNo    ,	,	
;c208	OpCode sz      ,               ,        	,TNo    ,	,	
;c209	OpCode sz      ,               ,        	,TNo    ,	,	
;c210	OpCode sz      ,               ,        	,TNo    ,	,	
;c211	OpCode sz      ,               ,        	,TNo    ,	,	
;c212	OpCode sz      ,               ,        	,TNo    ,	,	
;c213	OpCode sz      ,               ,        	,TNo    ,	,	
;c214	OpCode sz      ,               ,        	,TNo    ,	,	
;c215	OpCode sz      ,               ,        	,TNo    ,	,	
;c216	OpCode sz      ,               ,        	,TNo    ,	,	
;c217	OpCode sz      ,               ,        	,TNo    ,	,	
;c218	OpCode sz      ,               ,        	,TNo    ,	,	
;c219	OpCode sz      ,               ,        	,TNo    ,	,	
;c220	OpCode sz      ,               ,        	,TNo    ,	,	
;c221	OpCode sz      ,               ,        	,TNo    ,	,	
;c222	OpCode sz      ,               ,        	,TNo    ,	,	
;c223	OpCode sz      ,               ,        	,TNo    ,	,	
;c224	OpCode sz      ,               ,        	,TNo    ,	,	
;c225	OpCode sz      ,               ,        	,TNo    ,	,	
;c226	OpCode sz      ,               ,        	,TNo    ,	,	
;c227	OpCode sz      ,               ,        	,TNo    ,	,	
;c228	OpCode sz      ,               ,        	,TNo    ,	,	
;c229	OpCode sz      ,               ,        	,TNo    ,	,	
;c230	OpCode sz      ,               ,        	,TNo    ,	,	
;c231	OpCode sz      ,               ,        	,TNo    ,	,	
;c232	OpCode sz      ,               ,        	,TNo    ,	,	
;c233	OpCode sz      ,               ,        	,TNo    ,	,	
;c234	OpCode sz      ,               ,        	,TNo    ,	,	
;c235	OpCode sz      ,               ,        	,TNo    ,	,	
;c236	OpCode sz      ,               ,        	,TNo    ,	,	
;c237	OpCode sz      ,               ,        	,TNo    ,	,	
;c238	OpCode sz      ,               ,        	,TNo    ,	,	
;c239	OpCode sz      ,               ,        	,TNo    ,	,	
;c240	OpCode sz      ,               ,        	,TNo    ,	,	
;c241	OpCode sz      ,               ,        	,TNo    ,	,	
;c242	OpCode sz      ,               ,        	,TNo    ,	,	
;c243	OpCode sz      ,               ,        	,TNo    ,	,	
;c244	OpCode sz      ,               ,        	,TNo    ,	,	
;c245	OpCode sz      ,               ,        	,TNo    ,	,	
;c246	OpCode sz      ,               ,        	,TNo    ,	,	
;c247	OpCode sz      ,               ,        	,TNo    ,	,	
;c248	OpCode sz      ,               ,        	,TNo    ,	,	
;c249	OpCode sz      ,               ,        	,TNo    ,	,	
;c250	OpCode sz      ,               ,        	,TNo    ,	,	
;c251	OpCode sz      ,               ,        	,TNo    ,	,	
;c252	OpCode sz      ,               ,        	,TNo    ,	,	
;c253	OpCode sz      ,               ,        	,TNo    ,	,	
;c254	OpCode sz      ,               ,        	,TNo    ,	,	
;c255	OpCode sz      ,               ,        	,TNo    ,	,	



	