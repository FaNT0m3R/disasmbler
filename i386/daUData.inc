;########################################################################################	
section '.udata' data readable writeable
	
	bytes		rb 32
	
	;begPar		rd 1
	;endPar		rd 1
	
	;CommLine	rd 1
	;HConsole	rd 1
	;szDecod		rb 256
	;szFull		rb 256
	
	;begDisData	rd 1	;откуда дизассемблировать в файле
	;endDisData	rd 1
	
	;begInFile	rd 1	;расположение данных в памяти
	;endInFile	rd 1

	begAddr		rd 1	;указатель на начало наших байт

	;disResult	_DisRet	
	
	prfxSegm	rd 1 	;cs:/ds:/...
	prfxLock	rd 1	;lock
	prfxRep		rd 1	;repe/repne/rep
	regSize		rd 1	;16/32
	addrSize	rd 1	;16/32
	
	mnem		rd 1
	arg1		rd 1 
	arg2		rd 1
	arg3		rd 1
	szArg1		rb 80
	szArg2		rb 80
	szArg3		rb 80

	bModrm		rb 1
	bSib		rb 1
	PEndOC		rd 1  ;указатель на начало следующего опкода либо данных