	.text
	.newblock

	.asmfunc
	ABORTI
	ABS          ACC
	ABSTC        ACC
	ADD          ACC, #0x1234 << #10

	ADD          ACC, PL << T

	ADD          ACC, PL
	ADD          ACC, AR1 << #9
	ADD          ACC, PL << #9

	ADD          AL, @0x21
	ADD          AH, @0x21
	ADD          @0x21, AL
	ADD          @0x21, AH
	ADD          AR1, #0x859
	ADDB         ACC, #5
	ADDB         AL, #2
	ADDB         SP, #1
	ADDB         XAR2, #7
	ADDCL        ACC, XT
	ADDCU        ACC, T
	ADDL         ACC, XT
	ADDL         ACC, P << PM
	ADDL         XT, ACC
	ADDU         ACC, T
	ADDUL        P, XT
	ADDUL        ACC, XT
	ADRK         #217
	AND          ACC, #0x859 << #13
	AND          ACC, #0x859 << #16
	AND          ACC, PL
	AND          AL, PL, #0x859
	AND          IER, #0x2137
	AND          IFR, #0x2137
	AND          PL, AH
	AND          AH, PL
	AND          PL, #0x859
	ANDB         AL, #0xaa
	ASP
	ASR          AL, #5
	ASR          AH, T
	ASR64        ACC:P, #5
	ASR64        ACC:P, T
	ASRL         ACC, T
	B            1000, HIS
	B            -201, LO
	B            1000, UNC
	BANZ         0x859, AR2--
	BAR          21, AR3, AR7, EQ
	BAR          21, AR3, AR7, NEQ
	BF           256, NEQ
	C27MAP
	CLRC         M0M1MAP
	C27OBJ
	CLRC         OBJMODE
	C28ADDR
	CLRC         AMODE
	C28MAP
	SETC         M0M1MAP
	C28OBJ
	SETC         OBJMODE
	CLRC         OVC
	ZAP          OVC
	CLRC         XF
	;CLRC         0xff ; formatting difference
	CMP          AH, PL
	CMP          PL, #0x859
	CMP64        ACC:P
	CMPB         AH, #0x81
	CMPL         ACC, @0x3f
	CMPL         ACC, P<<PM
	CMPR         0
	CMPR         1
	CMPR         2
	CMPR         3
	CSB          ACC
	DEC          PL
	DINT
	DMAC         ACC:P, @0x11, *XAR7
	DMAC         ACC:P, @0x11, *XAR7++
	DMOV         @0x3a
	EALLOW
	EDIS
	;EINT ; CLRC INTM
	ESTOP0
	ESTOP1
	FFC          XAR7, 0x3fffff
	FFC          XAR7, 0x1
	;MOV          ACC, PL
	.endasmfunc
