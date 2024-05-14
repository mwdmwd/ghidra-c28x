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
	;MOV          ACC, PL
	.endasmfunc
