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
	;MOV          ACC, PL
	.endasmfunc
