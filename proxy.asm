.data

extern pAlphaBlend:QWORD
extern pDllInitialize:QWORD
extern pGradientFill:QWORD
extern pTransparentBlt:QWORD
extern pvSetDdrawflag:QWORD

.code

; The Exported Functions

AlphaBlend PROC
    jmp [pAlphaBlend]
AlphaBlend ENDP

DllInitialize PROC
    jmp [pDllInitialize]
DllInitialize ENDP

GradientFill PROC
    jmp [pGradientFill]
GradientFill ENDP

TransparentBlt PROC
    jmp [pTransparentBlt]
TransparentBlt ENDP

vSetDdrawflag PROC
    jmp [pvSetDdrawflag]
vSetDdrawflag ENDP

END