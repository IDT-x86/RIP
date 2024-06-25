.code

_spoofer_stub PROC
    pop r11
    pop r10
    mov rax, [rsp + 24]
        
    mov r10, [rax]
    mov [rsp], r10
        
    mov r10, [rax + 8]
    mov [rax + 8], r11
     
    mov [rax + 16], r13
    lea r13, fixup
    mov [rax], r13
    mov r13, rax
        
    jmp r10
     
    fixup:
        sub rsp, 16
        mov rcx, r13
        mov r13, [rcx + 16]
        jmp QWORD PTR [rcx + 8]
_spoofer_stub ENDP 
END