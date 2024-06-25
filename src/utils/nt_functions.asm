.code
nt_protect_vm proc
	mov r10, rcx
	mov eax, 50h
	syscall
	ret
nt_protect_vm endp

nt_query_virtual_memory proc
	mov r10, rcx
	mov eax, 23h
	syscall
	ret
nt_query_virtual_memory endp

end