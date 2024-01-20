.code
	fReadProcessMemory proc
			mov r10, rcx
			mov eax, 3Fh
			syscall
			ret
	fReadProcessMemory endp
end