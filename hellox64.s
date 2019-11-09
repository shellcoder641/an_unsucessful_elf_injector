global _start

section .text

_start:
  mov rax, 1        ; write(
  mov rdi, 1        ;   STDOUT_FILENO,
  mov rbx, 1
  mov rcx, msg
  add rbx, rcx
  mov rsi, rbx
  ;mov rsi, msg      ;   "Hello, world!\n",
  mov rdx, msglen   ;   sizeof("Hello, world!\n")
  syscall           ; );

  mov rax, 60       ; exit(
  mov rdi, 0        ;   EXIT_SUCCESS
  syscall           ; );

 mov rax, 0x11111111; //jump back to program entry point
 jmp rax            ; an indirect jump

section .rodata
  msg: db "Hello, world!"
  msglen: equ $ - msg
